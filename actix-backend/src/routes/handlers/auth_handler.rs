use actix_web::{
    cookie::{time, Cookie, SameSite},
    post, web, HttpRequest, HttpResponse, Responder,
};
use bcrypt::{hash, verify};
use chrono::{Utc, Duration as ChronoDuration};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::Error;

use crate::{
    models::{Claims, UserData, UserLoginRequest, UserRegisterRequest, UserSession},
    utils::test_password,
    AppState,
};

#[post("/register")]
pub async fn register(
    app_state: web::Data<AppState>,
    register_json: web::Json<UserRegisterRequest>,
) -> impl Responder {
    let req = register_json.into_inner();

    if req.email.is_empty() || req.username.is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing required fields" }));
    }
    if let Some(err) = test_password(&req.password) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": err }));
    }

    let password_hash = match hash(&req.password, 12) {
        Ok(x) => x,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Hash failed" }))
    };

    let res = sqlx::query!(
        r#"
        INSERT INTO users (email, username, first_name, last_name, password_hash)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        req.email,
        req.username,
        req.first_name,
        req.last_name,
        password_hash
    )
    .execute(&app_state.db)
    .await;

    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "error": null })),
        Err(Error::Database(db)) if db.message().contains("users_email_key") => {
            HttpResponse::Conflict().json(serde_json::json!({ "error": "Email already registered" }))
        }
        Err(Error::Database(db)) if db.message().contains("users_username_key") => {
            HttpResponse::Conflict().json(serde_json::json!({ "error": "Username taken" }))
        }
        Err(_) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Server error" }))
        }
    }
}

// TODO: (FIX THIS) When a user logs multiple times in a row, it creates new refresh tokens in the user_sessions table without removing the previous ones 
#[post("/login")]
pub async fn login(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    login_json: web::Json<UserLoginRequest>,
) -> impl Responder {
    let body = login_json.into_inner();
    if body.email.is_empty() || body.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing required fields" }));
    }

    // fetch only id & hash
    let row = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE email = $1",
        body.email
    )
    .fetch_optional(&app_state.db)
    .await;

    let row = match row {
        Ok(possible_row) => {
            match possible_row {
                Some(row) => row,
                None => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "Invalid credentials" }))
            }
        },
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Encountered error while querying database"})),
    };

    // 2) Verify the password against the stored hash
    match verify(&body.password, &row.password_hash) {
        Ok(true) => {
            // password match -> proceed
        }
        Ok(false) => {
            // incorrect password -> unauthorized
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Invalid credentials" }));
        }
        Err(_) => {
            // verification *failed* (e.g. bad hash format)
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Server error during password verification" }));
        }
    }



    let user_id = row.id;
    let now = Utc::now();
    let access_exp = now + ChronoDuration::minutes(15);
    let refresh_exp = now + ChronoDuration::hours(24);

    let access_claims = Claims {
        exp: access_exp.timestamp() as usize,
        user: UserData { id: user_id },
    };
    let refresh_claims = Claims {
        exp: refresh_exp.timestamp() as usize,
        user: UserData { id: user_id },
    };

    let access_token = match encode(
        &Header::default(), 
        &access_claims, 
        &EncodingKey::from_secret(app_state.jwt_access_secret.as_bytes())
    ) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Encountered error while building access_token"}))
    };

    let refresh_token = match encode(
        &Header::default(), 
        &refresh_claims, 
        &EncodingKey::from_secret(app_state.jwt_refresh_secret.as_bytes())
    ) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Encountered error while building refresh_token"}))
    };

    // metadata
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .map(str::to_owned);

    // insert session
    let store_res = sqlx::query!(
        r#"
        INSERT INTO user_sessions 
          (user_id, refresh_token, user_agent, ip_address) 
        VALUES ($1, $2, $3, $4)
        "#,
        user_id,
        refresh_token,
        user_agent,
        ip_address,
    )
    .execute(&app_state.db)
    .await;

    if let Err(_) = store_res {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to store session data." }));
    }

    let cookie = Cookie::build("jwt", refresh_token.clone())
        .http_only(true)
        .same_site(SameSite::None)
        .secure(true)
        .max_age(time::Duration::hours(24))
        .path("/")
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "accessToken": access_token, "error": null }))
}

#[post("/logout")]
pub async fn logout(app_state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let refresh_token = if let Some(c) = req.cookie("jwt") {
        c.value().to_string()
    } else {
        return HttpResponse::NoContent().json(serde_json::json!({ "error": "No cookie" }));
    };

    let update_result = sqlx::query!(
        "UPDATE user_sessions SET revoked = TRUE WHERE refresh_token = $1",
        refresh_token
    )
    .execute(&app_state.db)
    .await;

     if let Err(_) = update_result {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Failed to clear refresh token" }));
    }

    let mut clear_cookie = Cookie::build("jwt", "")
        .http_only(true)
        .same_site(SameSite::None)
        .secure(true)
        .max_age(time::Duration::hours(24))
        .path("/")
        .finish();

    clear_cookie.make_removal();

    HttpResponse::Ok().cookie(clear_cookie).json(serde_json::json!({ "error": null }))
}

#[post("/refresh")]
pub async fn refresh(app_state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let refresh_token = if let Some(c) = req.cookie("jwt") {
        c.value().to_string()
    } else {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "No refresh token cookie" }));
    };

    // step 1: fetch session
    let query_result = sqlx::query_as!(
        UserSession,
        r#"
        SELECT *
          FROM user_sessions
         WHERE refresh_token = $1
           AND revoked = FALSE
        "#,
        refresh_token
    )
    .fetch_optional(&app_state.db)
    .await;


    let session = match query_result {
        Ok(possible_row) => match possible_row {
            Some(row) => row,
            None => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "Invalid or revoked token" })),
        },
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Encountered erorr while querying for user_sessions in database"}))
    };

    // step 2: verify JWT
    let data = match decode::<Claims>(
        &refresh_token,
        &DecodingKey::from_secret(app_state.jwt_refresh_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(token) => token.claims,
        Err(_) => return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Invalid refresh token JWT" }))
    };

    if data.user.id != session.user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Token user mismatch" }));
    }

    // step 3: issue new access token
    let exp = Utc::now() + ChronoDuration::minutes(15);
    let claims = Claims {
        exp: exp.timestamp() as usize,
        user: UserData { id: session.user_id },
    };
    let access_token = match encode(
        &Header::default(), 
        &claims, 
        &EncodingKey::from_secret(app_state.jwt_access_secret.as_bytes())
    ) {
        Ok(token) => token,
        Err(_) => return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Invalid refresh token JWT" }))
    };

    HttpResponse::Ok().json(serde_json::json!({ "accessToken": access_token, "error": null }))
}
