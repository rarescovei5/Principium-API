use actix_web::{
    cookie::{time, Cookie, SameSite},
    post, web, HttpRequest, HttpResponse, Responder,
};
use bcrypt::{hash, verify};
use chrono::{Utc, Duration as ChronoDuration};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::Error;
use uuid::Uuid;

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

#[post("/login")]
pub async fn login(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    login_json: web::Json<UserLoginRequest>,
) -> impl Responder {
    let body = login_json.into_inner();
    if body.email.is_empty() || body.password.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "Missing required fields" }));
    }

    // 1) Fetch only id & hash
    let row = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE email = $1",
        body.email
    )
    .fetch_optional(&app_state.db)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Invalid credentials" }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "DB query error" }));
        }
    };

    // 2) Verify password
    match verify(&body.password, &row.password_hash) {
        Ok(true) => (),
        Ok(false) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Invalid credentials" }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Password verification error" }));
        }
    }

    // 3) Prepare tokens
    let user_id = row.id;
    let now = Utc::now();
    let access_exp = now + ChronoDuration::minutes(15);
    let refresh_exp = now + ChronoDuration::hours(24);

    let access_claims = Claims { exp: access_exp.timestamp() as usize, user: UserData { id: user_id } };
    let refresh_claims = Claims { exp: refresh_exp.timestamp() as usize, user: UserData { id: user_id } };

    let access_token = match encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(app_state.jwt_access_secret.as_bytes()),
    ) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Access token creation failed" }))
    };

    let refresh_token = match encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(app_state.jwt_refresh_secret.as_bytes()),
    ) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Refresh token creation failed" }))
    };

    // 4) Metadata
    let user_agent = req.headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .map(str::to_owned);

    // 5) Device ID logic
    let device_id = match req.cookie("device_id").map(|c| c.value().to_string()) {
        Some(id) => id,
        None => Uuid::new_v4().to_string(),
    };

    // 6) Try to rotate "existing" session on current browser
    let updated = sqlx::query!(
        r#"
        UPDATE user_sessions
           SET refresh_token = $1,
               user_agent    = $2,
               ip_address    = $3,
               last_used_at  = CURRENT_TIMESTAMP
         WHERE user_id    = $4
           AND device_id  = $5
           AND revoked     = false
        RETURNING id
        "#,
        refresh_token,
        user_agent,
        ip_address,
        user_id,
        device_id,
    )
    .fetch_optional(&app_state.db)
    .await;

    match updated {
        Ok(None) => {
            let res = sqlx::query!(
                r#"
                INSERT INTO user_sessions
                  (user_id, refresh_token, user_agent, ip_address, device_id)
                VALUES ($1, $2, $3, $4, $5)
                "#,
                user_id,
                refresh_token,
                user_agent,
                ip_address,
                device_id,
            )
            .execute(&app_state.db)
            .await;

            if let Err(_) = res {
                return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Session insert failed" }));
            };
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Session rotation failed" }));
        }
        _ => {}
    }

    // 7) Set cookies
    let refresh_cookie = Cookie::build("jwt", refresh_token.clone())
        .http_only(true)
        .same_site(SameSite::None)
        .secure(true)
        .max_age(time::Duration::hours(24))
        .path("/")
        .finish();

    let device_cookie = Cookie::build("device_id", device_id.clone())
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .max_age(time::Duration::days(365))
        .path("/")
        .finish();

    HttpResponse::Ok()
        .cookie(refresh_cookie)
        .cookie(device_cookie)
        .json(serde_json::json!({ "accessToken": access_token, "error": null }))
}

#[post("/logout")]
pub async fn logout(
    app_state: web::Data<AppState>,
    req: HttpRequest
) -> impl Responder {
    // 1) Extract refresh-token cookie
    let refresh_token = if let Some(c) = req.cookie("jwt") {
        c.value().to_string()
    } else {
        return HttpResponse::NoContent()
            .json(serde_json::json!({ "error": "No cookie" }));
    };

    // 2) Decode JWT to get user_id
    let claims = match decode::<Claims>(
        &refresh_token,
        &DecodingKey::from_secret(app_state.jwt_refresh_secret.as_bytes()),
        &Validation::default()
    ) {
        Ok(data) => data.claims,
        Err(_) => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({ "error": "Invalid refresh token" }));
        }
    };
    let user_id = claims.user.id;

    // 3) Read device_id cookie
    let device_id = if let Some(c) = req.cookie("device_id") {
        c.value().to_string()
    } else {
        return HttpResponse::NoContent()
            .json(serde_json::json!({ "error": "No device_id cookie" }));
    };

    // 4) Revoke only this device’s session
    let res = sqlx::query!(
        r#"
        UPDATE user_sessions
           SET revoked = TRUE
         WHERE user_id   = $1
           AND device_id = $2
        "#,
        user_id,
        device_id
    )
    .execute(&app_state.db)
    .await;

    if let Err(_) = res {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Failed to revoke session" }));
    }

    // 5) Clear both cookies
    let mut clear_jwt = Cookie::build("jwt", "")
        .http_only(true)
        .same_site(SameSite::None)
        .secure(true)
        .max_age(time::Duration::hours(24))
        .path("/")
        .finish();
    clear_jwt.make_removal();

    let mut clear_dev = Cookie::build("device_id", "")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .max_age(time::Duration::days(365))
        .path("/")
        .finish();
    clear_dev.make_removal();

    HttpResponse::Ok()
        .cookie(clear_jwt)
        .cookie(clear_dev)
        .json(serde_json::json!({ "error": null }))
}

#[post("/refresh")]
pub async fn refresh(
    app_state: web::Data<AppState>,
    req: HttpRequest
) -> impl Responder {
    // 1) Extract cookies
    let refresh_token = if let Some(c) = req.cookie("jwt") {
        c.value().to_string()
    } else {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "No refresh token cookie" }));
    };
    let device_id = if let Some(c) = req.cookie("device_id") {
        c.value().to_string()
    } else {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "No device_id cookie" }));
    };

    // 2) Decode JWT to get user_id
    let token_data = match decode::<Claims>(
        &refresh_token,
        &DecodingKey::from_secret(app_state.jwt_refresh_secret.as_bytes()),
        &Validation::default()
    ) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({ "error": "Invalid refresh token JWT" }));
        }
    };
    let user_id = token_data.claims.user.id;

    // 3) Fetch the session row for this user + device + token
    let session = match sqlx::query_as!(
        UserSession,
        r#"
        SELECT *
          FROM user_sessions
         WHERE user_id      = $1
           AND device_id    = $2
           AND refresh_token= $3
           AND revoked      = FALSE
        "#,
        user_id,
        device_id,
        refresh_token
    )
    .fetch_optional(&app_state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Invalid or revoked session" }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "DB error fetching session" }));
        }
    };

    // 4) Issue new access token
    let exp = Utc::now() + ChronoDuration::minutes(15);
    let claims = Claims { exp: exp.timestamp() as usize, user: UserData { id: session.user_id } };

    let access_token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(app_state.jwt_access_secret.as_bytes()),
    ) {
        Ok(tok) => tok,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Failed to create access token" }));
        }
    };

    HttpResponse::Ok()
        .json(serde_json::json!({ "accessToken": access_token, "error": null }))
}