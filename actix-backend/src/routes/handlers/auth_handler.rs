use actix_web::{cookie::{time, Cookie, SameSite}, post, web, HttpRequest, HttpResponse, Responder};
use bcrypt::{hash, verify};
use chrono::{Utc, Duration as ChronoDuration};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::Error;

use crate::{models::{Claims, UserData, UserLoginRequest, UserRegisterRequest}, utils::test_password, AppState};

#[post("/register")]
pub async fn register(
    app_state: web::Data<crate::AppState>, 
    register_json: web::Json<UserRegisterRequest>
) -> impl Responder {
    let req = register_json.into_inner();

    // Validate required fields
    if req.email.is_empty() || req.username.is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing required fields" }));
    }

    if let Some(pwd_err) = test_password(&req.password) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": pwd_err }));
    }

    // Hash the password
    let password_hash = match hash(&req.password, 12) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error hashing password" })),
    };

    // Try to insert the user
    let result = sqlx::query!(
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

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "error": null })),
        Err(err) => match &err {
            Error::Database(db_err) => {
                let msg = db_err.message();
                if msg.contains("users_email_key") {
                    HttpResponse::Conflict().json(serde_json::json!({ "error": "Email already registered" }))
                } else if msg.contains("users_username_key") {
                    HttpResponse::Conflict().json(serde_json::json!({ "error": "Username taken" }))
                } else {
                    eprintln!("Registration error: {}", err);
                    HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Server error during registration" }))
                }
            }
            _ => {
                eprintln!("Registration error: {err}");
                HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Unknown error" }))
            }
        },
    }
}

#[post("login")]
pub async fn login(app_state: web::Data<AppState>, login_json: web::Json<UserLoginRequest>) -> impl Responder {
    let req = login_json.into_inner();

    // Validate required fields
    if req.email.is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing required fields" }));
    }

    let user = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE email = $1", 
        &req.email
    ).fetch_optional(&app_state.db)
     .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "Invalid credentials" })),
        Err(e) => {
            eprintln!("DB error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Server error" }));
        }
    };
 
    let is_valid = verify(&req.password, &user.password_hash).unwrap_or(false);
    if !is_valid {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}));
    }

    let user_id = user.id;

    let now = Utc::now();
    let access_exp = now + ChronoDuration::minutes(15);
    let refresh_exp = now + ChronoDuration::hours(24);

    let access_claims = Claims {
        exp: access_exp.timestamp() as usize,
        user: UserData {id: user_id.clone() },
    };

    let refresh_claims = Claims {
        exp: refresh_exp.timestamp() as usize,
        user: UserData {id: user_id.clone() },
    };

    let access_token = match encode(
        &Header::default(), 
        &refresh_claims, 
        &EncodingKey::from_secret(app_state.jwt_access_secret.as_bytes())
    ) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to encode access token: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Token generation failed" }));
        }
    };

   let refresh_token = match encode(
        &Header::default(), 
        &access_claims, 
        &EncodingKey::from_secret(app_state.jwt_refresh_secret.as_bytes())
    ) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to encode refresh token: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Token generation failed" }));
        }
    };

    // 5. Store refresh token
    let store_result = sqlx::query!(
        "UPDATE users SET refresh_token = $1 WHERE id = $2",
        refresh_token,
        user.id
    )
    .execute(&app_state.db)
    .await;

    if let Err(e) = store_result {
        eprintln!("Failed to store refresh token: {:?}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Server error" }));
    }

    let cookie = Cookie::build("jwt", refresh_token.clone())
        .http_only(true)
        .same_site(actix_web::cookie::SameSite::None)
        .secure(true)
        .max_age(time::Duration::days(1))
        .path("/")
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "accessToken": access_token, "error": null }))
}

#[post("/logout")]
pub async fn logout(app_state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let refresh_token_cookie = match req.cookie("jwt") {
        Some(cookie) => cookie,
        None => {
            return HttpResponse::NoContent().json(serde_json::json!({"error": "No Cookie Supplied"}))
        }
    };

    let refresh_token = refresh_token_cookie.value();

    // Remove the Refresh Token from db
    let result = sqlx::query!(
        "UPDATE users SET refresh_token = NULL WHERE refresh_token = $1",
        refresh_token
    )
    .execute(&app_state.db)
    .await;

    if let Err(e) = result {
        eprintln!("Failed to clear refresh token: {:?}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Database error" }));
    }

    // Clear the cookie
    let clear_cookie = Cookie::build("jwt", "")
        .http_only(true)
        .same_site(SameSite::None)
        .secure(true)
        .max_age(time::Duration::seconds(0))
        .path("/")
        .finish();

    HttpResponse::Ok()
        .cookie(clear_cookie)
        .json(serde_json::json!({ "error": "No Error" }))
}


#[post("/refresh")]
pub async fn refresh(app_state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    // Extract cookie
    let refresh_token_cookie = match req.cookie("jwt") {
        Some(cookie) => cookie,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "No refresh token cookie"})),
    };

    let refresh_token = refresh_token_cookie.value();

    // Find user by refresh token
    let user = sqlx::query!(
        "SELECT id FROM users WHERE refresh_token = $1",
        refresh_token
    )
    .fetch_optional(&app_state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
        Err(e) => {
            eprintln!("DB error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Server error"}));
        }
    };

    // Verify refresh token JWT
    let token_data = match decode::<Claims>(
        refresh_token,
        &DecodingKey::from_secret(app_state.jwt_refresh_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Forbidden().json(serde_json::json!({"error": "Invalid refresh token"})),
    };

    // Check that user ID in token matches DB user ID
    if token_data.claims.user.id != user.id {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Token user mismatch"}));
    }

    // Generate new access token
    let access_exp = Utc::now() + ChronoDuration::minutes(5);
    let access_claims = Claims {
        exp: access_exp.timestamp() as usize,
        user: UserData { id: user.id },
    };

    let access_token = match encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(app_state.jwt_access_secret.as_bytes()),
    ) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create access token"})),
    };

    // Return the token
    HttpResponse::Ok().json(serde_json::json!({
        "accessToken": access_token,
        "error": null
    }))
}