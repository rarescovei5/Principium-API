use actix_web::{middleware::Logger, web::{self, Data}, App, HttpServer};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

// use crate::middleware::jwt_middleware::VerifyJWT;

mod models;
mod routes;
mod utils;
mod middleware;

// Shared application state containing the database connection pool
pub struct AppState {
    db: Pool<Postgres>,
    jwt_access_secret: String,
    jwt_refresh_secret: String,
}

/// Main entry point for the Actix web server application.
/// Sets up logging, environment variables, database connection pool, and starts the HTTP server.
/// Shares app state including database pool and JWT secrets across routes.
#[actix_web::main]
async fn main () -> std::io::Result<()> {
    // Enable Actix Web debug logs and full backtraces for better debugging
    unsafe { 
        std::env::set_var("RUST_LOG", "debug");
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    // Initialize the environment logger
    env_logger::init();

    // Load environment variables from .env file
    dotenv::from_filename(".env.local")
        .or_else(|_| dotenv::dotenv())
        .ok();

    // Establish a PostgreSQL connection pool
    let database_url =  std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    // Read server address and port from environment variables
    let port = std::env::var("PORT").unwrap().parse::<u16>().unwrap();
    let host = std::env::var("HOST").unwrap();

    let jwt_access_secret = std::env::var("JWT_ACCESS_SECRET").unwrap();
    let jwt_refresh_secret = std::env::var("JWT_REFRESH_SECRET").unwrap();

    // Create the app data
    let app_data = Data::new(AppState {
        db: pool.clone(),
        jwt_access_secret: jwt_access_secret.clone(),
        jwt_refresh_secret: jwt_refresh_secret.clone(),
    });

    // Start the Actix Web server
    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone()) // Share the Information across all routes via application state
            .wrap(Logger::default()) // Enable request/response logging middleware
            .service(
                web::scope("/api")
                    .configure(routes::auth_routes::config) 
            ) 
    })
    .bind((host, port))?  // Bind the server to the specified address and port
    .run() // Run the server asynchronously
    .await
}