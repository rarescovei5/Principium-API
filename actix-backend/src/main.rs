use actix_web::{middleware::Logger, web::{self, Data}, App, HttpServer};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};


mod handlers;
mod models;
mod utils;

mod middleware;
mod routes;

// use crate::middleware::jwt_middleware::VerifyJWT;


pub struct AppState {
    db: Pool<Postgres>,
    jwt_access_secret: String,
    jwt_refresh_secret: String,
}

#[actix_web::main]
async fn main () -> std::io::Result<()> {
    // Enable Actix Web debug logs and backtraces for better debugging
    unsafe { 
        std::env::set_var("RUST_LOG", "debug");
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    
    env_logger::init();

    // This project is setup such there is a .env.dev .env.local
    // The only difference is that the .env.dev has a different host and port for the db (db:5433)
    dotenv::from_filename(".env.local")
        .or_else(|_| dotenv::dotenv())
        .ok();

    // Establish a PostgreSQL connection pool
    // Since were using PosgresSQL proc macros for handlers, there is also a .env with the localhost version of the DATABASE_URL
    // If you don't have the schema setup, your editor will have more errors than code
    let database_url =  std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    // Read the rest of env vars
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
    .bind((host, port))? // Ex: This is telling the server to listen at 127.0.0.1:8080
    .run()
    .await
}