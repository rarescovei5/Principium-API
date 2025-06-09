use actix_web::{middleware::Logger, web::{self, Data}, App, HttpServer};
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

mod models;
mod routes;
mod utils;

// Shared application state containing the database connection pool
pub struct AppState {
    db: Pool<Postgres>,
    jwt_access_secret: String,
    jwt_refresh_secret: String,
}

#[actix_web::main]
async fn main () -> std::io::Result<()> {
    // For some reason it errors if it's not in an unsafe block
    unsafe { 
        // Enable Actix Web debug logs (e.g., incoming requests, responses, etc.)
        std::env::set_var("RUST_LOG", "debug");
        // Enable full backtraces for better debugging on panics
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    // Initialize the environment logger (reads from RUST_LOG)
    env_logger::init();

    // Load environment variables from the .env file
    // Required variables: PORT, ADDRESS, DATABASE_URL, JWT_ACCESS_SECRET, JWT_REFRESH_SECRET
    dotenv().ok();

    // Read the DATABASE_URL and establish a PostgreSQL connection pool
    let database_url =  std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

     // Read the server address and port from environment variables
    let port = std::env::var("PORT").unwrap().parse::<u16>().unwrap();
    let address = std::env::var("ADDRESS").unwrap();

    let jwt_access_secret = std::env::var("JWT_ACCESS_SECRET").unwrap();
    let jwt_refresh_secret = std::env::var("JWT_REFRESH_SECRET").unwrap();

    // Start the Actix Web server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(
                AppState { db: pool.clone(), 
                    jwt_access_secret: jwt_access_secret.clone(), 
                    jwt_refresh_secret: jwt_refresh_secret.clone() 
                })) // Share the Information across all routes via application state
            .wrap(Logger::default()) // Enable request/response logging middleware
            .service(
                web::scope("/api")
                    .configure(routes::auth_routes::config) 
            ) 
    })
    .bind((address, port))?  // Bind the server to the specified address and port (e.g., 127.0.0.1:8080)
    .run() // Run the server asynchronously (similar to how Express works in Node.js)
    .await

}