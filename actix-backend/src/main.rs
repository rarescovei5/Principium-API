use actix_web::{middleware::Logger, web::{self, Data}, App, HttpServer};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};


mod handlers;
mod models;
mod utils;

mod middleware;
mod routes;

pub struct AppState {
    db: Pool<Postgres>,
    jwt_access_secret: String,
    jwt_refresh_secret: String,
}

#[actix_web::main]
async fn main () -> std::io::Result<()> {
    unsafe { 
        std::env::set_var("RUST_LOG", "debug");
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    
    env_logger::init();

    dotenv::from_filename(".env.local")
        .or_else(|_| dotenv::dotenv())
        .ok();

    let database_url =  std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    let port = std::env::var("PORT").unwrap().parse::<u16>().unwrap();
    let host = std::env::var("HOST").unwrap();

    let jwt_access_secret = std::env::var("JWT_ACCESS_SECRET").unwrap();
    let jwt_refresh_secret = std::env::var("JWT_REFRESH_SECRET").unwrap();

    let app_data = Data::new(AppState {
        db: pool.clone(),
        jwt_access_secret: jwt_access_secret.clone(),
        jwt_refresh_secret: jwt_refresh_secret.clone(),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone()) 
            .wrap(Logger::default())
            .service(
                web::scope("/api")
                    .configure(routes::auth_routes::config) 
            ) 
    })
    .bind((host, port))? 
    .run()
    .await
}