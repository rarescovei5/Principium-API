use actix_web::web;

use crate::handlers;

pub fn config(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/v1/auth")
        .service(handlers::auth_handler::register)
        .service(handlers::auth_handler::login)
        .service(handlers::auth_handler::logout)
        .service(handlers::auth_handler::refresh)
    );
}