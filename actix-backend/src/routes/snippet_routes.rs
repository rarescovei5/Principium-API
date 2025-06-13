use actix_web::web;

use crate::handlers;

pub fn config(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/snippets")
        .service(handlers::snippet_handler::create_snippet)
        // .service(handlers::snippet_handler::update_snippet)
        .service(handlers::snippet_handler::delete_snippet)
        // .service(handlers::snippet_handler::get_user_snippets)
        // .service(handlers::snippet_handler::get_user_snippet)
        // .service(handlers::snippet_handler::get_page_snippets)
        // .service(handlers::snippet_handler::star_snippet)
    );
}