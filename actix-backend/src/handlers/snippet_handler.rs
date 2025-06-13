use actix_web::{delete, post, web, HttpResponse, Responder};
use uuid::Uuid;

use crate::{models::{snippets::CreateSnippetRequest, UserData}, AppState};

#[post("")]
pub async fn create_snippet(
    app_data: web::Data<AppState>, 
    data_json: web::Json<CreateSnippetRequest>,
    user_data: web::ReqData<UserData>,
) -> impl Responder {
    let rec = sqlx::query!(
        r#"
        INSERT INTO snippets_extension.snippets (title, owner_id)
        VALUES ($1, $2)
        RETURNING id
        "#,
        data_json.title,
        user_data.id
    )
    .fetch_one(&app_data.db)
    .await;

    let insert_id = match rec {
        Ok(record) => record.id,
        Err(_) => return HttpResponse::InternalServerError().json(
                    serde_json::json!({"error": "Inserting new snippet in database failed"}),
                )
    };

    HttpResponse::Ok().json(serde_json::json!({"id": insert_id}))
}

#[delete("/{id}")]
pub async fn delete_snippet(
    app_data: web::Data<AppState>,
    path: web::Path<Uuid>,
    user_data: web::ReqData<UserData>
) -> impl Responder {
    let snippet_id: Uuid = path.into_inner();
    let user_id = user_data.id;

    let rec = sqlx::query!(
        r#"
        DELETE FROM snippets_extension.snippets
        WHERE id = $1
          AND owner_id = $2
        RETURNING id
        "#,
        snippet_id,
        user_id
    )
    .fetch_optional(&app_data.db)
    .await;

    match rec {
        Ok(opt) => {
            if let Some(deleted) = opt {
                HttpResponse::Ok().json(serde_json::json!({
                    "id": deleted.id,
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": format!("No snippet found with id {}", snippet_id)
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to delete snippet {}: {}", snippet_id, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete snippet"
            }))
        }
    }
}
