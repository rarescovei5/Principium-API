use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

// ______________________________________ Snippets ______________________________________
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Snippet {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub code: String,
    pub language: String,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ______________________________________ Snippet Tags ______________________________________
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Tag {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SnippetTag {
    pub snippet_id: Uuid,
    pub tag_id: Uuid,
}

// ______________________________________ Snippet Stars ______________________________________
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SnippetStar {
    pub user_id: Uuid,
    pub snippet_id: Uuid,
    pub starred_at: DateTime<Utc>,
}