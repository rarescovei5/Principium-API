use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user: UserData,
    pub exp: usize, // Expiration timestamp
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserData {
    pub id: Uuid,
}
