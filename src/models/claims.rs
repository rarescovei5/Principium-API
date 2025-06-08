use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user: UserData,
    pub exp: usize, // Expiration timestamp
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub id: String,
}
