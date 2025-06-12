// Models contain structs meant to be used with query as, as well as request bodies for post routes

// Users
mod user;
pub use user::{
    User, UserSession, Subscription, 
    UserLoginRequest, UserRegisterRequest
};

mod claims;
pub use claims::{Claims,UserData};

// Snippets
pub mod snippets;
pub use snippets::{
    Snippet, SnippetStar, SnippetTag
};

