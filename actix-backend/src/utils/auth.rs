pub fn test_password(password: &str) -> Option<&'static str> {
    if password.len() < 8 {
        Some("Password must be at least 8 characters long")
    } else if !password.chars().any(|c| c.is_uppercase()) {
        Some("Password must include at least one uppercase letter")
    } else if !password.chars().any(|c| c.is_lowercase()) {
        Some("Password must include at least one lowercase letter")
    } else if !password.chars().any(|c| c.is_numeric()) {
        Some("Password must include at least one number")
    } else {
        None
    }
}
