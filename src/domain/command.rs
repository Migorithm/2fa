use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RegisterUser {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct Login {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateOTP {
    pub email: String,
    pub account_id: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyOTP {
    pub account_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct DisableOTP {
    pub account_id: String,
}
