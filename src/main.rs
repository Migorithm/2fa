pub mod adapter;
mod domain;
use crate::domain::command::{DisableOTP, GenerateOTP, Login, RegisterUser, VerifyOTP};

use adapter::database;
use axum::{http::StatusCode, response::IntoResponse, routing::post, Json};

use domain::{Mfa, User};

use serde_json::json;

use uuid::Uuid;

#[tokio::main]
async fn main() {
    println!("Environment variable is being set...");

    tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .compact()
        .init();

    let listener = tokio::net::TcpListener::bind(
        &std::env::var("SERVER_IP_PORT").unwrap_or("0.0.0.0:3000".into()),
    )
    .await
    .unwrap();

    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, router()).await.unwrap();
}

async fn register_user_handler(Json(body): Json<RegisterUser>) -> impl IntoResponse {
    let mut db = database().lock().await;

    if db.user.iter().any(|user| user.email == body.email) {
        // return forbidden

        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Email already exists"})),
        )
            .into_response();
    }

    let uuid_id = Uuid::new_v4();

    let user = User {
        id: uuid_id.to_string(),
        email: body.email.to_owned().to_lowercase(),
        name: body.name.to_owned(),
        password: body.password,
    };
    let mfa = Mfa {
        account_id: uuid_id.to_string(),
        otp_enabled: false,
        otp_verified: false,
        otp_base32: None,
        otp_auth_url: None,
    };

    db.user.push(user);
    db.mfa.push(mfa);

    Json(json!({"status": "success", "message": "Registered successfully, please login"}))
        .into_response()
}

async fn login_user_handler(Json(body): Json<Login>) -> impl IntoResponse {
    let db = database().lock().await;

    let user = db
        .user
        .iter()
        .find(|user| user.email == body.email.to_lowercase());

    if user.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid Password"})),
        )
            .into_response();
    }

    let user = user.unwrap();

    Json(json!(user)).into_response()
}

async fn generate_otp_handler(Json(body): Json<GenerateOTP>) -> impl IntoResponse {
    let mut db = database().lock().await;

    let Some(mfa) = db
        .mfa
        .iter_mut()
        .find(|user| user.account_id == body.account_id)
    else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Not Found"}))).into_response();
    };

    mfa.set(body.email);

    Json(json!(
        {"base32":mfa.otp_base32.to_owned(), "otpauth_url": mfa.otp_auth_url.to_owned()}
    ))
    .into_response()
}

async fn verify_otp_handler(Json(body): Json<VerifyOTP>) -> impl IntoResponse {
    let mut db = database().lock().await;

    let Some(mfa) = db
        .mfa
        .iter_mut()
        .find(|mfa| mfa.account_id == body.account_id)
    else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Not Found"}))).into_response();
    };

    mfa.verify(body.token);

    Json(json!("Ok")).into_response()
}

async fn validate_otp_handler(Json(body): Json<VerifyOTP>) -> impl IntoResponse {
    let mut db = database().lock().await;

    let Some(mfa) = db
        .mfa
        .iter_mut()
        .find(|user| user.account_id == body.account_id)
    else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Not Found"}))).into_response();
    };

    if !mfa.otp_enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "2FA not enabled"})),
        )
            .into_response();
    }

    mfa.verify(body.token);

    Json(json!("Ok")).into_response()
}

async fn disable_otp_handler(Json(body): Json<DisableOTP>) -> impl IntoResponse {
    let mut db = database().lock().await;

    let Some(mfa) = db
        .mfa
        .iter_mut()
        .find(|user| user.account_id == body.account_id)
    else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Not Found"}))).into_response();
    };

    mfa.otp_enabled = false;
    mfa.otp_verified = false;
    mfa.otp_auth_url = None;
    mfa.otp_base32 = None;

    Json(json!("Ok")).into_response()
}

pub fn router() -> axum::Router {
    // #[post("/auth/otp/disable")]

    axum::Router::new()
        .route("/auth/register", post(register_user_handler))
        .route("/auth/login", post(login_user_handler))
        .route("/auth/otp/generate", post(generate_otp_handler))
        .route("/auth/otp/verify", post(verify_otp_handler))
        .route("/auth/otp/validate", post(validate_otp_handler))
        .route("/auth/otp/disable", post(disable_otp_handler))
}
