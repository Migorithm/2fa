pub mod command;

use rand::Rng;
use serde::Serialize;
use totp_rs::{Algorithm, Secret, TOTP};

#[derive(Serialize, Debug)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub password: String,
}

pub struct Mfa {
    pub account_id: String,
    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
}

impl Mfa {
    pub fn set(&mut self, email: String) {
        let mut rng = rand::thread_rng();
        let data_byte: [u8; 21] = rng.gen();
        let base32_string =
            base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte);
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(base32_string).to_bytes().unwrap(),
        )
        .unwrap();

        let otp_base32 = totp.get_secret_base32();

        let issuer = "migorithm";
        let otp_auth_url =
            format!("otpauth://totp/{issuer}:{email}?secret={otp_base32}&issuer={issuer}");

        self.otp_base32 = Some(otp_base32.to_owned());
        self.otp_auth_url = Some(otp_auth_url.to_owned());
    }

    pub fn verify(&mut self, token: String) {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(self.otp_base32.as_ref().unwrap().clone())
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let is_valid = totp.check_current(&token).unwrap();

        if !is_valid {
            panic!("Token is invalid or user doesn't exist");
        }
        self.otp_enabled = true;
        self.otp_verified = true;
    }
}
