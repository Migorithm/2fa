use std::sync::{Arc, OnceLock};

use tokio::sync::Mutex;

use crate::domain::{Mfa, User};

pub struct Db {
    pub user: Vec<User>,
    pub mfa: Vec<Mfa>,
}

static DB: OnceLock<Arc<Mutex<Db>>> = OnceLock::new();

pub fn database() -> &'static Arc<Mutex<Db>> {
    DB.get_or_init(|| {
        Arc::new(Mutex::new(Db {
            user: Vec::new(),
            mfa: Vec::new(),
        }))
    })
}
