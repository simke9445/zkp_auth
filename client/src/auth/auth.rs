use std::error::Error;

use openssl::bn::BigNum;

pub struct Registration<T> {
    pub y1: T,
    pub y2: T,
    pub x: BigNum,
}

pub struct AuthenticationState<T> {
    pub r1: T,
    pub r2: T,
    pub c: BigNum,
    pub k: BigNum,
    pub x: BigNum,
}

#[allow(async_fn_in_trait)]
pub trait AuthClient {
    async fn register(&mut self, user: &str) -> Result<(), Box<dyn Error>>;
    async fn create_authentication_challenge(
        &mut self,
        user: &str,
    ) -> Result<String, Box<dyn Error>>;
    async fn verify_authentication(&mut self, auth_id: &str) -> Result<String, Box<dyn Error>>;
}
