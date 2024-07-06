use openssl::bn::BigNum;
use tonic::Status;

use proto::zkp_auth::{
    AuthenticationAnswerRequest as ProtoAuthenticationAnswerRequest,
    AuthenticationAnswerResponse as ProtoAuthenticationAnswerResponse,
    AuthenticationChallengeRequest as ProtoAuthenticationChallengeRequest,
    AuthenticationChallengeResponse as ProtoAuthenticationChallengeResponse,
    RegisterRequest as ProtoRegisterRequest, RegisterResponse as ProtoRegisterResponse,
};

pub struct RegisterRequest<T> {
    pub user: String,
    pub y1: T,
    pub y2: T,
}

pub struct RegisterResponse {}

pub struct AuthenticationChallengeRequest<T> {
    pub user: String,
    pub r1: T,
    pub r2: T,
}

pub struct AuthenticationChallengeResponse {
    pub auth_id: String,
    pub c: BigNum,
}

pub struct AuthenticationAnswerRequest {
    pub auth_id: String,
    pub s: BigNum,
}

pub struct AuthenticationAnswerResponse {
    pub session_id: String,
}

pub struct Registration<T> {
    pub y1: T,
    pub y2: T,
}

pub struct AuthenticationState<T> {
    pub r1: T,
    pub r2: T,
    pub c: BigNum,
    pub user: String,
}

#[tonic::async_trait]
pub trait AuthServer: Send + Sync + 'static {
    async fn register(
        &self,
        request: ProtoRegisterRequest,
    ) -> Result<ProtoRegisterResponse, Status>;
    async fn create_authentication_challenge(
        &self,
        request: ProtoAuthenticationChallengeRequest,
    ) -> Result<ProtoAuthenticationChallengeResponse, Status>;
    async fn verify_authentication(
        &self,
        request: ProtoAuthenticationAnswerRequest,
    ) -> Result<ProtoAuthenticationAnswerResponse, Status>;
}
