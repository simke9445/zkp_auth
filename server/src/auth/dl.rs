use super::conversion::{FromProto, ToProto};
use super::types::{
    AuthServer, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, AuthenticationState, RegisterRequest, Registration,
};
use crypto::dl::verifier::DlVerifier;
use crypto::verifier::Verifier;
use openssl::bn::BigNum;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::Status;
use uuid::Uuid;

use proto::zkp_auth::{
    AuthenticationAnswerRequest as ProtoAuthenticationAnswerRequest,
    AuthenticationAnswerResponse as ProtoAuthenticationAnswerResponse,
    AuthenticationChallengeRequest as ProtoAuthenticationChallengeRequest,
    AuthenticationChallengeResponse as ProtoAuthenticationChallengeResponse,
    RegisterRequest as ProtoRegisterRequest, RegisterResponse as ProtoRegisterResponse,
};

pub struct DlAuthServer {
    verifier: Arc<Mutex<DlVerifier>>,
    registrations: Arc<Mutex<HashMap<String, Registration<BigNum>>>>,
    authentication_states: Arc<Mutex<HashMap<String, AuthenticationState<BigNum>>>>,
}

impl DlAuthServer {
    pub fn new(verifier: DlVerifier) -> Self {
        DlAuthServer {
            verifier: Arc::new(Mutex::new(verifier)),
            registrations: Arc::new(Mutex::new(HashMap::new())),
            authentication_states: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl AuthServer for DlAuthServer {
    async fn register(
        &self,
        request: ProtoRegisterRequest,
    ) -> Result<ProtoRegisterResponse, Status> {
        let mut verifier = self
            .verifier
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        let request: RegisterRequest<BigNum> = request.from_proto(&mut verifier.ctx)?;

        let mut registrations = self
            .registrations
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        registrations.insert(
            request.user.clone(),
            Registration {
                y1: request.y1,
                y2: request.y2,
            },
        );

        Ok(ProtoRegisterResponse {})
    }

    async fn create_authentication_challenge(
        &self,
        request: ProtoAuthenticationChallengeRequest,
    ) -> Result<ProtoAuthenticationChallengeResponse, Status> {
        let mut verifier = self
            .verifier
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        let request: AuthenticationChallengeRequest<BigNum> =
            request.from_proto(&mut verifier.ctx)?;

        let registrations = self
            .registrations
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        if !registrations.contains_key(&request.user) {
            return Err(Status::not_found("User not registered"));
        }

        let c = verifier
            .random()
            .map_err(|_| Status::internal("Failed to create challenge"))?;

        let auth_id = Uuid::new_v4().to_string();
        let mut auth_states = self
            .authentication_states
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        auth_states.insert(
            auth_id.clone(),
            AuthenticationState {
                r1: request.r1,
                r2: request.r2,
                c: c.to_owned().map_err(|_| Status::internal("Clone error"))?,
                user: request.user,
            },
        );

        let response = AuthenticationChallengeResponse { auth_id, c };

        response.to_proto(&mut verifier.ctx)
    }

    async fn verify_authentication(
        &self,
        request: ProtoAuthenticationAnswerRequest,
    ) -> Result<ProtoAuthenticationAnswerResponse, Status> {
        let mut verifier = self
            .verifier
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        let request = request.from_proto(&mut verifier.ctx)?;

        let mut auth_states = self
            .authentication_states
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        let state = auth_states
            .get(&request.auth_id)
            .ok_or_else(|| Status::not_found("Invalid auth_id"))?;

        let registrations = self
            .registrations
            .lock()
            .map_err(|_| Status::internal("Lock error"))?;
        let registration = registrations
            .get(&state.user)
            .ok_or_else(|| Status::not_found("User not registered"))?;

        let verified = verifier
            .check(
                &registration.y1,
                &registration.y2,
                &state.r1,
                &state.r2,
                &state.c,
                &request.s,
            )
            .map_err(|_| Status::internal("Verification failed"))?;

        if verified {
            auth_states.remove(&request.auth_id);

            let response = AuthenticationAnswerResponse {
                session_id: Uuid::new_v4().to_string(),
            };
            response.to_proto(&mut verifier.ctx)
        } else {
            Err(Status::unauthenticated("Authentication failed"))
        }
    }
}
