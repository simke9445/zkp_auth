use super::conversion::{FromProto, ToProto};
use super::types::{
    AuthServer, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, AuthenticationState, RegisterRequest, Registration,
};
use crypto::ec::verifier::EcVerifier;
use crypto::verifier::Verifier;
use dashmap::DashMap;
use openssl::ec::EcPoint;
use tonic::Status;
use uuid::Uuid;

use proto::zkp_auth::{
    AuthenticationAnswerRequest as ProtoAuthenticationAnswerRequest,
    AuthenticationAnswerResponse as ProtoAuthenticationAnswerResponse,
    AuthenticationChallengeRequest as ProtoAuthenticationChallengeRequest,
    AuthenticationChallengeResponse as ProtoAuthenticationChallengeResponse,
    RegisterRequest as ProtoRegisterRequest, RegisterResponse as ProtoRegisterResponse,
};

pub struct EcAuthServer {
    verifier: EcVerifier,
    registrations: DashMap<String, Registration<EcPoint>>,
    authentication_states: DashMap<String, AuthenticationState<EcPoint>>,
}

impl EcAuthServer {
    pub fn new(verifier: EcVerifier) -> Self {
        EcAuthServer {
            verifier,
            registrations: DashMap::new(),
            authentication_states: DashMap::new(),
        }
    }
}

#[tonic::async_trait]
impl AuthServer for EcAuthServer {
    async fn register(
        &self,
        request: ProtoRegisterRequest,
    ) -> Result<ProtoRegisterResponse, Status> {
        let request: RegisterRequest<EcPoint> = request.from_proto()?;

        self.registrations.insert(
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
        let request: AuthenticationChallengeRequest<EcPoint> = request.from_proto()?;

        if !self.registrations.contains_key(&request.user) {
            return Err(Status::not_found("User not registered"));
        }

        let c = self
            .verifier
            .random()
            .map_err(|_| Status::internal("Failed to create challenge"))?;

        let auth_id = Uuid::new_v4().to_string();
        self.authentication_states.insert(
            auth_id.clone(),
            AuthenticationState {
                r1: request.r1,
                r2: request.r2,
                c: c.to_owned().map_err(|_| Status::internal("Clone error"))?,
                user: request.user,
            },
        );

        let response = AuthenticationChallengeResponse { auth_id, c };

        response.to_proto()
    }

    async fn verify_authentication(
        &self,
        request: ProtoAuthenticationAnswerRequest,
    ) -> Result<ProtoAuthenticationAnswerResponse, Status> {
        let request = request.from_proto()?;

        let verified = self
            .authentication_states
            .remove_if(&request.auth_id, |_, state| {
                if let Some(registration) = self.registrations.get(&state.user) {
                    self.verifier
                        .check(
                            &registration.y1,
                            &registration.y2,
                            &state.r1,
                            &state.r2,
                            &state.c,
                            &request.s,
                        )
                        .unwrap_or(false)
                } else {
                    false // Check failed, don't remove state
                }
            });

        match verified {
            Some(_) => {
                let response = AuthenticationAnswerResponse {
                    session_id: Uuid::new_v4().to_string(),
                };
                response.to_proto()
            }
            None => Err(Status::unauthenticated("Authentication failed")),
        }
    }
}
