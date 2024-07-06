use super::auth::AuthServer;
use super::dl::DlAuthServer;
use super::ec::EcAuthServer;
use crypto::dl::verifier::DlVerifier;
use crypto::ec::verifier::EcVerifier;
use crypto::verifier::Verifier;
use proto::zkp_auth::auth_server::Auth;
use proto::zkp_auth::{
    AuthAlgo, AuthenticationAnswerRequest as ProtoAuthenticationAnswerRequest,
    AuthenticationAnswerResponse as ProtoAuthenticationAnswerResponse,
    AuthenticationChallengeRequest as ProtoAuthenticationChallengeRequest,
    AuthenticationChallengeResponse as ProtoAuthenticationChallengeResponse,
    RegisterRequest as ProtoRegisterRequest, RegisterResponse as ProtoRegisterResponse,
};
use std::error::Error;
use tonic::{Request, Response, Status};
use util::params::{dl_params, ec_params};

pub struct Server {
    pub ec_server: EcAuthServer,
    pub dl_server: DlAuthServer,
}

impl Server {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Server {
            ec_server: EcAuthServer::new(EcVerifier::new(ec_params()?)?),
            dl_server: DlAuthServer::new(DlVerifier::new(dl_params()?)?),
        })
    }
}

#[tonic::async_trait]
impl Auth for Server {
    async fn register(
        &self,
        request: Request<ProtoRegisterRequest>,
    ) -> Result<Response<ProtoRegisterResponse>, Status> {
        let req = request.into_inner();
        match AuthAlgo::try_from(req.auth_algo) {
            Ok(AuthAlgo::Ec) => {
                let response = self.ec_server.register(req).await?;
                Ok(Response::new(response))
            }
            Ok(AuthAlgo::Dl) => {
                let response = self.dl_server.register(req).await?;
                Ok(Response::new(response))
            }
            _ => Err(Status::invalid_argument("Invalid auth_algo")),
        }
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<ProtoAuthenticationChallengeRequest>,
    ) -> Result<Response<ProtoAuthenticationChallengeResponse>, Status> {
        let req = request.into_inner();
        match AuthAlgo::try_from(req.auth_algo) {
            Ok(AuthAlgo::Ec) => {
                let response = self.ec_server.create_authentication_challenge(req).await?;
                Ok(Response::new(response))
            }
            Ok(AuthAlgo::Dl) => {
                let response = self.dl_server.create_authentication_challenge(req).await?;
                Ok(Response::new(response))
            }
            _ => Err(Status::invalid_argument("Invalid auth_algo")),
        }
    }

    async fn verify_authentication(
        &self,
        request: Request<ProtoAuthenticationAnswerRequest>,
    ) -> Result<Response<ProtoAuthenticationAnswerResponse>, Status> {
        let req = request.into_inner();
        match AuthAlgo::try_from(req.auth_algo) {
            Ok(AuthAlgo::Ec) => {
                let response = self.ec_server.verify_authentication(req).await?;
                Ok(Response::new(response))
            }
            Ok(AuthAlgo::Dl) => {
                let response = self.dl_server.verify_authentication(req).await?;
                Ok(Response::new(response))
            }
            _ => Err(Status::invalid_argument("Invalid auth_algo")),
        }
    }
}
