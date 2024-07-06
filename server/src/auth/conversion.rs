use super::types::{
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcPoint;
use proto::zkp_auth::{
    AuthenticationAnswerRequest as ProtoAuthenticationAnswerRequest,
    AuthenticationAnswerResponse as ProtoAuthenticationAnswerResponse,
    AuthenticationChallengeRequest as ProtoAuthenticationChallengeRequest,
    AuthenticationChallengeResponse as ProtoAuthenticationChallengeResponse,
    RegisterRequest as ProtoRegisterRequest, RegisterResponse as ProtoRegisterResponse,
};
use tonic::Status;
use util::codec::Codec;

pub trait FromProto<T>: Sized {
    #[allow(clippy::wrong_self_convention)]
    fn from_proto(self, ctx: &mut BigNumContext) -> Result<T, Status>;
}

pub trait ToProto<T> {
    fn to_proto(self, ctx: &mut BigNumContext) -> Result<T, Status>;
}

impl FromProto<RegisterRequest<EcPoint>> for ProtoRegisterRequest {
    fn from_proto(self, ctx: &mut BigNumContext) -> Result<RegisterRequest<EcPoint>, Status> {
        Ok(RegisterRequest {
            user: self.user,
            y1: EcPoint::decode(&self.y1, ctx)
                .map_err(|_| Status::invalid_argument("Invalid y1"))?,
            y2: EcPoint::decode(&self.y2, ctx)
                .map_err(|_| Status::invalid_argument("Invalid y2"))?,
        })
    }
}

impl FromProto<RegisterRequest<BigNum>> for ProtoRegisterRequest {
    fn from_proto(self, ctx: &mut BigNumContext) -> Result<RegisterRequest<BigNum>, Status> {
        Ok(RegisterRequest {
            user: self.user,
            y1: BigNum::decode(&self.y1, ctx)
                .map_err(|_| Status::invalid_argument("Invalid y1"))?,
            y2: BigNum::decode(&self.y2, ctx)
                .map_err(|_| Status::invalid_argument("Invalid y2"))?,
        })
    }
}

impl ToProto<ProtoRegisterResponse> for RegisterResponse {
    fn to_proto(self, _ctx: &mut BigNumContext) -> Result<ProtoRegisterResponse, Status> {
        Ok(ProtoRegisterResponse {})
    }
}

impl FromProto<AuthenticationChallengeRequest<EcPoint>> for ProtoAuthenticationChallengeRequest {
    fn from_proto(
        self,
        ctx: &mut BigNumContext,
    ) -> Result<AuthenticationChallengeRequest<EcPoint>, Status> {
        Ok(AuthenticationChallengeRequest {
            user: self.user,
            r1: EcPoint::decode(&self.r1, ctx)
                .map_err(|_| Status::invalid_argument("Invalid r1"))?,
            r2: EcPoint::decode(&self.r2, ctx)
                .map_err(|_| Status::invalid_argument("Invalid r2"))?,
        })
    }
}

impl FromProto<AuthenticationChallengeRequest<BigNum>> for ProtoAuthenticationChallengeRequest {
    fn from_proto(
        self,
        ctx: &mut BigNumContext,
    ) -> Result<AuthenticationChallengeRequest<BigNum>, Status> {
        Ok(AuthenticationChallengeRequest {
            user: self.user,
            r1: BigNum::decode(&self.r1, ctx)
                .map_err(|_| Status::invalid_argument("Invalid r1"))?,
            r2: BigNum::decode(&self.r2, ctx)
                .map_err(|_| Status::invalid_argument("Invalid r2"))?,
        })
    }
}

impl ToProto<ProtoAuthenticationChallengeResponse> for AuthenticationChallengeResponse {
    fn to_proto(
        self,
        ctx: &mut BigNumContext,
    ) -> Result<ProtoAuthenticationChallengeResponse, Status> {
        Ok(ProtoAuthenticationChallengeResponse {
            auth_id: self.auth_id,
            c: self
                .c
                .encode(ctx)
                .map_err(|_| Status::invalid_argument("Invalid c"))?,
        })
    }
}

impl FromProto<AuthenticationAnswerRequest> for ProtoAuthenticationAnswerRequest {
    fn from_proto(self, ctx: &mut BigNumContext) -> Result<AuthenticationAnswerRequest, Status> {
        Ok(AuthenticationAnswerRequest {
            auth_id: self.auth_id,
            s: BigNum::decode(&self.s, ctx).map_err(|_| Status::invalid_argument("Invalid s"))?,
        })
    }
}

impl ToProto<ProtoAuthenticationAnswerResponse> for AuthenticationAnswerResponse {
    fn to_proto(
        self,
        _ctx: &mut BigNumContext,
    ) -> Result<ProtoAuthenticationAnswerResponse, Status> {
        Ok(ProtoAuthenticationAnswerResponse {
            session_id: self.session_id,
        })
    }
}
