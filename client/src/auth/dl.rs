use std::collections::HashMap;
use std::error::Error;

use crypto::dl::prover::DlProver;
use crypto::prover::Prover;
use openssl::bn::BigNum;
use tonic::{transport::Channel, Request};

use proto::zkp_auth::auth_client::AuthClient as ProtoAuthClient;
use proto::zkp_auth::{
    AuthAlgo, AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest,
};

use util::codec::Codec;

use super::types::{AuthClient, AuthenticationState, Registration};

pub struct DlAuthClient {
    pub client: ProtoAuthClient<Channel>,
    pub prover: DlProver,
    pub registrations: HashMap<String, Registration<BigNum>>,
    pub authentication_states: HashMap<String, AuthenticationState<BigNum>>,
}

impl AuthClient for DlAuthClient {
    async fn register(&mut self, user: &str) -> Result<(), Box<dyn Error>> {
        let x = self.prover.random()?;
        let keys = self.prover.public_keys(&x)?;

        let request = RegisterRequest {
            user: user.to_string(),
            y1: keys.y1.encode()?,
            y2: keys.y2.encode()?,
            auth_algo: AuthAlgo::Dl as i32,
        };

        self.client.register(Request::new(request)).await?;
        self.registrations.insert(
            user.to_string(),
            Registration {
                y1: keys.y1,
                y2: keys.y2,
                x,
            },
        );
        Ok(())
    }

    async fn create_authentication_challenge(
        &mut self,
        user: &str,
    ) -> Result<String, Box<dyn Error>> {
        let registration = self.registrations.get(user).ok_or("User not registered")?;

        let k = self.prover.random()?;
        let commit = self.prover.commit(&k)?;

        let request = AuthenticationChallengeRequest {
            user: user.to_string(),
            r1: commit.r1.encode()?,
            r2: commit.r2.encode()?,
            auth_algo: AuthAlgo::Dl as i32,
        };

        let response = self
            .client
            .create_authentication_challenge(Request::new(request))
            .await?;
        let resp = response.into_inner();
        let auth_id = resp.auth_id;
        let c = BigNum::decode(&resp.c)?;

        self.authentication_states.insert(
            auth_id.clone(),
            AuthenticationState {
                r1: commit.r1,
                r2: commit.r2,
                c,
                k,
                x: registration.x.to_owned()?,
            },
        );
        Ok(auth_id)
    }

    async fn verify_authentication(&mut self, auth_id: &str) -> Result<String, Box<dyn Error>> {
        let state = self
            .authentication_states
            .get(auth_id)
            .ok_or("Invalid auth_id")?;

        let response = self
            .prover
            .challenge_response(&state.k, &state.c, &state.x)?;

        let request = AuthenticationAnswerRequest {
            auth_id: auth_id.to_string(),
            s: response.s.encode()?,
            auth_algo: AuthAlgo::Dl as i32,
        };

        let response = self
            .client
            .verify_authentication(Request::new(request))
            .await?;
        self.authentication_states.remove(auth_id);
        Ok(response.into_inner().session_id)
    }
}
