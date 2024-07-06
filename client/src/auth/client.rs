use std::collections::HashMap;
use std::error::Error;

use crypto::dl::prover::DlProver;
use crypto::ec::prover::EcProver;
use crypto::prover::Prover;
use tonic::transport::Channel;

use proto::zkp_auth::auth_client::AuthClient as ProtoAuthClient;
use proto::zkp_auth::AuthAlgo;

use util::params::{dl_params, ec_params};

use super::auth::AuthClient;
use super::dl::DlAuthClient;
use super::ec::EcAuthClient;

pub struct Client {
    ec_client: EcAuthClient,
    dl_client: DlAuthClient,
}

impl Client {
    pub async fn new(server_addr: String) -> Result<Self, Box<dyn Error>> {
        let channel = Channel::from_shared(server_addr)?.connect().await?;
        let client = ProtoAuthClient::new(channel.clone());

        Ok(Client {
            ec_client: EcAuthClient {
                client: client.clone(),
                prover: EcProver::new(ec_params()?)?,
                registrations: HashMap::new(),
                authentication_states: HashMap::new(),
            },
            dl_client: DlAuthClient {
                client,
                prover: DlProver::new(dl_params()?)?,
                registrations: HashMap::new(),
                authentication_states: HashMap::new(),
            },
        })
    }

    pub async fn register(&mut self, user: &str, algo: AuthAlgo) -> Result<(), Box<dyn Error>> {
        match algo {
            AuthAlgo::Ec => self.ec_client.register(user).await,
            AuthAlgo::Dl => self.dl_client.register(user).await,
        }
    }

    pub async fn create_authentication_challenge(
        &mut self,
        user: &str,
        algo: AuthAlgo,
    ) -> Result<String, Box<dyn Error>> {
        match algo {
            AuthAlgo::Ec => self.ec_client.create_authentication_challenge(user).await,
            AuthAlgo::Dl => self.dl_client.create_authentication_challenge(user).await,
        }
    }

    pub async fn verify_authentication(
        &mut self,
        auth_id: &str,
        algo: AuthAlgo,
    ) -> Result<String, Box<dyn Error>> {
        match algo {
            AuthAlgo::Ec => self.ec_client.verify_authentication(auth_id).await,
            AuthAlgo::Dl => self.dl_client.verify_authentication(auth_id).await,
        }
    }
}
