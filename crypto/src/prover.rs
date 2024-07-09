use openssl::{bn::BigNum, error::ErrorStack};

pub struct ProverPublicKeys<Element> {
    pub y1: Element,
    pub y2: Element,
}

pub struct ProverCommit<Element> {
    pub r1: Element,
    pub r2: Element,
}

pub struct ProverChallengeResponse {
    pub s: BigNum,
}

pub trait Prover<Params, Element> {
    fn new(params: Params) -> Result<Self, ErrorStack>
    where
        Self: Sized;
    fn random(&self) -> Result<BigNum, ErrorStack>;
    fn public_keys(&self, x: &BigNum) -> Result<ProverPublicKeys<Element>, ErrorStack>;
    fn commit(&self, k: &BigNum) -> Result<ProverCommit<Element>, ErrorStack>;
    fn challenge_response(
        &self,
        k: &BigNum,
        c: &BigNum,
        x: &BigNum,
    ) -> Result<ProverChallengeResponse, ErrorStack>;
}
