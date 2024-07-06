use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

use crate::{
    prover::{Prover, ProverChallengeResponse, ProverCommit, ProverPublicKeys},
    util::{mod_mul, mod_sub, rng},
};

use super::params::DlParams;

pub struct DlProver {
    pub params: DlParams,
    pub ctx: BigNumContext,
}

impl Prover<DlParams, BigNum> for DlProver {
    fn new(params: DlParams) -> Result<DlProver, ErrorStack> {
        Ok(DlProver {
            params,
            ctx: BigNumContext::new()?,
        })
    }

    fn random(&self) -> Result<BigNum, ErrorStack> {
        let rand: BigNum = rng(&self.params.q).unwrap();

        Ok(rand)
    }

    fn public_keys(&mut self, x: &BigNum) -> Result<ProverPublicKeys<BigNum>, ErrorStack> {
        let mut y1 = BigNum::new().unwrap();
        let mut y2 = BigNum::new().unwrap();
        y1.mod_exp(&self.params.g, x, &self.params.p, &mut self.ctx)?;
        y2.mod_exp(&self.params.h, x, &self.params.p, &mut self.ctx)?;

        Ok(ProverPublicKeys { y1, y2 })
    }

    fn commit(&mut self, k: &BigNum) -> Result<ProverCommit<BigNum>, ErrorStack> {
        let mut r1 = BigNum::new().unwrap();
        let mut r2 = BigNum::new().unwrap();

        r1.mod_exp(&self.params.g, k, &self.params.p, &mut self.ctx)?;
        r2.mod_exp(&self.params.h, k, &self.params.p, &mut self.ctx)?;

        Ok(ProverCommit { r1, r2 })
    }

    fn challenge_response(
        &mut self,
        k: &BigNum,
        c: &BigNum,
        x: &BigNum,
    ) -> Result<ProverChallengeResponse, ErrorStack> {
        Ok(ProverChallengeResponse {
            s: mod_sub(
                k,
                &mod_mul(c, x, &self.params.q, &mut self.ctx)?,
                &self.params.q,
                &mut self.ctx,
            )?,
        })
    }
}
