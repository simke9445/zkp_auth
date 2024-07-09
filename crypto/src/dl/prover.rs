use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

use crate::{
    context::with_bn_ctx,
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

    fn public_keys(&self, x: &BigNum) -> Result<ProverPublicKeys<BigNum>, ErrorStack> {
        with_bn_ctx(|ctx: &mut BigNumContext| {
            let mut y1 = BigNum::new().unwrap();
            let mut y2 = BigNum::new().unwrap();
            y1.mod_exp(&self.params.g, x, &self.params.p, ctx)?;
            y2.mod_exp(&self.params.h, x, &self.params.p, ctx)?;

            Ok(ProverPublicKeys { y1, y2 })
        })
    }

    fn commit(&self, k: &BigNum) -> Result<ProverCommit<BigNum>, ErrorStack> {
        with_bn_ctx(|ctx: &mut BigNumContext| {
            let mut r1 = BigNum::new().unwrap();
            let mut r2 = BigNum::new().unwrap();

            r1.mod_exp(&self.params.g, k, &self.params.p, ctx)?;
            r2.mod_exp(&self.params.h, k, &self.params.p, ctx)?;

            Ok(ProverCommit { r1, r2 })
        })
    }

    fn challenge_response(
        &self,
        k: &BigNum,
        c: &BigNum,
        x: &BigNum,
    ) -> Result<ProverChallengeResponse, ErrorStack> {
        with_bn_ctx(|ctx: &mut BigNumContext| {
            Ok(ProverChallengeResponse {
                s: mod_sub(k, &mod_mul(c, x, &self.params.q, ctx)?, &self.params.q, ctx)?,
            })
        })
    }
}
