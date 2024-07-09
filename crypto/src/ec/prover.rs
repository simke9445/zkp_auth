#![allow(clippy::unnecessary_mut_passed)]

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcPoint;
use openssl::error::ErrorStack;

use crate::context::with_bn_ctx;
use crate::prover::{Prover, ProverChallengeResponse, ProverCommit, ProverPublicKeys};
use crate::util::{mod_mul, mod_sub, rng};

use super::params::EcParams;

pub struct EcProver {
    pub params: EcParams,
    pub ctx: BigNumContext,
}

impl Prover<EcParams, EcPoint> for EcProver {
    fn new(params: EcParams) -> Result<EcProver, ErrorStack> {
        Ok(EcProver {
            params,
            ctx: BigNumContext::new()?,
        })
    }

    fn random(&self) -> Result<BigNum, ErrorStack> {
        let rand = rng(&self.params.order)?;

        Ok(rand)
    }

    fn public_keys(&self, x: &BigNum) -> Result<ProverPublicKeys<EcPoint>, ErrorStack> {
        with_bn_ctx(|ctx| {
            let mut y1 = EcPoint::new(&self.params.group)?;
            y1.mul(&self.params.group, &self.params.g, x, ctx)?;
            let mut y2 = EcPoint::new(&self.params.group)?;
            y2.mul(&self.params.group, &self.params.h, x, ctx)?;

            Ok(ProverPublicKeys { y1, y2 })
        })
    }

    fn commit(&self, k: &BigNum) -> Result<ProverCommit<EcPoint>, ErrorStack> {
        with_bn_ctx(|ctx| {
            let mut r1 = EcPoint::new(&self.params.group)?;
            r1.mul(&self.params.group, &self.params.g, k, ctx)?;
            let mut r2 = EcPoint::new(&self.params.group)?;
            r2.mul(&self.params.group, &self.params.h, k, ctx)?;

            Ok(ProverCommit { r1, r2 })
        })
    }

    fn challenge_response(
        &self,
        k: &BigNum,
        c: &BigNum,
        x: &BigNum,
    ) -> Result<ProverChallengeResponse, ErrorStack> {
        with_bn_ctx(|ctx| {
            let s = mod_sub(
                k,
                &mod_mul(c, x, &self.params.order, ctx)?,
                &self.params.order,
                ctx,
            )?;

            Ok(ProverChallengeResponse { s })
        })
    }
}
