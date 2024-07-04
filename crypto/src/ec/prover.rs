use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcPoint;
use openssl::error::ErrorStack;

use crate::util::{mod_mul, mod_sub, rng};

use super::params::EcParams;

pub struct EcProver<'a> {
    pub params: &'a EcParams,
    pub ctx: BigNumContext,
}

pub struct EcProverCommit {
    pub r1: EcPoint,
    pub r2: EcPoint,
}

pub struct EcProverChallengeReponse {
    pub s: BigNum,
}

pub struct EcProverPublicKeys {
    pub y1: EcPoint,
    pub y2: EcPoint,
}

impl<'a> EcProver<'a> {
    pub fn random(&mut self) -> Result<BigNum, ErrorStack> {
        let rand = rng(&self.params.order)?;

        Ok(rand)
    }

    pub fn public_keys(&mut self, x: &BigNum) -> Result<EcProverPublicKeys, ErrorStack> {
        let mut y1 = EcPoint::new(&self.params.group)?;
        y1.mul(&self.params.group, &self.params.g, x, &mut self.ctx)?;
        let mut y2 = EcPoint::new(&self.params.group)?;
        y2.mul(&self.params.group, &self.params.h, x, &mut self.ctx)?;

        Ok(EcProverPublicKeys { y1, y2 })
    }

    pub fn commit(&mut self, k: &BigNum) -> Result<EcProverCommit, ErrorStack> {
        let mut r1 = EcPoint::new(&self.params.group)?;
        r1.mul(&self.params.group, &self.params.g, k, &mut self.ctx)?;
        let mut r2 = EcPoint::new(&self.params.group)?;
        r2.mul(&self.params.group, &self.params.h, k, &mut self.ctx)?;

        Ok(EcProverCommit { r1, r2 })
    }

    pub fn challenge_response(
        &mut self,
        k: &BigNum,
        c: &BigNum,
        x: &BigNum,
    ) -> Result<EcProverChallengeReponse, ErrorStack> {
        let s = mod_sub(
            k,
            &mod_mul(c, x, &self.params.order, &mut self.ctx)?,
            &self.params.order,
            &mut self.ctx,
        )?;

        Ok(EcProverChallengeReponse { s })
    }
}
