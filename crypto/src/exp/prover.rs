use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

use crate::util::{mod_mul, mod_sub, rng};

use super::params::ExpParams;

pub struct ExpProverCommit {
    pub r1: BigNum,
    pub r2: BigNum,
}

pub struct ExpProverChallengeReponse {
    pub s: BigNum,
}

pub struct ExpProverPublicKeys {
    pub y1: BigNum,
    pub y2: BigNum,
}

pub struct ExpProver<'a> {
    pub params: &'a ExpParams,
    pub ctx: BigNumContext,
}

impl<'a> ExpProver<'a> {
    pub fn random(&self) -> Result<BigNum, ErrorStack> {
        let rand: BigNum = rng(&self.params.q).unwrap();

        Ok(rand)
    }

    pub fn public_keys(&mut self, x: &BigNum) -> Result<ExpProverPublicKeys, ErrorStack> {
        let mut y1 = BigNum::new().unwrap();
        let mut y2 = BigNum::new().unwrap();
        y1.mod_exp(&self.params.g, &x, &self.params.p, &mut self.ctx)?;
        y2.mod_exp(&self.params.h, &x, &self.params.p, &mut self.ctx)?;

        Ok(ExpProverPublicKeys { y1, y2 })
    }

    pub fn commit(&mut self, k: &BigNum) -> Result<ExpProverCommit, ErrorStack> {
        let mut r1 = BigNum::new().unwrap();
        let mut r2 = BigNum::new().unwrap();

        r1.mod_exp(&self.params.g, &k, &self.params.p, &mut self.ctx)?;
        r2.mod_exp(&self.params.h, &k, &self.params.p, &mut self.ctx)?;

        Ok(ExpProverCommit { r1, r2 })
    }

    pub fn challenge_response(
        &mut self,
        k: &BigNum,
        c: &BigNum,
        x: &BigNum,
    ) -> Result<ExpProverChallengeReponse, ErrorStack> {
        Ok(ExpProverChallengeReponse {
            s: mod_sub(
                k,
                &mod_mul(c, x, &self.params.q, &mut self.ctx)?,
                &self.params.q,
                &mut self.ctx,
            )?,
        })
    }
}
