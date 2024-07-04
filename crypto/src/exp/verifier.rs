use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

use crate::util::rng;

use super::params::ExpParams;

pub struct ExpVerifier<'a> {
    pub params: &'a ExpParams,
    pub ctx: BigNumContext,
}

impl<'a> ExpVerifier<'a> {
    pub fn new(params: &ExpParams) -> Result<ExpVerifier, ErrorStack> {
        return Ok(ExpVerifier {
            params,
            ctx: BigNumContext::new()?,
        });
    }

    pub fn random(&self) -> Result<BigNum, ErrorStack> {
        let rand: BigNum = rng(&self.params.q).unwrap();

        Ok(rand)
    }

    pub fn check(
        &mut self,
        y1: &BigNum,
        y2: &BigNum,
        r1: &BigNum,
        r2: &BigNum,
        c: &BigNum,
        s: &BigNum,
    ) -> Result<bool, ErrorStack> {
        let mut gs = BigNum::new().unwrap();
        gs.mod_exp(&self.params.g, s, &self.params.p, &mut self.ctx)?;
        let mut hs = BigNum::new().unwrap();
        hs.mod_exp(&self.params.h, s, &self.params.p, &mut self.ctx)?;
        let mut y1c = BigNum::new().unwrap();
        y1c.mod_exp(y1, c, &self.params.p, &mut self.ctx)?;
        let mut y2c = BigNum::new().unwrap();
        y2c.mod_exp(y2, c, &self.params.p, &mut self.ctx)?;

        let mut check1 = BigNum::new().unwrap();
        check1.mod_mul(&gs, &y1c, &self.params.p, &mut self.ctx)?;
        let mut check2 = BigNum::new().unwrap();
        check2.mod_mul(&hs, &y2c, &self.params.p, &mut self.ctx)?;

        Ok(check1 == *r1 && check2 == *r2)
    }
}
