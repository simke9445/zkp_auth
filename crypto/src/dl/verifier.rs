use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

use crate::{context::with_bn_ctx, util::rng, verifier::Verifier};

use super::params::DlParams;

pub struct DlVerifier {
    pub params: DlParams,
    pub ctx: BigNumContext,
}

impl Verifier<DlParams, BigNum> for DlVerifier {
    fn new(params: DlParams) -> Result<DlVerifier, ErrorStack> {
        Ok(DlVerifier {
            params,
            ctx: BigNumContext::new()?,
        })
    }

    fn random(&self) -> Result<BigNum, ErrorStack> {
        let rand: BigNum = rng(&self.params.q).unwrap();

        Ok(rand)
    }

    fn check(
        &self,
        y1: &BigNum,
        y2: &BigNum,
        r1: &BigNum,
        r2: &BigNum,
        c: &BigNum,
        s: &BigNum,
    ) -> Result<bool, ErrorStack> {
        with_bn_ctx(|ctx| {
            let mut gs = BigNum::new().unwrap();
            gs.mod_exp(&self.params.g, s, &self.params.p, ctx)?;
            let mut hs = BigNum::new().unwrap();
            hs.mod_exp(&self.params.h, s, &self.params.p, ctx)?;
            let mut y1c = BigNum::new().unwrap();
            y1c.mod_exp(y1, c, &self.params.p, ctx)?;
            let mut y2c = BigNum::new().unwrap();
            y2c.mod_exp(y2, c, &self.params.p, ctx)?;

            let mut check1 = BigNum::new().unwrap();
            check1.mod_mul(&gs, &y1c, &self.params.p, ctx)?;
            let mut check2 = BigNum::new().unwrap();
            check2.mod_mul(&hs, &y2c, &self.params.p, ctx)?;

            Ok(check1 == *r1 && check2 == *r2)
        })
    }
}
