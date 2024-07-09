#![allow(clippy::unnecessary_mut_passed)]

use openssl::{bn::BigNum, ec::EcPoint, error::ErrorStack};

use crate::{context::with_bn_ctx, util::rng, verifier::Verifier};

use super::params::EcParams;

pub struct EcVerifier {
    pub params: EcParams,
}

impl Verifier<EcParams, EcPoint> for EcVerifier {
    fn new(params: EcParams) -> Result<EcVerifier, ErrorStack> {
        Ok(EcVerifier { params })
    }

    fn random(&self) -> Result<BigNum, ErrorStack> {
        let rand = rng(&self.params.order)?;
        Ok(rand)
    }

    fn check(
        &self,
        y1: &EcPoint,
        y2: &EcPoint,
        r1: &EcPoint,
        r2: &EcPoint,
        c: &BigNum,
        s: &BigNum,
    ) -> Result<bool, ErrorStack> {
        with_bn_ctx(|ctx| {
            // Calculate g^s
            let mut gs = EcPoint::new(&self.params.group)?;
            gs.mul(&self.params.group, &self.params.g, s, ctx)?;

            // Calculate h^s
            let mut hs = EcPoint::new(&self.params.group)?;
            hs.mul(&self.params.group, &self.params.h, s, ctx)?;

            // Calculate y1^c
            let mut y1c = EcPoint::new(&self.params.group)?;
            y1c.mul(&self.params.group, y1, c, ctx)?;

            // Calculate y2^c
            let mut y2c = EcPoint::new(&self.params.group)?;
            y2c.mul(&self.params.group, y2, c, ctx)?;

            // Calculate check1 = g^s * y1^c
            let mut check1 = EcPoint::new(&self.params.group)?;
            check1.add(&self.params.group, &gs, &y1c, ctx)?;

            // Calculate check2 = h^s * y2^c
            let mut check2 = EcPoint::new(&self.params.group)?;
            check2.add(&self.params.group, &hs, &y2c, ctx)?;

            // Compare check1 with r1 and check2 with r2
            Ok(
                check1.eq(&self.params.group, r1, ctx)?
                    && check2.eq(&self.params.group, r2, ctx)?,
            )
        })
    }
}
