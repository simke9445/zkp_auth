use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcPoint,
    error::ErrorStack,
};

use crate::util::rng;

use super::params::EcParams;

pub struct EcVerifier<'a> {
    pub params: &'a EcParams,
    pub ctx: BigNumContext,
}

impl<'a> EcVerifier<'a> {
    pub fn random(&self) -> Result<BigNum, ErrorStack> {
        let rand = rng(&self.params.order)?;
        Ok(rand)
    }

    pub fn check(
        &mut self,
        y1: &EcPoint,
        y2: &EcPoint,
        r1: &EcPoint,
        r2: &EcPoint,
        c: &BigNum,
        s: &BigNum,
    ) -> Result<bool, ErrorStack> {
        // Calculate g^s
        let mut gs = EcPoint::new(&self.params.group)?;
        gs.mul(&self.params.group, &self.params.g, s, &mut self.ctx)?;

        // Calculate h^s
        let mut hs = EcPoint::new(&self.params.group)?;
        hs.mul(&self.params.group, &self.params.h, s, &mut self.ctx)?;

        // Calculate y1^c
        let mut y1c = EcPoint::new(&self.params.group)?;
        y1c.mul(&self.params.group, y1, c, &mut self.ctx)?;

        // Calculate y2^c
        let mut y2c = EcPoint::new(&self.params.group)?;
        y2c.mul(&self.params.group, y2, c, &mut self.ctx)?;

        // Calculate check1 = g^s * y1^c
        let mut check1 = EcPoint::new(&self.params.group)?;
        check1.add(&self.params.group, &gs, &y1c, &mut self.ctx)?;

        // Calculate check2 = h^s * y2^c
        let mut check2 = EcPoint::new(&self.params.group)?;
        check2.add(&self.params.group, &hs, &y2c, &mut self.ctx)?;

        // Compare check1 with r1 and check2 with r2
        Ok(check1.eq(&self.params.group, r1, &mut self.ctx)?
            && check2.eq(&self.params.group, r2, &mut self.ctx)?)
    }
}
