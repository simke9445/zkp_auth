use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::{bn::BigNum, ec::EcPoint};

use crate::params::EC_CURVE;

pub trait Codec: Sized {
    fn encode(&self, ctx: &mut BigNumContext) -> Result<Vec<u8>, ErrorStack>;
    fn decode(data: &[u8], ctx: &mut BigNumContext) -> Result<Self, ErrorStack>;
}

impl Codec for EcPoint {
    fn encode(&self, ctx: &mut BigNumContext) -> Result<Vec<u8>, ErrorStack> {
        let group = EcGroup::from_curve_name(EC_CURVE)?;
        self.to_bytes(&group, PointConversionForm::COMPRESSED, ctx)
    }

    fn decode(data: &[u8], ctx: &mut BigNumContext) -> Result<Self, ErrorStack> {
        let group = EcGroup::from_curve_name(EC_CURVE)?;
        EcPoint::from_bytes(&group, data, ctx)
    }
}

impl Codec for BigNum {
    fn encode(&self, _ctx: &mut BigNumContext) -> Result<Vec<u8>, ErrorStack> {
        Ok(self.to_vec())
    }

    fn decode(data: &[u8], _ctx: &mut BigNumContext) -> Result<Self, ErrorStack> {
        BigNum::from_slice(data)
    }
}
