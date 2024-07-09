use crypto::context::with_bn_ctx;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::{bn::BigNum, ec::EcPoint};

use crate::params::EC_CURVE;

pub trait Codec: Sized {
    fn encode(&self) -> Result<Vec<u8>, ErrorStack>;
    fn decode(data: &[u8]) -> Result<Self, ErrorStack>;
}

impl Codec for EcPoint {
    fn encode(&self) -> Result<Vec<u8>, ErrorStack> {
        with_bn_ctx(|ctx: &mut openssl::bn::BigNumContext| {
            let group = EcGroup::from_curve_name(EC_CURVE)?;
            self.to_bytes(&group, PointConversionForm::COMPRESSED, ctx)
        })
    }

    fn decode(data: &[u8]) -> Result<Self, ErrorStack> {
        with_bn_ctx(|ctx: &mut openssl::bn::BigNumContext| {
            let group = EcGroup::from_curve_name(EC_CURVE)?;
            EcPoint::from_bytes(&group, data, ctx)
        })
    }
}

impl Codec for BigNum {
    fn encode(&self) -> Result<Vec<u8>, ErrorStack> {
        Ok(self.to_vec())
    }

    fn decode(data: &[u8]) -> Result<Self, ErrorStack> {
        BigNum::from_slice(data)
    }
}
