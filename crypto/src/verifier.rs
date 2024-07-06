use openssl::{bn::BigNum, error::ErrorStack};

pub trait Verifier<Params, Element> {
    fn new(params: Params) -> Result<Self, ErrorStack>
    where
        Self: Sized;
    fn random(&self) -> Result<BigNum, ErrorStack>;
    fn check(
        &mut self,
        y1: &Element,
        y2: &Element,
        r1: &Element,
        r2: &Element,
        c: &BigNum,
        s: &BigNum,
    ) -> Result<bool, ErrorStack>;
}
