use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;

fn find_generator(
    group: &EcGroup,
    order: &BigNum,
    ctx: &mut BigNumContext,
) -> Result<EcPoint, ErrorStack> {
    let mut point = EcPoint::new(group)?;
    let mut rand = BigNum::new()?;
    order.rand_range(&mut rand)?;
    point.mul_generator(group, &rand, ctx)?;

    Ok(point)
}

pub fn generate_params() -> Result<EcParams, ErrorStack> {
    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;

    let mut order = BigNum::new()?;
    group.order(&mut order, &mut ctx)?;

    // Find generators g and h
    let g = find_generator(&group, &order, &mut ctx)?;
    let mut h = find_generator(&group, &order, &mut ctx)?;

    // Ensure h is different from g
    while h.eq(&group, &g, &mut ctx)? {
        h = find_generator(&group, &order, &mut ctx)?;
    }

    Ok(EcParams { group, g, h, order })
}

pub struct EcParams {
    pub group: EcGroup,
    pub g: EcPoint,
    pub h: EcPoint,
    pub order: BigNum,
}
