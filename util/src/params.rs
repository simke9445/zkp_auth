use openssl::bn::BigNumContext;
use openssl::ec::EcGroup;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::{bn::BigNum, ec::EcPoint};

use crypto::dl::params::DlParams;
use crypto::ec::params::EcParams;

// TODO: choose different p and g, not p = 2q + 1
// Constants for DL parameters
pub const DL_P: &[u8] = &[
    1, 228, 164, 70, 159, 253, 85, 99, 176, 119, 239, 15, 7, 41, 200, 100, 185, 252, 39, 57, 182,
    165, 89, 116, 125, 36, 82, 106, 231, 247, 255, 149, 95,
];
pub const DL_G: &[u8] = &[
    44, 96, 70, 169, 189, 112, 246, 137, 174, 132, 91, 238, 129, 189, 51, 169, 151, 84, 35, 62, 66,
    123, 242, 121, 194, 25, 100, 138, 158, 48, 113, 41,
];
pub const DL_H: &[u8] = &[
    52, 175, 175, 4, 167, 10, 98, 111, 238, 133, 24, 107, 87, 12, 78, 101, 55, 109, 3, 250, 132,
    235, 188, 90, 2, 196, 67, 151, 103, 224, 143, 63,
];

// Constants for EC parameters
pub const EC_G: &[u8] = &[
    2, 203, 98, 195, 54, 234, 150, 67, 169, 241, 37, 73, 20, 37, 137, 250, 84, 179, 217, 71, 229,
    83, 63, 176, 238, 208, 109, 185, 82, 44, 80, 41, 93,
];
pub const EC_H: &[u8] = &[
    2, 203, 98, 195, 54, 234, 150, 67, 169, 241, 37, 73, 20, 37, 137, 250, 84, 179, 217, 71, 229,
    83, 63, 176, 238, 208, 109, 185, 82, 44, 80, 41, 93,
];
pub const EC_CURVE: Nid = Nid::SECP256K1;

pub fn ec_params() -> Result<EcParams, ErrorStack> {
    let mut ctx = BigNumContext::new().unwrap();
    let group = EcGroup::from_curve_name(EC_CURVE)?;

    let g = EcPoint::from_bytes(&group, EC_G, &mut ctx)?;
    let h = EcPoint::from_bytes(&group, EC_H, &mut ctx)?;
    let params = EcParams::with_params(EC_CURVE, g, h)?;

    Ok(params)
}

pub fn dl_params() -> Result<DlParams, ErrorStack> {
    let p = BigNum::from_slice(DL_P)?;
    let g = BigNum::from_slice(DL_G)?;
    let h = BigNum::from_slice(DL_H)?;
    let params = DlParams::with_params(p, g, h)?;

    Ok(params)
}
