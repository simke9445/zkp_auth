use openssl::bn::BigNumContext;
use openssl::ec::EcGroup;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::{bn::BigNum, ec::EcPoint};

use crypto::dl::params::DlParams;
use crypto::ec::params::EcParams;

// Constants for DL parameters
// q = 95323790354645866989878273881751216942630210959135343057135663681821136636963
pub const DL_Q: &[u8] = &[
    210, 191, 90, 118, 231, 36, 240, 249, 221, 135, 95, 42, 202, 116, 56, 43, 79, 165, 55, 51, 241,
    56, 40, 60, 238, 76, 134, 128, 63, 23, 204, 35,
];
// p = 190647580709291733979756547763502433885260421918270686114271327363642273273927
pub const DL_P: &[u8] = &[
    1, 165, 126, 180, 237, 206, 73, 225, 243, 187, 14, 190, 85, 148, 232, 112, 86, 159, 74, 110,
    103, 226, 112, 80, 121, 220, 153, 13, 0, 126, 47, 152, 71,
];
// g = 171670852572928472888139503175515038342604868353722897525558979317782763303223
pub const DL_G: &[u8] = &[
    1, 123, 138, 66, 94, 146, 149, 205, 114, 62, 193, 223, 114, 153, 3, 64, 62, 199, 104, 176, 23,
    44, 61, 209, 90, 46, 76, 221, 199, 206, 236, 113, 55,
];
// h = 23879747473187410337148282237111274999995618673330608148166136263819518677657
pub const DL_H: &[u8] = &[
    52, 203, 117, 70, 11, 73, 148, 228, 72, 226, 87, 31, 54, 82, 19, 130, 1, 46, 51, 83, 156, 101,
    25, 183, 194, 160, 120, 163, 189, 126, 18, 153,
];

// Constants for EC parameters
// (x, y) = (87254753980364497552870028920037307725331490527579155562257602382389969860720, 5680688582317100251061343659837920885585461670565723910007566337080519753216)
pub const EC_G: &[u8] = &[
    2, 192, 232, 112, 205, 104, 39, 209, 104, 239, 95, 247, 140, 78, 240, 157, 167, 251, 165, 208,
    111, 44, 60, 153, 143, 118, 211, 80, 132, 78, 190, 184, 112,
];
// (x, y) = (84393524528455714661586904515318407170919209766852059800669914116931836361041, 87870688185902817226144150486770308118957474588889599130244928736264613435325)
pub const EC_H: &[u8] = &[
    3, 186, 149, 10, 202, 151, 100, 123, 187, 240, 64, 106, 197, 30, 24, 93, 77, 13, 255, 228, 204,
    21, 240, 176, 54, 127, 46, 1, 83, 124, 154, 185, 81,
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
    let q = BigNum::from_slice(DL_Q)?;
    let p = BigNum::from_slice(DL_P)?;
    let g = BigNum::from_slice(DL_G)?;
    let h = BigNum::from_slice(DL_H)?;
    let params = DlParams::with_params(q, p, g, h)?;

    Ok(params)
}
