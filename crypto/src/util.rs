use openssl::{bn::{BigNum, BigNumContext}, error::ErrorStack};

pub fn mod_sub(
  a: &BigNum,
  b: &BigNum,
  m: &BigNum,
  ctx: &mut BigNumContext,
) -> Result<BigNum, ErrorStack> {
  let mut result = BigNum::new()?;
  result.mod_sub(a, b, m, ctx)?;
  Ok(result)
}

pub fn mod_mul(
  a: &BigNum,
  b: &BigNum,
  m: &BigNum,
  ctx: &mut BigNumContext,
) -> Result<BigNum, ErrorStack> {
  let mut result = BigNum::new()?;
  result.mod_mul(a, b, m, ctx)?;
  Ok(result)
}

pub fn rng(p: &BigNum) -> Result<BigNum, ErrorStack> {
  let mut random = BigNum::new().unwrap();
  p.rand_range(&mut random)?;

  Ok(random)
}