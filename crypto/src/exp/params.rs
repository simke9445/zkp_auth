use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;

pub fn is_generator(
    g: &BigNum,
    q: &BigNum,
    p: &BigNum,
    ctx: &mut BigNumContext,
) -> Result<bool, ErrorStack> {
    let mut exp = BigNum::new()?;
    // Check if g^q mod p = 1
    exp.mod_exp(g, q, p, ctx)?;
    Ok(exp == BigNum::from_u32(1)? && *g != BigNum::from_u32(1)?)
}

fn find_generator(q: &BigNum, p: &BigNum, ctx: &mut BigNumContext) -> Result<BigNum, ErrorStack> {
    let mut x = BigNum::new()?;
    loop {
        p.rand_range(&mut x)?;
        let mut y = BigNum::new()?;
        y.mod_exp(&x, &BigNum::from_u32(2).unwrap(), p, ctx)?;
        if is_generator(&y, q, p, ctx)? {
            return Ok(y);
        }
    }
}

pub struct ExpParams {
    pub q: BigNum,
    pub p: BigNum,
    pub g: BigNum,
    pub h: BigNum,
}

pub fn generate_params(bit_length: i32) -> Result<ExpParams, ErrorStack> {
    let mut ctx = BigNumContext::new()?;

    // Generate prime q
    let mut p = BigNum::new().unwrap();
    p.generate_prime(bit_length + 1, true, None, None)?;

    let mut q = p.to_owned().unwrap();
    let mut tmp = q.to_owned().unwrap();
    q.checked_sub(&tmp, &BigNum::from_u32(1).unwrap()).unwrap();
    tmp = q.to_owned().unwrap();
    q.checked_div(&tmp, &BigNum::from_u32(2).unwrap(), &mut ctx)
        .unwrap();

    // Find a generator
    let g = find_generator(&q, &p, &mut ctx)?;
    let mut h = find_generator(&q, &p, &mut ctx)?;

    // Ensure h is different from g
    while h == g {
        h = find_generator(&q, &mut p, &mut ctx)?;
    }

    Ok(ExpParams { p, q, g, h })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_params() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;
        let ExpParams { p: _, q, g, h } = params;
        let mut ctx = BigNumContext::new()?;

        // Test 1: Verify q is prime
        assert!(q.is_prime(20, &mut ctx)?, "q is not prime");

        // Test 2: Verify p (2q + 1) is prime
        let mut p = BigNum::new()?;
        p.checked_mul(&BigNum::from_u32(2).unwrap(), &q, &mut ctx)?;
        let tmp = p.to_owned().unwrap();
        p.checked_add(&tmp, &BigNum::from_u32(1).unwrap())?;
        assert!(p.is_prime(20, &mut ctx)?, "p (2q + 1) is not prime");

        // Test 3: Verify g is a generator of order q
        assert!(
            is_generator(&g, &q, &p, &mut ctx)?,
            "g is not a generator of order q"
        );

        // Test 4: Verify h is a generator of order q
        assert!(
            is_generator(&h, &q, &p, &mut ctx)?,
            "h is not a generator of order q"
        );

        // Test 5: Verify g and h are different
        assert!(g != h, "g and h are not different");

        // Test 6: Verify q has the correct bit length
        assert!(q.num_bits() == 256, "q does not have 256 bits");

        println!(
            "h: {:?}, g: {:?}, q: {:?}, p: {:?}",
            h.to_dec_str(),
            g.to_dec_str(),
            q.to_dec_str(),
            p.to_dec_str()
        );

        Ok(())
    }

    #[test]
    fn test_multiple_generations() -> Result<(), ErrorStack> {
        for _ in 0..5 {
            let ExpParams { p: _, q, g, h } = generate_params(256)?;
            let mut ctx = BigNumContext::new()?;
            let mut p = BigNum::new()?;
            p.checked_mul(&BigNum::from_u32(2).unwrap(), &q, &mut ctx)?;
            let tmp = p.to_owned().unwrap();
            p.checked_add(&tmp, &BigNum::from_u32(1).unwrap())?;

            assert!(q.is_prime(20, &mut ctx)?, "q is not prime");
            assert!(p.is_prime(20, &mut ctx)?, "p (2q + 1) is not prime");
            assert!(
                is_generator(&g, &q, &p, &mut ctx)?,
                "g is not a generator of order q"
            );
            assert!(
                is_generator(&h, &q, &p, &mut ctx)?,
                "h is not a generator of order q"
            );
            assert!(g != h, "g and h are not different");
        }
        Ok(())
    }

    #[test]
    fn test_is_generator() -> Result<(), ErrorStack> {
        let mut ctx = BigNumContext::new()?;

        // Create a small prime q and corresponding p = 2q + 1
        let q = BigNum::from_dec_str("11")?; // q is prime
        let mut p = BigNum::new()?;
        p.checked_mul(&BigNum::from_u32(2).unwrap(), &q, &mut ctx)?;
        let tmp = p.to_owned().unwrap();
        p.checked_add(&tmp, &BigNum::from_u32(1).unwrap())?;
        // p should be 23, which is also prime

        // Known generator for this group
        let g = BigNum::from_u32(2)?;

        // Test known generator
        assert!(
            is_generator(&g, &q, &p, &mut ctx)?,
            "2 should be a generator"
        );

        // Test non-generator
        let non_gen = BigNum::from_u32(5)?;
        assert!(
            !is_generator(&non_gen, &q, &p, &mut ctx)?,
            "5 should not be a generator"
        );

        // Test edge cases
        let one = BigNum::from_u32(1)?;
        assert!(
            !is_generator(&one, &q, &p, &mut ctx)?,
            "1 should not be a generator"
        );

        let mut p_minus_one = BigNum::new()?;
        p_minus_one.checked_sub(&p, &one)?;
        assert!(
            !is_generator(&p_minus_one, &q, &p, &mut ctx)?,
            "p-1 should not be a generator"
        );

        // Test all values in the range [2, p-2]
        for i in 2..22 {
            let x = BigNum::from_u32(i)?;
            let is_gen = is_generator(&x, &q, &p, &mut ctx)?;
            println!("{} is generator: {}", i, is_gen);
            // The generators for this group should be 2, 3, 4, 6, 8, 9, 12, 13, 16, 18
            let expected = [2, 3, 4, 6, 8, 9, 12, 13, 16, 18].contains(&i);
            assert_eq!(is_gen, expected, "{} generator status is incorrect", i);
        }

        Ok(())
    }
}
