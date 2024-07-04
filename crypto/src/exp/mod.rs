pub mod params;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests {
    use openssl::{bn::BigNumContext, error::ErrorStack};

    use crate::exp::{
        params::generate_params,
        prover::{ExpProver, ExpProverChallengeReponse, ExpProverCommit, ExpProverPublicKeys},
        verifier::ExpVerifier,
    };

    #[test]
    fn test_exp_chaum_pedersen_protocol() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;

        let mut prover = ExpProver {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        let mut verifier = ExpVerifier {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        // ExpProver's secret
        let x = prover.random()?;

        // ExpProver's public keys
        let ExpProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;

        // ExpProver's commitment
        let k = prover.random()?;
        let ExpProverCommit { r1, r2 } = prover.commit(&k)?;

        // ExpVerifier's challenge
        let c = verifier.random()?;

        // ExpProver's challenge response
        let ExpProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // ExpVerifier's check
        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;

        assert!(valid, "Chaum-Pedersen protocol verification failed");

        Ok(())
    }

    #[test]
    fn test_exp_incorrect_prover_secret() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;
        let mut prover = ExpProver { params: &params, ctx: BigNumContext::new()? };
        let mut verifier = ExpVerifier { params: &params, ctx: BigNumContext::new()? };

        let x = prover.random()?;
        let ExpProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ExpProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;

        // Use an incorrect secret for the challenge response
        let incorrect_x = prover.random()?;
        let ExpProverChallengeReponse { s } = prover.challenge_response(&k, &c, &incorrect_x)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect secret");

        Ok(())
    }

    #[test]
    fn test_exp_tampered_public_keys_y1() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;
        let mut prover = ExpProver { params: &params, ctx: BigNumContext::new()? };
        let mut verifier = ExpVerifier { params: &params, ctx: BigNumContext::new()? };

        let x = prover.random()?;
        let ExpProverPublicKeys { mut y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ExpProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ExpProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with y1
        y1.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with tampered public keys");

        Ok(())
    }

    #[test]
    fn test_exp_tampered_public_keys_y2() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;
        let mut prover = ExpProver { params: &params, ctx: BigNumContext::new()? };
        let mut verifier = ExpVerifier { params: &params, ctx: BigNumContext::new()? };

        let x = prover.random()?;
        let ExpProverPublicKeys { y1, mut y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ExpProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ExpProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with y1
        y2.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with tampered public keys");

        Ok(())
    }

    #[test]
    fn test_exp_incorrect_commitment_r1() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;
        let mut prover = ExpProver { params: &params, ctx: BigNumContext::new()? };
        let mut verifier = ExpVerifier { params: &params, ctx: BigNumContext::new()? };

        let x = prover.random()?;
        let ExpProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ExpProverCommit { mut r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ExpProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with r1
        r1.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect commitment");

        Ok(())
    }

    #[test]
    fn test_exp_incorrect_commitment_r2() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;
        let mut prover = ExpProver { params: &params, ctx: BigNumContext::new()? };
        let mut verifier = ExpVerifier { params: &params, ctx: BigNumContext::new()? };

        let x = prover.random()?;
        let ExpProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ExpProverCommit { r1, mut r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ExpProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with r1
        r2.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect commitment");

        Ok(())
    }

    #[test]
    fn test_exp_incorrect_challenge_response() -> Result<(), ErrorStack> {
        let params = generate_params(256)?;
        let mut prover = ExpProver { params: &params, ctx: BigNumContext::new()? };
        let mut verifier = ExpVerifier { params: &params, ctx: BigNumContext::new()? };

        let x = prover.random()?;
        let ExpProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ExpProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ExpProverChallengeReponse { mut s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with s
        s.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect challenge response");

        Ok(())
    }

    #[test]
    fn test_exp_mismatched_parameters() -> Result<(), ErrorStack> {
        let params1 = generate_params(256)?;
        let params2 = generate_params(256)?;
        let mut prover = ExpProver { params: &params1, ctx: BigNumContext::new()? };
        let mut verifier = ExpVerifier { params: &params2, ctx: BigNumContext::new()? }; // Different params

        let x = prover.random()?;
        let ExpProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ExpProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ExpProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with mismatched parameters");

        Ok(())
    }
}
