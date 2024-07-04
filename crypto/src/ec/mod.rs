pub mod params;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcPoint},
        error::ErrorStack,
    };

    use crate::ec::{
        params::generate_params,
        prover::{EcProver, EcProverChallengeReponse, EcProverCommit, EcProverPublicKeys},
        verifier::EcVerifier,
    };

    #[test]
    fn test_ec_chaum_pedersen_protocol() -> Result<(), ErrorStack> {
        let params = generate_params()?;
        let mut prover = EcProver {
            params: &params,
            ctx: BigNumContext::new().unwrap(),
        };
        let mut verifier = EcVerifier {
            params: &params,
            ctx: BigNumContext::new().unwrap(),
        };

        // Prover's secret
        let x = prover.random()?;

        // Prover's public keys
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;

        // Prover's commitment
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;

        // Verifier's challenge
        let c = verifier.random()?;

        // Prover's challenge response
        let EcProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Verifier's check
        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;

        assert!(valid, "Ec Chaum-Pedersen protocol verification failed");

        Ok(())
    }

    fn tamper_point(
        point: &EcPoint,
        group: &EcGroup,
        ctx: &mut BigNumContext,
    ) -> Result<EcPoint, ErrorStack> {
        let mut tampered = EcPoint::new(group)?;
        tampered.add(group, point, &group.generator(), ctx)?;
        Ok(tampered)
    }

    #[test]
    fn test_ec_incorrect_prover_secret() -> Result<(), ErrorStack> {
        let params = generate_params()?;
        let mut prover = EcProver {
            params: &params,
            ctx: BigNumContext::new()?,
        };
        let mut verifier = EcVerifier {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        let x = prover.random()?;
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;

        // Use an incorrect secret for the challenge response
        let incorrect_x = prover.random()?;
        let EcProverChallengeReponse { s } = prover.challenge_response(&k, &c, &incorrect_x)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect secret");

        Ok(())
    }

    #[test]
    fn test_ec_tampered_public_keys_y1() -> Result<(), ErrorStack> {
        let params = generate_params()?;
        let mut prover = EcProver {
            params: &params,
            ctx: BigNumContext::new()?,
        };
        let mut verifier = EcVerifier {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        let x = prover.random()?;
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let EcProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with y1
        let tampered_y1 = tamper_point(&y1, &params.group, &mut prover.ctx)?;

        let valid = verifier.check(&tampered_y1, &y2, &r1, &r2, &c, &s)?;
        assert!(
            !valid,
            "Verification should fail with tampered public key y1"
        );

        Ok(())
    }

    #[test]
    fn test_ec_tampered_public_keys_y2() -> Result<(), ErrorStack> {
        let params = generate_params()?;
        let mut prover = EcProver {
            params: &params,
            ctx: BigNumContext::new()?,
        };
        let mut verifier = EcVerifier {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        let x = prover.random()?;
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let EcProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with y2
        let tampered_y2 = tamper_point(&y2, &params.group, &mut prover.ctx)?;

        let valid = verifier.check(&y1, &tampered_y2, &r1, &r2, &c, &s)?;
        assert!(
            !valid,
            "Verification should fail with tampered public key y2"
        );

        Ok(())
    }

    #[test]
    fn test_ec_incorrect_commitment_r1() -> Result<(), ErrorStack> {
        let params = generate_params()?;
        let mut prover = EcProver {
            params: &params,
            ctx: BigNumContext::new()?,
        };
        let mut verifier = EcVerifier {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        let x = prover.random()?;
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let EcProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with r1
        let tampered_r1 = tamper_point(&r1, &params.group, &mut prover.ctx)?;

        let valid = verifier.check(&y1, &y2, &tampered_r1, &r2, &c, &s)?;
        assert!(
            !valid,
            "Verification should fail with incorrect commitment r1"
        );

        Ok(())
    }

    #[test]
    fn test_ec_incorrect_commitment_r2() -> Result<(), ErrorStack> {
        let params = generate_params()?;
        let mut prover = EcProver {
            params: &params,
            ctx: BigNumContext::new()?,
        };
        let mut verifier = EcVerifier {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        let x = prover.random()?;
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let EcProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with r2
        let tampered_r2 = tamper_point(&r2, &params.group, &mut prover.ctx)?;

        let valid = verifier.check(&y1, &y2, &r1, &tampered_r2, &c, &s)?;
        assert!(
            !valid,
            "Verification should fail with incorrect commitment r2"
        );

        Ok(())
    }

    #[test]
    fn test_ec_incorrect_challenge_response() -> Result<(), ErrorStack> {
        let params = generate_params()?;
        let mut prover = EcProver {
            params: &params,
            ctx: BigNumContext::new()?,
        };
        let mut verifier = EcVerifier {
            params: &params,
            ctx: BigNumContext::new()?,
        };

        let x = prover.random()?;
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let EcProverChallengeReponse { mut s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with s
        s.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(
            !valid,
            "Verification should fail with incorrect challenge response"
        );

        Ok(())
    }

    #[test]
    fn test_ec_mismatched_parameters() -> Result<(), ErrorStack> {
        let params1 = generate_params()?;
        let params2 = generate_params()?;
        let mut prover = EcProver {
            params: &params1,
            ctx: BigNumContext::new()?,
        };
        let mut verifier = EcVerifier {
            params: &params2,
            ctx: BigNumContext::new()?,
        }; // Different params

        let x = prover.random()?;
        let EcProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let EcProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let EcProverChallengeReponse { s } = prover.challenge_response(&k, &c, &x)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(
            !valid,
            "Verification should fail with mismatched parameters"
        );

        Ok(())
    }
}
