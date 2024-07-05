pub mod params;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests {
    use openssl::error::ErrorStack;

    use crate::{
        dl::{params::DlParams, prover::DlProver, verifier::DlVerifier},
        prover::{Prover, ProverChallengeResponse, ProverCommit, ProverPublicKeys},
        verifier::Verifier,
    };

    #[test]
    fn test_dl_chaum_pedersen_protocol() -> Result<(), ErrorStack> {
        let params = DlParams::new(256)?;
        let mut prover = DlProver::new(&params)?;
        let mut verifier = DlVerifier::new(&params)?;

        // DlProver's secret
        let x = prover.random()?;

        // DlProver's public keys
        let ProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;

        // DlProver's commitment
        let k = prover.random()?;
        let ProverCommit { r1, r2 } = prover.commit(&k)?;

        // DlVerifier's challenge
        let c = verifier.random()?;

        // DlProver's challenge response
        let ProverChallengeResponse { s } = prover.challenge_response(&k, &c, &x)?;

        // DlVerifier's check
        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;

        assert!(valid, "Chaum-Pedersen protocol verification failed");

        // let g_bytes = params.g.to_vec();
        // let h_bytes = params.h.to_vec();
        // let p_bytes = params.p.to_vec();

        // println!("p: {:?}, g: {:?}, h: {:?}", p_bytes, g_bytes, h_bytes);

        Ok(())
    }

    #[test]
    fn test_dl_incorrect_prover_secret() -> Result<(), ErrorStack> {
        let params = DlParams::new(256)?;
        let mut prover = DlProver::new(&params)?;
        let mut verifier = DlVerifier::new(&params)?;

        let x = prover.random()?;
        let ProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;

        // Use an incorrect secret for the challenge response
        let incorrect_x = prover.random()?;
        let ProverChallengeResponse { s } = prover.challenge_response(&k, &c, &incorrect_x)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect secret");

        Ok(())
    }

    #[test]
    fn test_dl_tampered_public_keys_y1() -> Result<(), ErrorStack> {
        let params = DlParams::new(256)?;
        let mut prover = DlProver::new(&params)?;
        let mut verifier = DlVerifier::new(&params)?;

        let x = prover.random()?;
        let ProverPublicKeys { mut y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ProverChallengeResponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with y1
        y1.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with tampered public keys");

        Ok(())
    }

    #[test]
    fn test_dl_tampered_public_keys_y2() -> Result<(), ErrorStack> {
        let params = DlParams::new(256)?;
        let mut prover = DlProver::new(&params)?;
        let mut verifier = DlVerifier::new(&params)?;

        let x = prover.random()?;
        let ProverPublicKeys { y1, mut y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ProverChallengeResponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with y1
        y2.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with tampered public keys");

        Ok(())
    }

    #[test]
    fn test_dl_incorrect_commitment_r1() -> Result<(), ErrorStack> {
        let params = DlParams::new(256)?;
        let mut prover = DlProver::new(&params)?;
        let mut verifier = DlVerifier::new(&params)?;

        let x = prover.random()?;
        let ProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ProverCommit { mut r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ProverChallengeResponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with r1
        r1.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect commitment");

        Ok(())
    }

    #[test]
    fn test_dl_incorrect_commitment_r2() -> Result<(), ErrorStack> {
        let params = DlParams::new(256)?;
        let mut prover = DlProver::new(&params)?;
        let mut verifier = DlVerifier::new(&params)?;

        let x = prover.random()?;
        let ProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ProverCommit { r1, mut r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ProverChallengeResponse { s } = prover.challenge_response(&k, &c, &x)?;

        // Tamper with r1
        r2.add_word(1)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(!valid, "Verification should fail with incorrect commitment");

        Ok(())
    }

    #[test]
    fn test_dl_incorrect_challenge_response() -> Result<(), ErrorStack> {
        let params = DlParams::new(256)?;
        let mut prover = DlProver::new(&params)?;
        let mut verifier = DlVerifier::new(&params)?;

        let x = prover.random()?;
        let ProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ProverChallengeResponse { mut s } = prover.challenge_response(&k, &c, &x)?;

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
    fn test_dl_mismatched_parameters() -> Result<(), ErrorStack> {
        let params1 = DlParams::new(256)?;
        let params2 = DlParams::new(256)?;
        let mut prover = DlProver::new(&params1)?;
        let mut verifier = DlVerifier::new(&params2)?; // Different params

        let x = prover.random()?;
        let ProverPublicKeys { y1, y2 } = prover.public_keys(&x)?;
        let k = prover.random()?;
        let ProverCommit { r1, r2 } = prover.commit(&k)?;
        let c = verifier.random()?;
        let ProverChallengeResponse { s } = prover.challenge_response(&k, &c, &x)?;

        let valid = verifier.check(&y1, &y2, &r1, &r2, &c, &s)?;
        assert!(
            !valid,
            "Verification should fail with mismatched parameters"
        );

        Ok(())
    }
}
