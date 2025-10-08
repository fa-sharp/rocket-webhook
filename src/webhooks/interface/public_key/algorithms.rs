/// ECDSA P256 Algorithm
#[cfg(feature = "p256")]
pub mod p256 {
    use tokio_util::bytes::Bytes;

    use super::super::WebhookPublicKeyAlgorithm;

    pub struct EcdsaP256Asn1;
    impl WebhookPublicKeyAlgorithm for EcdsaP256Asn1 {
        fn verify(public_key: &Bytes, message: &[u8], signature: &[u8]) -> Result<(), String> {
            use p256::ecdsa::signature::Verifier;

            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
                .map_err(|e| format!("Public key is invalid: {e}"))?;
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|e| format!("Expected signature is invalid: {e}"))?;
            key.verify(message, &signature)
                .map_err(|e| format!("ECDSA P-256 verification failed: {e}"))
        }
    }
}

/// ED25519 Algorithm
#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use tokio_util::bytes::{Buf, Bytes};

    use super::super::WebhookPublicKeyAlgorithm;

    pub struct Ed25519;
    impl WebhookPublicKeyAlgorithm for Ed25519 {
        fn verify(public_key: &Bytes, message: &[u8], signature: &[u8]) -> Result<(), String> {
            let mut key = [0; 32];
            public_key
                .clone()
                .try_copy_to_slice(&mut key)
                .map_err(|e| format!("Public key is invalid: {e}"))?;
            let key = VerifyingKey::from_bytes(&key)
                .map_err(|e| format!("Public key is invalid: {e}"))?;
            let signature = Signature::from_slice(signature)
                .map_err(|e| format!("Expected signature is invalid: {e}"))?;
            key.verify(message, &signature)
                .map_err(|e| format!("Ed25519 verification failed: {e}"))
        }
    }
}
