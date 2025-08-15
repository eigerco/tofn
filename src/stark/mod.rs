use starknet_crypto::{
    get_public_key, rfc6979_generate_k, sign as stark_sign, verify as stark_verify, Felt,
};
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    constants::STARK_TAG,
    crypto_tools::{message_digest::MessageDigest, rng},
    sdk::{
        api::{BytesVec, TofnFatal, TofnResult},
        key::SecretRecoveryKey,
    },
};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct SecretKey {
    inner: [u8; 32],
}

impl SecretKey {
    fn from_felt(felt: Felt) -> Self {
        Self {
            inner: felt.to_bytes_be(),
        }
    }

    fn to_felt(&self) -> Felt {
        Felt::from_bytes_be(&self.inner)
    }
}

#[derive(Debug)]
pub struct KeyPair {
    signing_key: SecretKey,
    encoded_verifying_key: [u8; 32], // Felt encoded as 32 bytes
}

impl KeyPair {
    /// Felt encoded public key (32 bytes).
    /// tofnd needs to return this to axelar-core.
    pub fn encoded_verifying_key(&self) -> &[u8; 32] {
        &self.encoded_verifying_key
    }

    /// tofnd needs to store this in the kv store.
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.inner
    }

    /// Create from stored signing key bytes
    pub fn from_signing_key_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SecretKey { inner: *bytes };
        let private_key = signing_key.to_felt();
        let public_key = get_public_key(&private_key);

        Self {
            signing_key,
            encoded_verifying_key: public_key.to_bytes_be(),
        }
    }
}

pub fn keygen(
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeyPair> {
    let mut rng =
        rng::rng_seed_signing_key(STARK_TAG, KEYGEN_TAG, secret_recovery_key, session_nonce)?;

    // Generate a random 32-byte seed and convert to Felt
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rng.fill_bytes(&mut seed);

    // Convert to Felt, ensuring it's within the field range
    let private_key = Felt::from_bytes_be_slice(&seed);
    let public_key = get_public_key(&private_key);

    Ok(KeyPair {
        signing_key: SecretKey::from_felt(private_key),
        encoded_verifying_key: public_key.to_bytes_be(),
    })
}

/// Returns an extended STARK signature with r, s, and v components.
pub fn sign(signing_key_bytes: &[u8; 32], message_digest: &MessageDigest) -> TofnResult<BytesVec> {
    let signing_key = SecretKey {
        inner: *signing_key_bytes,
    };
    let private_key = signing_key.to_felt();
    let message_hash = Felt::from_bytes_be_slice(message_digest.as_ref());

    // Generate deterministic k
    let domain_seed =
        rng::rng_seed_stark_ephemeral_k(STARK_TAG, SIGN_TAG, &private_key, &message_hash)?;
    let k = rfc6979_generate_k(&message_hash, &private_key, Some(&domain_seed));

    let signature = stark_sign(&private_key, &message_hash, &k).map_err(|e| {
        error!("failure to sign: {:?}", e);
        TofnFatal
    })?;

    let mut packed_sig = Vec::with_capacity(96);
    packed_sig.extend_from_slice(&signature.r.to_bytes_be());
    packed_sig.extend_from_slice(&signature.s.to_bytes_be());
    packed_sig.extend_from_slice(&signature.v.to_bytes_be());

    Ok(packed_sig)
}

pub fn verify(
    encoded_verifying_key: &[u8; 32],
    message_digest: &MessageDigest,
    encoded_signature: &[u8],
) -> TofnResult<bool> {
    if encoded_signature.len() != 96 {
        error!(
            "Invalid signature length: expected 96, got {}",
            encoded_signature.len()
        );
        return Err(TofnFatal);
    }

    let public_key = Felt::from_bytes_be_slice(encoded_verifying_key);
    let message_hash = Felt::from_bytes_be_slice(message_digest.as_ref());

    let r = Felt::from_bytes_be_slice(&encoded_signature[0..32]);
    let s = Felt::from_bytes_be_slice(&encoded_signature[32..64]);

    Ok(
        stark_verify(&public_key, &message_hash, &r, &s).map_err(|e| {
            error!("failure to verify: {:?}", e);
            TofnFatal
        })?,
    )
}

/// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;
const SIGN_TAG: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::{keygen, sign, verify};
    use crate::sdk::key::{dummy_secret_recovery_key, SecretRecoveryKey};

    #[test]
    fn keygen_sign_decode_verify() {
        let message_digest = [42; 32].into();

        let key_pair = keygen(&dummy_secret_recovery_key(42), b"tofn nonce").unwrap();
        let encoded_signature = sign(&key_pair.signing_key_bytes(), &message_digest).unwrap();
        let success = verify(
            key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(success);
    }

    /// Check keygen/signing outputs against golden files to catch regressions (such as on updating deps).
    #[test]
    fn keygen_sign_known_vectors() {
        struct TestCase {
            secret_recovery_key: SecretRecoveryKey,
            session_nonce: Vec<u8>,
            message_digest: [u8; 32],
        }

        let test_cases = vec![
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0; 64]),
                session_nonce: vec![0; 4],
                message_digest: [42; 32],
            },
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0xff; 64]),
                session_nonce: vec![0xff; 32],
                message_digest: [0xff; 32],
            },
        ];

        let expected_outputs: Vec<Vec<_>> = test_cases
            .into_iter()
            .map(|test_case| {
                let keypair =
                    keygen(&test_case.secret_recovery_key, &test_case.session_nonce).unwrap();
                let encoded_signing_key = keypair.signing_key_bytes().to_vec();
                let encoded_verifying_key = keypair.encoded_verifying_key().to_vec();

                let signature: Vec<u8> = sign(
                    &keypair.signing_key_bytes(),
                    &test_case.message_digest.into(),
                )
                .unwrap();

                let success = verify(
                    keypair.encoded_verifying_key(),
                    &test_case.message_digest.into(),
                    &signature,
                )
                .unwrap();
                assert!(success);

                [encoded_signing_key, encoded_verifying_key, signature]
                    .into_iter()
                    .map(hex::encode)
                    .collect()
            })
            .collect();

        goldie::assert_json!(expected_outputs);
    }
}
