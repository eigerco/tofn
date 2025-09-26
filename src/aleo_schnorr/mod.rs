//! # Aleo Schnorr Signature Module
//!
//! This module provides Schnorr signatures specifically designed for compatibility with
//! Leo programs and the Aleo blockchain's zero-knowledge proof system.
//!
//! ## Leo Program Compatibility
//!
//! The core design follows Aleo's data transformation requirements:
//! **Raw Bytes (32) → Group<N> → Value<N> → Fields → Signature**
//!
//! ### Why This Transformation Chain?
//!
//! 1. **Group Elements**: At Leo programs we use `hash_to_group()` which produces Group<N> elements.
//!    Both Groups and MessageDigests are exactly 32 bytes, enabling direct conversion.
//!    This ensures `msg_to_sign` work with Leo's native hashing operations.
//!
//! 2. **Value<N> Wrapper**: Leo's type system requires all data as Value<N>.
//!
//! 3. **Field Serialization**: snarkVM provides signatures over field elements.
//!
//! This transformation ensures signatures generated here can be directly verified
//! in Leo programs.
//!
//! ## Example Leo Integration
//!
//! ```leo
//! program verify_signature.aleo {
//!     transition verify(message: group, signature: signature, addr: address) -> bool {
//!         return signature.verify(addr, message);
//!     }
//! }
//! ```

use crate::crypto_tools::message_digest::MessageDigest;
use crate::sdk::api::TofnFatal;
use rand::SeedableRng as _;
use snarkos_account::Account;
use snarkvm_console::account::{PrivateKey, Signature};
use snarkvm_console::prelude::{FromBytes, Network, SizeInBytes, ToBytes, ToFields};
use snarkvm_console::program::{Literal, Value};
use snarkvm_console::types::{Address, Field, Group};

use tracing::error;

use crate::{
    constants::ALEO_SCHNORRR_TAG,
    crypto_tools::rng,
    sdk::{
        api::{BytesVec, TofnResult},
        key::SecretRecoveryKey,
    },
};

/// Length of the Aleo address in bytes
const PUBLIC_KEY_LENGTH: usize = 32;

/// Aleo key pair wrapper around SnarkVM's Account type.
#[derive(Debug)]
pub struct KeyPair<N: Network> {
    aleo_account: Account<N>,
}

impl<N: Network> KeyPair<N> {
    /// Returns the private key for signing operations.
    /// Should be stored securely in tofnd's key-value store.
    pub fn signing_key(&self) -> &PrivateKey<N> {
        self.aleo_account.private_key()
    }

    pub fn encoded_verifying_key(&self) -> TofnResult<[u8; PUBLIC_KEY_LENGTH]> {
        if PUBLIC_KEY_LENGTH != Address::<N>::size_in_bytes() {
            error!(
                "Public key length mismatch: expected {}, got {}",
                PUBLIC_KEY_LENGTH,
                Address::<N>::size_in_bytes()
            );
            return Err(TofnFatal);
        }

        let bytes = self.aleo_account.address().to_bytes_le().map_err(|_| {
            error!("Failed to encode Aleo address");
            TofnFatal
        })?;

        bytes.try_into().map_err(|_| {
            error!("Failed to convert address to byte array");
            TofnFatal
        })
    }
}

pub fn keygen<N: Network>(
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeyPair<N>> {
    /// Domain separation for seeding the RNG
    const KEYGEN_TAG: u8 = 0x00;

    let mut rng = rng::rng_seed_signing_key(
        ALEO_SCHNORRR_TAG,
        KEYGEN_TAG,
        secret_recovery_key,
        session_nonce,
    )?;

    let aleo_account = PrivateKey::new(&mut rng)
        .and_then(Account::try_from)
        .map_err(|_| {
            error!("Keygen failure to generate Aleo account.");
            TofnFatal
        })?;

    Ok(KeyPair { aleo_account })
}

/// Signs a message using system entropy for nonce generation.
///
/// Follows the Leo-compatible transformation: bytes → Group → Value → Fields → Signature.
pub fn sign<N: Network>(
    signing_key: &KeyPair<N>,
    msg_to_sign: &MessageDigest,
) -> TofnResult<BytesVec> {
    sign_with_rng(
        signing_key,
        msg_to_sign,
        &mut rand_chacha::ChaChaRng::from_entropy(),
    )
}

/// Signs a message with provided RNG for deterministic signatures (useful for testing).
///
/// Performs the Leo-compatible transformation chain:
/// 1. MessageDigest (32 bytes) → Group<N> (32 bytes) - direct conversion
/// 2. Group → Literal::Group - wrap in Leo's type system
/// 3. Literal → Value<N> - Leo's unified data representation
/// 4. Value → Fields
/// 5. Sign field elements - generate final signature
pub fn sign_with_rng<N: Network, R: rand::Rng + rand::CryptoRng>(
    signing_key: &KeyPair<N>,
    msg_to_sign: &MessageDigest,
    rng: &mut R,
) -> TofnResult<BytesVec> {
    let msg_fields = msg_to_fields::<N>(msg_to_sign)?;

    signing_key
        .aleo_account
        .sign(&msg_fields, rng)
        .and_then(|signature| signature.to_bytes_le())
        .map_err(|_| {
            error!("Failed to sign message and convert to bytes");
            TofnFatal
        })
}

/// Verifies a signature by applying the same transformation chain as signing.
///
/// Ensures compatibility with Leo program verification by using identical
/// bytes → Group → Value → Fields conversion.
pub fn verify<N: Network>(
    address: &[u8],
    message: &MessageDigest,
    signature: &Signature<N>,
) -> TofnResult<bool> {
    let address = Address::from_bytes_le(&address).map_err(|_| {
        error!("Failed to create Aleo address. Failed to verify signature.");
        TofnFatal
    })?;

    let msg_fields = msg_to_fields::<N>(message)?;
    Ok(signature.verify(&address, &msg_fields))
}

fn msg_to_fields<N: Network>(msg: &MessageDigest) -> TofnResult<Vec<Field<N>>> {
    let group_value = Group::from_bytes_le(msg.as_ref()).map_err(|_| {
        error!("Failed to create Aleo group value for msg.");
        TofnFatal
    })?;

    let value = Value::from(Literal::Group(group_value));
    value.to_fields().map_err(|_| {
        error!("Failed to convert Aleo group value to fields.");
        TofnFatal
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub type CurrentNetwork = snarkvm_console::network::TestnetV0;

    pub fn dummy_keygen<N: Network>() -> TofnResult<KeyPair<N>> {
        keygen::<N>(
            &crate::sdk::key::dummy_secret_recovery_key(42),
            b"tofn nonce",
        )
        .map_err(|_| TofnFatal)
    }

    #[test]
    fn keygen_sign_decode_verify() {
        let message = [
            30, 165, 51, 99, 240, 22, 44, 209, 224, 46, 25, 4, 49, 49, 114, 238, 209, 48, 186, 136,
            95, 224, 128, 254, 19, 109, 54, 40, 214, 206, 187, 13,
        ]
        .into();

        let key_pair: KeyPair<CurrentNetwork> =
            dummy_keygen().expect("Failed to generate key pair");
        let encoded_signature = sign(&key_pair, &message).expect("Failed to sign message");
        let signature = Signature::<CurrentNetwork>::from_bytes_le(&encoded_signature)
            .expect("Failed to decode signature");
        let success = verify(
            &key_pair
                .encoded_verifying_key()
                .expect("Failed to encode verifying key"),
            &message,
            &signature,
        )
        .expect("Failed to verify signature");

        assert!(success);
    }

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
                message_digest: [
                    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            },
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0xff; 64]),
                session_nonce: vec![0xff; 32],
                message_digest: [
                    112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            },
        ];

        let expected_outputs: Vec<Vec<_>> = test_cases
            .into_iter()
            .enumerate()
            .map(|(i, test_case)| {
                let keypair = keygen::<CurrentNetwork>(
                    &test_case.secret_recovery_key,
                    &test_case.session_nonce,
                )
                .unwrap();
                let encoded_signing_key = keypair.signing_key().to_bytes_le().unwrap();
                let encoded_verifying_key = keypair.encoded_verifying_key().unwrap().to_vec();
                let mut rng = rand_chacha::ChaChaRng::seed_from_u64(i as u64);
                let signature: Vec<u8> =
                    sign_with_rng(&keypair, &test_case.message_digest.into(), &mut rng).unwrap();

                let success = verify(
                    &keypair
                        .encoded_verifying_key()
                        .expect("Failed to encode verifying key"),
                    &test_case.message_digest.into(),
                    &Signature::<CurrentNetwork>::from_bytes_le(&signature)
                        .expect("Failed to decode signature"),
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
