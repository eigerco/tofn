use crate::crypto_tools::message_digest::MessageDigest;
use crate::sdk::api::TofnFatal;
use rand::SeedableRng as _;
use snarkos_account::Account;
use snarkvm::prelude::{Address, FromBytes, Network, PrivateKey, Signature, SizeInBytes, ToBytes};
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

#[derive(Debug)]
pub struct KeyPair<N: Network> {
    aleo_account: Account<N>,
}

impl<N: Network> KeyPair<N> {
    /// tofnd needs to store this in the kv store.
    pub fn signing_key(&self) -> &PrivateKey<N> {
        &self.aleo_account.private_key()
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

        self.aleo_account
            .address()
            .to_bytes_le()
            .map_err(|_| {
                error!("Failed to encode Aleo address.");
                TofnFatal
            })?
            .try_into()
            .map_err(|_| {
                error!("Failed to convert Aleo address to bytes.");
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

    let private_key = PrivateKey::new(&mut rng).map_err(|_| {
        error!("Keygen failure to generate Aleo private key.");
        TofnFatal
    })?;
    let aleo_account = Account::try_from(private_key).map_err(|_| {
        error!("Keygen failure to generate Aleo account.");
        TofnFatal
    })?;

    Ok(KeyPair { aleo_account })
}

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

pub fn sign_with_rng<N: Network, R: rand::Rng + rand::CryptoRng>(
    signing_key: &KeyPair<N>,
    msg_to_sign: &MessageDigest,
    rng: &mut R,
) -> TofnResult<BytesVec> {
    signing_key
        .aleo_account
        .sign_bytes(msg_to_sign.as_ref(), rng)
        .and_then(|signature| signature.to_bytes_le())
        .map_err(|_| {
            error!("Failed to sign message and convert to bytes");
            TofnFatal
        })
}

pub fn verify<N: Network>(
    address: &[u8],
    message: &MessageDigest,
    signature: &Signature<N>,
) -> TofnResult<bool> {
    let address = Address::from_bytes_le(&address).map_err(|_| {
        error!("Failed to create Aleo address. Failed to verify signature.");
        TofnFatal
    })?;

    Ok(signature.verify_bytes(&address, message.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub type CurrentNetwork = snarkvm::prelude::TestnetV0;

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
