use std::str::FromStr;

use crate::crypto_tools::message_digest::MessageDigest;
use crate::sdk::api::TofnFatal;
use rand::SeedableRng as _;
use snarkos_account::Account;
use snarkvm::prelude::ToFields;
use snarkvm::prelude::Field;
use snarkvm::prelude::{Network, PrivateKey, Signature};

use crate::{
    constants::ALEO_SCHNORRR_TAG,
    crypto_tools::rng,
    sdk::{
        api::{BytesVec, TofnResult},
        key::SecretRecoveryKey,
    },
};

#[derive(Debug)]
pub struct KeyPair<N: Network> {
    aleo_account: Account<N>,
}

impl<N: Network> KeyPair<N> {
    /// tofnd needs to store this in the kv store.
    pub fn signing_key(&self) -> &PrivateKey<N> {
        &self.aleo_account.private_key()
    }

    pub fn encoded_verifying_key(&self) -> String {
        self.aleo_account.address().to_string()
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

    let private_key = PrivateKey::new(&mut rng).map_err(|_| TofnFatal)?;
    let aleo_account = Account::try_from(private_key).map_err(|_| TofnFatal)?;

    Ok(KeyPair { aleo_account })
}

pub fn sign<N: Network>(
    signing_key: &KeyPair<N>,
    msg_to_sign: &MessageDigest,
) -> TofnResult<BytesVec> {
    let message = aleo_encoded(msg_to_sign).map_err(|_| TofnFatal)?;

    let sign = signing_key
        .aleo_account
        .sign(&message, &mut rand_chacha::ChaChaRng::from_entropy())
        .map_err(|_| TofnFatal)?;

    Ok(sign.to_string().as_bytes().to_vec())
}

pub fn verify<N: Network>(
    address: &str,
    signature: &Signature<N>,
    message: &MessageDigest,
) -> TofnResult<bool> {
    use snarkvm::prelude::Address;

    let message = aleo_encoded(message).map_err(|_| TofnFatal)?;

    let address = Address::from_str(address).map_err(|_| TofnFatal)?;

    Ok(signature.verify(&address, &message))
}

fn aleo_encoded<N: Network>(data: &MessageDigest) -> TofnResult<Vec<Field<N>>> {
    let num = cosmwasm_std::Uint256::from_le_bytes(data.0);
    let message = format!("{num}group");

    snarkvm::prelude::Value::from_str(message.as_str())
        .map_err(|_| TofnFatal)?
        .to_fields()
        .map_err(|_| TofnFatal)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::sdk::{
        api::MessageDigest,
        key::{dummy_secret_recovery_key, SecretRecoveryKey},
    };

    pub type CurrentNetwork = snarkvm::prelude::TestnetV0;

    #[test]
    fn keygen_sign_decode_verify() {
        let message = [30, 165, 51, 99, 240, 22, 44, 209, 224, 46, 25, 4, 49, 49, 114, 238, 209, 48, 186, 136, 95, 224, 128, 254, 19, 109, 54, 40, 214, 206, 187, 13].into();

        let key_pair = keygen::<CurrentNetwork>(&dummy_secret_recovery_key(42), b"tofn nonce")
            .map_err(|_| TofnFatal)
            .unwrap();
        let encoded_signature = sign(&key_pair, &message).map_err(|_| TofnFatal).unwrap();
        let signature = Signature::<CurrentNetwork>::from_str(
            &String::from_utf8(encoded_signature)
                .map_err(|_| TofnFatal)
                .unwrap(),
        )
        .map_err(|_| TofnFatal)
        .unwrap();
        let success = verify(
            key_pair.encoded_verifying_key().as_str(),
            &signature,
            &message,
        )
        .map_err(|_| TofnFatal)
        .unwrap();

        assert!(success);
    }

    /// Check keygen/signing outputs against golden files to catch regressions (such as on updating deps).
    /// Golden files were generated from tofn commit corresponding to tofnd v0.10.1 release
    #[test]
    fn keygen_sign_known_vectors() {
        // todo!()
        // struct TestCase {
        //     secret_recovery_key: SecretRecoveryKey,
        //     session_nonce: Vec<u8>,
        //     message_digest: [u8; 32],
        // }
        //
        // let test_cases = vec![
        //     TestCase {
        //         secret_recovery_key: SecretRecoveryKey([0; 64]),
        //         session_nonce: vec![0; 4],
        //         message_digest: [42; 32],
        //     },
        //     TestCase {
        //         secret_recovery_key: SecretRecoveryKey([0xff; 64]),
        //         session_nonce: vec![0xff; 32],
        //         message_digest: [0xff; 32],
        //     },
        // ];
        //
        // let expected_outputs: Vec<Vec<_>> = test_cases
        //     .into_iter()
        //     .map(|test_case| {
        //         let keypair =
        //             keygen(&test_case.secret_recovery_key, &test_case.session_nonce).map_err(|_| TofnFatal)?;
        //         let encoded_signing_key = keypair.signing_key().as_ref().to_bytes().to_vec();
        //         let encoded_verifying_key = keypair.encoded_verifying_key().to_vec();
        //
        //         let signature: Vec<u8> =
        //             sign(keypair.signing_key(), &test_case.message_digest.into()).map_err(|_| TofnFatal)?;
        //
        //         let success = verify(
        //             &keypair.encoded_verifying_key(),
        //             &test_case.message_digest.into(),
        //             &signature,
        //         )
        //         .map_err(|_| TofnFatal)?;
        //         assert!(success);
        //
        //         [encoded_signing_key, encoded_verifying_key, signature]
        //             .into_iter()
        //             .map(hex::encode)
        //             .collect()
        //     })
        //     .collect();
        //
        // goldie::assert_json!(expected_outputs);
    }
}
