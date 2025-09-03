// Domain separation for protocols/schemes
#[cfg(feature = "secp256k1")]
pub const ECDSA_TAG: u8 = 0x00;

#[cfg(feature = "ed25519")]
pub const ED25519_TAG: u8 = 0x01;

#[cfg(feature = "aleo-schnorr")]
pub const ALEO_SCHNORRR_TAG: u8 = 0x02;
