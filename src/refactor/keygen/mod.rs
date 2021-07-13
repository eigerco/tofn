mod api;
mod r1;
mod r2;
mod r3;
mod r4;
mod rng;
pub use api::*;

#[cfg(test)]
pub(super) mod tests; // pub(super) so that sign module can see tests::execute_keygen

#[cfg(feature = "malicious")]
pub mod malicious;