/// pastctfprimes attack: data-driven prime lookup in Python version.
/// Rust port keeps this as a stub until bundled prime corpus is wired in.

use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct PastCtfPrimesAttack;

impl RsaAttack for PastCtfPrimesAttack {
    fn name(&self) -> &'static str { "pastctfprimes" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn can_run(&self) -> bool { false }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
