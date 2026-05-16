/// siqs attack: self-initializing quadratic sieve via external tools in Python version.
/// Rust port keeps this as a stub until native SIQS backend is added.

use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct SiqsAttack;

impl RsaAttack for SiqsAttack {
    fn name(&self) -> &'static str { "siqs" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn can_run(&self) -> bool { false }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
