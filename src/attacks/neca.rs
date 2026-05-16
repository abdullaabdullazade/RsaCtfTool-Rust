/// neca attack: external NECA/Sage-based attack in Python version.
/// Rust port keeps this as a stub pending native implementation.

use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct NecaAttack;

impl RsaAttack for NecaAttack {
    fn name(&self) -> &'static str { "neca" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn can_run(&self) -> bool { false }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
