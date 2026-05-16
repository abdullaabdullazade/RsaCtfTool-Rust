/// wolframalpha attack: API-backed factor lookup in Python version.
/// Rust port keeps this as an offline-safe stub for now.

use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct WolframAlphaAttack;

impl RsaAttack for WolframAlphaAttack {
    fn name(&self) -> &'static str { "wolframalpha" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn can_run(&self) -> bool { false }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
