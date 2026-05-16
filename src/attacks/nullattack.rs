/// nullattack: does nothing, returns None. Used as a no-op placeholder.
/// Matches Python's nullattack (speed: medium).

use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct NullAttack;

impl RsaAttack for NullAttack {
    fn name(&self) -> &'static str { "nullattack" }
    fn speed(&self) -> Speed { Speed::Medium }
    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
