use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct Rapid7PrimesAttack;

impl RsaAttack for Rapid7PrimesAttack {
    fn name(&self) -> &'static str { "rapid7primes" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn can_run(&self) -> bool { false }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
