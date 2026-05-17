use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct PartialQAttack;

impl RsaAttack for PartialQAttack {
    fn name(&self) -> &'static str { "partial_q" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        log::debug!("[partial_q] requires --partial private key components");
        None
    }
}
