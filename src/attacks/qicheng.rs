use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct QichengAttack;

impl RsaAttack for QichengAttack {
    fn name(&self) -> &'static str { "qicheng" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn can_run(&self) -> bool { false }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
