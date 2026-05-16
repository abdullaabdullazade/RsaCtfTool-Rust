/// partial_q attack: recover p and q from partial CRT private key components.
/// Python source: https://0day.work/0ctf-2016-quals-writeups/
/// Only applicable when --partial key components (dp, dq, qinv, partial_q) are known.

use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct PartialQAttack;

impl RsaAttack for PartialQAttack {
    fn name(&self) -> &'static str { "partial_q" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        // This attack requires partial private key components (dp, dq, qi, partial_q)
        // which are not exposed in the current PublicKey struct.
        // The full implementation is in PrivateKey partial-mode parsing (--partial flag).
        log::debug!("[partial_q] requires --partial private key components");
        None
    }
}
