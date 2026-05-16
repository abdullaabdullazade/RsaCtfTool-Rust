/// Lehmer's machine (fermat-based). Matches Python's lehmer_machine() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, is_square};
use crate::key::PublicKey;

pub struct LehmerAttack;

impl RsaAttack for LehmerAttack {
    fn name(&self) -> &'static str { "lehmer" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        if n.clone().modulo(&Integer::from(4u32)) == 2 { return None; }

        let mut y = Integer::from(1u32);
        let limit = Integer::from(1_000_000u32);

        while y < limit {
            if abort.load(Ordering::Relaxed) { return None; }
            let val = n.clone() + &y * &y;
            if let Some(x) = is_square(&val) {
                let p = x.clone() - &y;
                let q = x + &y;
                if p > 1 && q > 1 && p.clone() * &q == *n {
                    log::debug!("[lehmer] found p={}", &p);
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
            }
            y += 1u32;
        }
        None
    }
}
