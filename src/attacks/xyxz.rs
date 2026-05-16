/// XYXZ attack: factors N when N = base^y * base^z form. Matches Python's factor_XYXZ().

use rug::{Integer, ops::Pow};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;
use crate::math::ilogb;

pub struct XyxzAttack;

fn factor_xyxz(n: &Integer, base: u32) -> Option<(Integer, Integer)> {
    let mut power = 1u32;
    let base_int = Integer::from(base);
    let logn_base = ilogb(n, base as u64);
    let max_power = (logn_base / 2) + 1;

    while power <= max_power {
        let candidate = {
            let bp = base_int.clone().pow(power);
            next_prime_above(&bp)
        };
        if n.clone().modulo(&candidate) == 0 {
            let q = n.clone() / &candidate;
            return Some((candidate, q));
        }
        power += 1;
    }
    None
}

fn next_prime_above(n: &Integer) -> Integer {
    crate::math::next_prime(n)
}

impl RsaAttack for XyxzAttack {
    fn name(&self) -> &'static str { "XYXZ" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        for base in [2u32, 3, 5, 7, 11, 13, 17] {
            if abort.load(Ordering::Relaxed) { return None; }
            if let Some((p, q)) = factor_xyxz(n, base) {
                log::debug!("[XYXZ] base={}, found p={}", base, &p);
                return make_result(p, q, &pub_key.e, n, cipher);
            }
        }
        None
    }
}
