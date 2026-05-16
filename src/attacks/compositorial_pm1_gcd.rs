/// compositorial_pm1_gcd: GCD(compositorial ± 1, n).
/// Compositorial = product of composites with prime factors removed.
/// Matches Python's compositorial_pm1_gcd attack.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;
use crate::math::next_prime;

pub struct CompositorialPm1GcdAttack;

impl RsaAttack for CompositorialPm1GcdAttack {
    fn name(&self) -> &'static str { "compositorial_pm1_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let limit = 10_001u32;
        let mut f = Integer::from(1u32);
        let mut p = Integer::from(2u32);

        for x in 2u32..limit {
            if abort.load(Ordering::Relaxed) { return None; }
            f *= x;
            // Remove all factors of the current prime p from f
            while f.clone().modulo(&p) == 0 {
                f /= &p;
                p = next_prime(&p);
            }
            for val in [f.clone() - 1u32, f.clone() + 1u32] {
                let g = gcd(&val, n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    log::debug!("[compositorial_pm1_gcd] found factor at x={}", x);
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }
        }
        None
    }
}
