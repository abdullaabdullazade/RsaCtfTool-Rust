/// Pollard-Strassen O(n^(1/4)) factoring. Matches Python's pollard_strassen() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct PollardStrassenAttack;

impl RsaAttack for PollardStrassenAttack {
    fn name(&self) -> &'static str { "pollard_strassen" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        // Simplified Pollard-Strassen using baby-step giant-step approach
        // Matches the Python implementation's batch GCD method
        let n4 = {
            let (root, _) = crate::math::iroot(n, 4);
            root
        };

        let limit = n4.to_u64().unwrap_or(1_000_000).min(1_000_000);
        let step = (limit as f64).sqrt() as u64 + 1;

        let mut j = 1u64;
        while j <= limit {
            if abort.load(Ordering::Relaxed) { return None; }

            // Compute product of (j*step + i) for i=0..step
            let mut prod = Integer::from(1u32);
            for i in 0..step {
                let val = Integer::from(j * step + i);
                prod = (prod * &val).modulo(n);
            }

            let g = gcd(&prod, n);
            if g > 1 && g < *n {
                // Narrow down to exact factor
                for i in 0..step {
                    if abort.load(Ordering::Relaxed) { return None; }
                    let val = Integer::from(j * step + i);
                    let g2 = gcd(&val, n);
                    if g2 > 1 && g2 < *n {
                        let q = n.clone() / &g2;
                        log::debug!("[pollard_strassen] found factor={}", &g2);
                        return make_result(g2, q, &pub_key.e, n, cipher);
                    }
                }
                // If narrowing failed, use g directly
                let q = n.clone() / &g;
                log::debug!("[pollard_strassen] found factor={}", &g);
                return make_result(g, q, &pub_key.e, n, cipher);
            }

            j += 1;
        }
        None
    }
}
