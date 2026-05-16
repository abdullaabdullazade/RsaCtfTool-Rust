/// Euler's factorization method. Matches Python's euler() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd, is_square};
use crate::key::PublicKey;

pub struct EulerAttack;

impl RsaAttack for EulerAttack {
    fn name(&self) -> &'static str { "euler" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let end = n.clone().sqrt();
        let mut a = Integer::new();
        let mut solutions: Vec<(Integer, Integer)> = Vec::new();
        let mut firstb = Integer::from(-1i32);

        while a < end {
            if abort.load(Ordering::Relaxed) { return None; }
            let val = n.clone() - a.clone() * &a;
            if let Some(b) = is_square(&val) {
                if a != firstb && b != firstb {
                    solutions.push((b.clone(), a.clone()));
                    firstb = b;
                    if solutions.len() == 2 { break; }
                }
            }
            a += 1u32;
        }

        if solutions.len() < 2 { return None; }

        let (a0, b0) = &solutions[0];
        let (a1, b1) = &solutions[1];

        // k = gcd(a0-a1, b1-b0)^2, etc.
        let k = {
            let g = gcd(&(a0.clone() - a1), &(b1.clone() - b0));
            g.clone() * g
        };
        let h = {
            let g = gcd(&(a0.clone() + a1), &(b1.clone() + b0));
            g.clone() * g
        };
        let m = {
            let g = gcd(&(a0.clone() + a1), &(b1.clone() - b0));
            g.clone() * g
        };
        let lev = {
            let g = gcd(&(a0.clone() - a1), &(b1.clone() + b0));
            g.clone() * g
        };

        let p = gcd(&(k.clone() + &h), n);
        let q = gcd(&(lev.clone() + &m), n);

        if p > 1 && q > 1 && p.clone() * &q == *n {
            log::debug!("[euler] found p={}, q={}", &p, &q);
            return make_result(p, q, &pub_key.e, n, cipher);
        }
        None
    }
}
