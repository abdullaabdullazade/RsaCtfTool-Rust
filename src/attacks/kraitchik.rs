/// Kraitchik's factorization. Matches Python's kraitchik() in algos.py.

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd, is_square};
use crate::key::PublicKey;

pub struct KraitchikAttack;

impl RsaAttack for KraitchikAttack {
    fn name(&self) -> &'static str { "kraitchik" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let mut x = n.clone().sqrt();
        let limit = x.clone() + 1_000_000u32;

        while x < limit {
            if abort.load(Ordering::Relaxed) { return None; }
            let x2 = x.clone() * &x;
            let mut y2 = x2 - n;
            while y2 >= 0 {
                if let Some(y) = is_square(&y2) {
                    let z = x.clone() + &y;
                    let w = x.clone() - &y;
                    if z.clone().modulo(n) != 0 && w.clone().modulo(n) != 0 {
                        let p = gcd(&z, n);
                        let q = gcd(&w, n);
                        if p > 1 && q > 1 {
                            log::debug!("[kraitchik] found p={}", &p);
                            return make_result(p, q, &pub_key.e, n, cipher);
                        }
                    }
                }
                y2 -= n;
            }
            x += 1u32;
        }
        None
    }
}
