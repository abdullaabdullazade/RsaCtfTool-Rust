/// Pollard's Rho factorization (Floyd cycle detection).
/// Matches Python's pollard_rho() in algos.py.

use rug::Integer;
use rand::Rng;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct PollardRhoAttack;

fn rho_step(x: Integer, c: &Integer, n: &Integer) -> Integer {
    (x.clone() * &x + c).modulo(n)
}

impl RsaAttack for PollardRhoAttack {
    fn name(&self) -> &'static str { "pollard_rho" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        if n.significant_bits() > 160 {
            return None;
        }
        let mut rng = rand::thread_rng();
        let max_tries = 16u32;
        let max_iter = 100_000u64;

        for _ in 0..max_tries {
            if abort.load(Ordering::Relaxed) { return None; }
            let c = Integer::from((rng.gen::<u64>() % 19) + 1);
            let mut d = Integer::from(1u32);
            let mut x = Integer::from(2u32);
            let mut y = Integer::from(2u32);

            for _ in 0..max_iter {
                if abort.load(Ordering::Relaxed) { return None; }
                if d != 1 { break; }
                x = rho_step(x, &c, n);
                y = rho_step(rho_step(y, &c, n), &c, n);
                let diff = if x > y { x.clone() - &y } else { y.clone() - &x };
                d = gcd(&diff, n);
            }

            if d > 1 && d < *n {
                let q = n.clone() / &d;
                log::debug!("[pollard_rho] found p={}", &d);
                return make_result(d, q, &pub_key.e, n, cipher);
            }
        }
        None
    }
}
