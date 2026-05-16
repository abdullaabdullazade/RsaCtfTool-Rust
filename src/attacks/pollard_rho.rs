/// Pollard's Rho factorization (Floyd cycle detection).
/// Matches Python's pollard_rho() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct PollardRhoAttack;

fn rho_step(x: Integer, n: &Integer) -> Integer {
    (x.clone() * &x - 1u32).modulo(n)
}

impl RsaAttack for PollardRhoAttack {
    fn name(&self) -> &'static str { "pollard_rho" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let mut d = Integer::from(1u32);
        let mut x = Integer::from(2u32);
        let mut y = Integer::from(2u32);

        while d == 1 {
            if abort.load(Ordering::Relaxed) { return None; }
            x = rho_step(x, n);
            y = rho_step(rho_step(y, n), n);
            let diff = if x > y { x.clone() - &y } else { y.clone() - &x };
            d = gcd(&diff, n);
        }

        if d == *n { return None; } // failure — try different start

        let q = n.clone() / &d;
        log::debug!("[pollard_rho] found p={}", &d);
        make_result(d, q, &pub_key.e, n, cipher)
    }
}
