/// Williams P+1 factorization. Matches Python's williams_pp1() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;
use crate::math::{next_prime, mlucas, ilogb};

pub struct WilliamsPp1Attack;

impl RsaAttack for WilliamsPp1Attack {
    fn name(&self) -> &'static str { "williams_pp1" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        if n.significant_bits() > 160 {
            return None;
        }
        let i2 = n.clone().sqrt();
        let mut p = Integer::from(2u32);

        for v_start in 1u32..50 {
            if abort.load(Ordering::Relaxed) { return None; }
            let mut v = Integer::from(v_start);
            let mut prime = p.clone();
            let mut prime_steps = 0u64;
            let max_prime_steps = 50_000u64;

            loop {
                if abort.load(Ordering::Relaxed) { return None; }
                if prime_steps >= max_prime_steps { return None; }
                prime_steps += 1;
                let e = ilogb(&i2, prime.to_u64().unwrap_or(2));
                if e == 0 { break; }
                for _ in 0..e {
                    v = mlucas(&v, &prime, n);
                }
                let g = gcd(&(v.clone() - 2u32), n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    log::debug!("[williams_pp1] found factor={}", &g);
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
                if g == *n { break; }
                prime = next_prime(&prime);
                if prime > i2 { break; }
            }
            p = next_prime(&p);
        }
        None
    }
}
