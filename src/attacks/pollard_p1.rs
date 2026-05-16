/// Pollard P-1 factorization. Matches Python's pollard_P_1() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd, primes_up_to};
use crate::key::PublicKey;

pub struct PollardP1Attack;

impl RsaAttack for PollardP1Attack {
    fn name(&self) -> &'static str { "pollard_p_1" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let primes = primes_up_to(997);
        let logn = (n.significant_bits() as f64) / 2.0; // approx log(sqrt(n))

        // Build exponents list: for each prime p, include floor(log_p(sqrt(n))) copies
        let mut z: Vec<u64> = Vec::new();
        for &p in &primes {
            let logp = (p as f64).ln();
            let exp = (logn / logp).floor() as usize;
            for _ in 0..exp {
                z.push(p);
            }
        }

        for &pp_start in &primes {
            if abort.load(Ordering::Relaxed) { return None; }
            let mut pp = Integer::from(pp_start);
            for &zi in &z {
                pp = pp.pow_mod(&Integer::from(zi), n).ok()?;
                let p = gcd(&(pp.clone() - 1u32), n);
                if *n > p && p > 1 {
                    let q = n.clone() / &p;
                    log::debug!("[pollard_p_1] found p={}", &p);
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
            }
        }
        None
    }
}
