/// Carmichael factorization — Wagstaff's Joy of Factoring algorithm.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;
use crate::math::next_prime;

pub struct CarmichaelAttack;

fn a000265(n: &Integer) -> Integer {
    let mut r = n.clone();
    while r.clone() & 1u32 == 0 { r >>= 1u32; }
    r
}

impl RsaAttack for CarmichaelAttack {
    fn name(&self) -> &'static str { "carmichael" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        // Naive Carmichael search is only practical on small moduli.
        if n.significant_bits() > 96 {
            return None;
        }
        let n1 = n.clone() - 1u32;
        let f = a000265(&n1);
        let mut a = Integer::from(2u32);
        let mut rounds = 0u64;
        let max_rounds = 50_000u64;

        while a <= n1 {
            if abort.load(Ordering::Relaxed) { return None; }
            if rounds >= max_rounds { return None; }
            rounds += 1;

            let _f2 = f.clone() << 1u32;
            let r = a.clone().pow_mod(&f, n).ok()?;

            if r.clone().pow_mod(&Integer::from(2u32), n).ok()? == 1 {
                let p = gcd(&(r.clone() - 1u32), n);
                let q = gcd(&(r.clone() + 1u32), n);
                if *n > q && q > p && p > 1 {
                    log::debug!("[carmichael] found p={}, q={}", &p, &q);
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
            }
            a = next_prime(&a);
        }
        None
    }
}
