/// Lehman's factoring algorithm. Matches Python's lehman() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd, is_square};
use crate::key::PublicKey;
use crate::math::iroot;

pub struct LehmanAttack;

impl RsaAttack for LehmanAttack {
    fn name(&self) -> &'static str { "lehman" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        // n ≡ 2 (mod 4) → Fermat-class failure
        if n.clone().modulo(&Integer::from(4u32)) == 2 { return None; }

        let (cbrt_n, _) = iroot(n, 3);
        let (i6, _) = iroot(n, 6);

        for k in 1u64.. {
            if abort.load(Ordering::Relaxed) { return None; }
            let ki = Integer::from(k);
            if ki > cbrt_n { break; }

            let nk4 = n.clone() * &ki * 4u32;
            let ki_sqrt = ki.clone().sqrt();
            let ki4 = ki_sqrt.clone() * 4u32;
            let ink4 = nk4.clone().sqrt() + 1u32;
            let limit = ink4.clone() + Integer::from(&i6 / &ki4) + 1u32;

            let mut a = ink4;
            while a < limit {
                if abort.load(Ordering::Relaxed) { return None; }
                let b2 = a.clone() * &a - &nk4;
                if b2 >= 0 {
                    if let Some(b) = is_square(&b2) {
                        let p = gcd(&(a.clone() + &b), n);
                        let q = gcd(&(a.clone() - &b), n);
                        if p > 1 && q > 1 {
                            log::debug!("[lehman] found p={}", &p);
                            return make_result(p, q, &pub_key.e, n, cipher);
                        }
                    }
                }
                a += 1u32;
            }
        }
        None
    }
}
