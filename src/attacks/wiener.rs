/// Wiener's attack via continued fractions.
/// Matches Python's wiener() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, is_square};
use crate::key::PublicKey;

pub struct WienerAttack;

/// Continued fraction expansion of num/den → convergents as (k, d) pairs.
fn convergents(mut num: Integer, mut den: Integer) -> Vec<(Integer, Integer)> {
    let mut h_prev = Integer::from(1u32);
    let mut k_prev = Integer::new();
    let mut h_curr = Integer::new();
    let mut k_curr = Integer::from(1u32);
    let mut result = Vec::new();
    let mut first = true;

    while den != 0 {
        let (q, r) = num.clone().div_rem(den.clone());

        if first {
            h_curr = q.clone();
            k_curr = Integer::from(1u32);
            first = false;
        } else {
            let h_next = q.clone() * &h_curr + &h_prev;
            let k_next = q.clone() * &k_curr + &k_prev;
            h_prev = h_curr;
            k_prev = k_curr;
            h_curr = h_next;
            k_curr = k_next;
        }

        result.push((h_curr.clone(), k_curr.clone()));
        num = den;
        den = r;
    }
    result
}

impl RsaAttack for WienerAttack {
    fn name(&self) -> &'static str { "wiener" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let e = &pub_key.e;

        for (k, d) in convergents(e.clone(), n.clone()) {
            if abort.load(Ordering::Relaxed) { return None; }
            if k == 0 { continue; }

            // phi = (e*d - 1) / k  must be integer
            let ed_minus_1 = e.clone() * &d - 1u32;
            let (phi, rem) = ed_minus_1.div_rem(k.clone());
            if rem != 0 { continue; }
            if phi.clone() & 1u32 != 0 { continue; } // phi must be even

            // s = n - phi + 1 = p + q
            let s = n.clone() - &phi + 1u32;
            // discriminant = s^2 - 4n
            let discr = s.clone() * &s - (n.clone() << 2u32);
            if discr <= 0 { continue; }

            if let Some(t) = is_square(&discr) {
                if (s.clone() + &t) % 2u32 != 0 { continue; }
                let p = (s.clone() + &t) / 2u32;
                let q = (s - &t) / 2u32;
                if p.clone() * &q == *n && p > 1 && q > 1 {
                    log::debug!("[wiener] found d={}", &d);
                    return make_result(p, q, e, n, cipher);
                }
            }
        }
        None
    }
}
