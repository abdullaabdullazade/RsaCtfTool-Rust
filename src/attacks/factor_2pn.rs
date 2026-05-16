

/// Factor 2PN: factors N = p*q where sqrt(2PN) ≈ (Pp + 2q)/2.
/// Matches Python's factor_2PN() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;

pub struct Factor2PnAttack;

fn factor_2pn(n: &Integer, p_val: u32) -> Option<(Integer, Integer)> {
    let p2n = n.clone() * Integer::from(p_val) * 2u32;
    let (a, rem) = p2n.clone().sqrt_rem(Integer::new());
    let a = if rem != 0 { a + 1u32 } else { a };

    let c = -(a.clone() * &a) + &a + &p2n;
    let disc = Integer::from(1i32) - (c.clone() << 2u32);
    if disc < 0 { return None; }

    let (isqrt_disc, rem_disc) = disc.sqrt_rem(Integer::new());
    if rem_disc != 0 { return None; }

    for sign in &[1i32, -1i32] {
        let x = if *sign > 0 {
            (Integer::from(-1i32) + &isqrt_disc) / 2i32
        } else {
            (Integer::from(-1i32) - &isqrt_disc) / 2i32
        };
        if x < 0 { continue; }

        // 2q < Pp
        let p_candidate = (a.clone() + &x) / Integer::from(p_val);
        let q_candidate = (a.clone() - &x - 1u32) / 2u32;
        if p_candidate.clone() * &q_candidate == *n && p_candidate > 1 && q_candidate > 1 {
            return Some((p_candidate, q_candidate));
        }

        // Pp < 2q
        let p2 = (a.clone() - &x - 1u32) / Integer::from(p_val);
        let q2 = (a.clone() + &x) / 2u32;
        if p2.clone() * &q2 == *n && p2 > 1 && q2 > 1 {
            return Some((p2, q2));
        }
    }
    None
}

impl RsaAttack for Factor2PnAttack {
    fn name(&self) -> &'static str { "factor_2PN" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        for &p in &[3u32, 5, 7, 11, 13] {
            if let Some((p_val, q_val)) = factor_2pn(&pub_key.n, p) {
                log::debug!("[factor_2PN] p={}", p);
                return make_result(p_val, q_val, &pub_key.e, &pub_key.n, cipher);
            }
        }
        None
    }
}
