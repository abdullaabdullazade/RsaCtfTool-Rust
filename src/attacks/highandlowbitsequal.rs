use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, is_square};
use crate::attack::isqrt;
use crate::key::PublicKey;

pub struct HighAndLowBitsEqualAttack;

fn inverse_inverse_sqrt2exp(n: &Integer, k: u32) -> Option<Integer> {
    // Newton's method to find r such that r^2 ≈ n (mod 2^k)
    // Starting from r = 1, iteratively refine
    let mut r = Integer::from(1u32);
    let two_k = Integer::from(1u32) << k;
    for _ in 0..64 {
        // r_new = r * (3 - n * r^2) / 2 mod 2^k
        let r2 = r.clone() * &r;
        let nr2 = (n.clone() * &r2).modulo(&two_k);
        if nr2 == 1 { break; }
        let t = (Integer::from(3u32) - &nr2).modulo(&two_k);
        r = (r * t * Integer::from(2u32).invert(&two_k).ok()?).modulo(&two_k);
    }
    Some(r)
}

impl RsaAttack for HighAndLowBitsEqualAttack {
    fn name(&self) -> &'static str { "highandlowbitsequal" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let n_size = n.significant_bits();
        if n_size < 6 || n.clone().modulo(&Integer::from(8u32)) != 1 {
            return None;
        }

        let k = (n_size + 1) / 2;
        let r0 = inverse_inverse_sqrt2exp(n, k + 1)?;
        let a = isqrt(&(n.clone() - Integer::from(1u32))) + Integer::from(1u32);
        let k_shift = Integer::from(1u32) << k;

        let max_middle_bits = 24usize;
        for middle_bits in 1..=max_middle_bits {
            if abort.load(Ordering::Relaxed) { return None; }
            for r_start in [r0.clone(), k_shift.clone() - &r0] {
                let mut s = a.clone();
                for i in 0..k {
                    if abort.load(Ordering::Relaxed) { return None; }
                    if ((s.clone() ^ &r_start) >> i) & Integer::from(1u32) != 0 {
                        let m = middle_bits.min(i as usize);
                        let shift_val = Integer::from(1u32) << (i as usize - m);
                        for _ in 0..(1usize << m) {
                            s += &shift_val;
                            let d = s.clone() * &s - n;
                            if d >= 0 {
                                if let Some(d_sqrt) = is_square(&d) {
                                    let p = s.clone() - &d_sqrt;
                                    let q = s.clone() + &d_sqrt;
                                    if p > 1 && q > 1 && p.clone() * &q == *n {
                                        log::debug!("[highandlowbitsequal] found factor");
                                        return make_result(p, q, &pub_key.e, n, cipher);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
