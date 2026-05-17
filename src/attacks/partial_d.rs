use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;
use crate::math::gcdext;

pub struct PartialDAttack;

/// Hensel lift: find all x in [0, 2^bits) s.t. a*x^2 + b*x + c ≡ 0 (mod 2^bits)
fn hensel_lift(a: &Integer, b: &Integer, c: &Integer, bits: u32) -> Vec<Integer> {
    // Seeds mod 2
    let mut roots: Vec<Integer> = (0u32..2).filter(|&r| {
        let r = Integer::from(r);
        let val = a.clone() * r.clone() * r.clone() + b.clone() * r.clone() + c.clone();
        val.clone().modulo(&Integer::from(2u32)) == 0
    }).map(Integer::from).collect();

    for k in 1..bits {
        let modulus = Integer::from(1u32) << k;
        let next_mod = modulus.clone() << 1u32;
        let mut new_roots = Vec::new();
        for r in &roots {
            for delta in [Integer::from(0u32), modulus.clone()] {
                let candidate = r.clone() + delta;
                let val = a.clone() * candidate.clone() * candidate.clone()
                        + b.clone() * candidate.clone()
                        + c.clone();
                if val.modulo(&next_mod) == 0 {
                    new_roots.push(candidate.modulo(&next_mod));
                }
            }
        }
        roots = new_roots;
    }
    roots
}

/// Coppersmith small root for monic f(x) = l*x + p_low mod n, |x| < X
fn coppersmith_linear(n: &Integer, p_low: &Integer, l: &Integer, x_bound: &Integer) -> Option<Integer> {
    // f(x) = l*x + p_low ≡ 0 (mod p) where p | n
    // We want gcd(f(x0), n) for x0 in range
    // For linear case: x0 = -p_low * l^-1 mod p, but we try small values
    let (_, inv_l, _) = gcdext(l, n);
    let x0 = (Integer::from(0u32) - p_low.clone() * &inv_l).modulo(n);
    // Check if it's in range
    if x0 <= *x_bound {
        let p_candidate = l.clone() * &x0 + p_low;
        let g = Integer::from(p_candidate.gcd_ref(n));
        if g > 1 && g < *n {
            return Some(g);
        }
    }
    // Also try n - x0 variant
    let x1 = n.clone() - &x0;
    if x1 <= *x_bound {
        let p_candidate = l.clone() * &x1 + p_low;
        let g = Integer::from(p_candidate.gcd_ref(n));
        if g > 1 && g < *n {
            return Some(g);
        }
    }
    None
}

impl RsaAttack for PartialDAttack {
    fn name(&self) -> &'static str { "partial_d" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, _cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let e = &pub_key.e;

        // This attack requires the low bits of d. Without partial key input we can't run.
        // However we can attempt with a small d_low range for CTF purposes.
        // Full implementation requires --partial flag support.
        log::debug!("[partial_d] requires partial d bits via --partial flag");
        let _ = (n, e, abort.load(Ordering::Relaxed));
        None
    }
}

/// Public helper for use when d_low bits are known.
pub fn partial_d_attack(n: &Integer, e: &Integer, d_low: &Integer, abort: &Arc<AtomicBool>) -> Option<(Integer, Integer)> {
    let lower_bits = d_low.significant_bits();
    let l = Integer::from(1u32) << lower_bits;
    let x_bound = Integer::from(1u32) << (n.significant_bits() / 2 - lower_bits + 1);

    for k in 1u32..e.to_u32().unwrap_or(65537) + 1 {
        if abort.load(Ordering::Relaxed) { return None; }
        let a = Integer::from(k);
        let b = e.clone() * d_low - Integer::from(k) * (n.clone() + 1u32) - 1u32;
        let c = Integer::from(k) * n;

        for p_low in hensel_lift(&a, &b, &c, lower_bits) {
            if abort.load(Ordering::Relaxed) { return None; }
            if let Some(p) = coppersmith_linear(n, &p_low, &l, &x_bound) {
                if n.clone().modulo(&p) == 0 {
                    return Some((p.clone(), n.clone() / &p));
                }
            }
        }
    }
    None
}
