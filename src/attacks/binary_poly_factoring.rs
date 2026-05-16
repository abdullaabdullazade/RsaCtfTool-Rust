/// binary_polynomial_factoring: represent n as a GF(2)[x] polynomial and factor it.
/// n = sum_{i: bit_i=1} 2^i → polynomial over GF(2). Factor the polynomial, evaluate at x=2.
/// Works well for Mersenne-like numbers where n = p * q with p = 2^a+1, q = 2^b+1 etc.
/// Python: sage/binary_polynomial_factoring.sage

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};

pub struct BinaryPolyFactoringAttack;

/// GF(2) polynomial multiplication (coefficients in Z/2Z, represented as bit vector u64).
fn gf2_poly_mul(a: u128, b: u128) -> u128 {
    let mut result = 0u128;
    let mut aa = a;
    let mut bb = b;
    while bb != 0 {
        if bb & 1 != 0 { result ^= aa; }
        aa <<= 1;
        bb >>= 1;
    }
    result
}

/// GF(2) polynomial GCD
fn gf2_poly_gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = gf2_poly_rem(a, b);
        a = b;
        b = r;
    }
    a
}

/// Degree of GF(2) polynomial
fn gf2_poly_deg(a: u128) -> i32 {
    if a == 0 { return -1; }
    127 - a.leading_zeros() as i32
}

/// GF(2) polynomial division remainder
fn gf2_poly_rem(mut a: u128, b: u128) -> u128 {
    let db = gf2_poly_deg(b);
    if db < 0 { return 0; }
    loop {
        let da = gf2_poly_deg(a);
        if da < db { break; }
        a ^= b << (da - db) as u32;
    }
    a
}

/// Evaluate GF(2) polynomial at x=2 over integers
fn gf2_eval_at_2(poly: u128) -> Integer {
    let mut result = Integer::new();
    let mut p = poly;
    let mut bit = 0u32;
    while p != 0 {
        if p & 1 != 0 {
            result += Integer::from(1u32) << bit;
        }
        p >>= 1;
        bit += 1;
    }
    result
}

/// Convert n to a GF(2) polynomial (bit representation), limited to 127 bits
fn int_to_gf2_poly(n: &Integer) -> Option<u128> {
    if n.significant_bits() > 127 { return None; }
    let digits = n.to_digits::<u8>(rug::integer::Order::LsfBe);
    let mut result = 0u128;
    for (i, &byte) in digits.iter().enumerate() {
        result |= (byte as u128) << (i * 8);
    }
    Some(result)
}

/// Trial division in GF(2)[x] up to degree half of input
fn gf2_factor(mut n_poly: u128) -> Option<(u128, u128)> {
    let dn = gf2_poly_deg(n_poly);
    if dn <= 1 { return None; }

    // Try small irreducible polynomials
    // GF(2) irreducible polys by degree: x+1=3, x^2+x+1=7, x^3+x+1=11, x^3+x^2+1=13, ...
    let small_irr: &[u128] = &[3, 7, 11, 13, 19, 25, 37, 41, 47, 55, 59, 61, 67, 91, 97, 103, 109, 115];
    for &p in small_irr {
        if gf2_poly_deg(p) > dn / 2 { break; }
        if gf2_poly_rem(n_poly, p) == 0 {
            // p divides n_poly, do full division
            let mut q = 0u128;
            let mut rem = n_poly;
            while gf2_poly_deg(rem) >= gf2_poly_deg(p) {
                let shift = gf2_poly_deg(rem) - gf2_poly_deg(p);
                q ^= 1u128 << shift;
                rem ^= p << shift;
            }
            return Some((p, q));
        }
    }

    // Brute force search for factors
    let half_deg = dn / 2;
    let mut d = 2u128;
    while gf2_poly_deg(d) <= half_deg {
        if gf2_poly_rem(n_poly, d) == 0 {
            let mut q = 0u128;
            let mut rem = n_poly;
            while gf2_poly_deg(rem) >= gf2_poly_deg(d) {
                let shift = gf2_poly_deg(rem) - gf2_poly_deg(d);
                q ^= 1u128 << shift;
                rem ^= d << shift;
            }
            return Some((d, q));
        }
        d += 1;
    }
    None
}

impl RsaAttack for BinaryPolyFactoringAttack {
    fn name(&self) -> &'static str { "binary_polynomial_factoring" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, _cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let e = &pub_key.e;

        if abort.load(Ordering::Relaxed) { return None; }

        let n_poly = match int_to_gf2_poly(n) {
            Some(p) => p,
            None => {
                log::debug!("[binary_polynomial_factoring] n too large (>127 bits)");
                return None;
            }
        };

        if let Some((p_poly, q_poly)) = gf2_factor(n_poly) {
            let p = gf2_eval_at_2(p_poly);
            let q = gf2_eval_at_2(q_poly);

            if p > 1 && q > 1 && p.clone() * &q == *n {
                if let Some(pk) = PrivateKey::new(p, q, e.clone(), n.clone()) {
                    return Some(AttackResult { priv_key: Some(pk), decrypted: vec![] });
                }
            }

            // Also try: factor might not equal n directly, check gcd
            let p_int = gf2_eval_at_2(p_poly);
            let g = Integer::from(p_int.gcd_ref(n));
            if g > 1 && g < *n {
                let q_int = n.clone() / &g;
                if let Some(pk) = PrivateKey::new(g, q_int, e.clone(), n.clone()) {
                    return Some(AttackResult { priv_key: Some(pk), decrypted: vec![] });
                }
            }
        }
        None
    }
}
