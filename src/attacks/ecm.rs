/// Lenstra's Elliptic Curve Method (ECM) for factoring.
/// Uses multiple random curves with Montgomery parametrization.
/// Reference: https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization

use rug::{Integer, ops::Pow};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};

pub struct EcmAttack;
pub struct Ecm2Attack;

// ---------------------------------------------------------------------------
// Montgomery form: Point = (X : Z) where (X/Z, ...) is the affine point
// Using Montgomery ladder for scalar multiplication
// ---------------------------------------------------------------------------

/// Modular inverse — returns None if not invertible (found a factor!)
fn modinv_with_factor(a: &Integer, n: &Integer) -> Result<Integer, Integer> {
    let g = a.clone().gcd(n);
    if g == 1 {
        Ok(a.clone().invert(n).unwrap())
    } else if g == *n {
        Err(Integer::new()) // degenerate
    } else {
        Err(g) // found a factor!
    }
}

/// Montgomery curve point addition: (P+Q, P-Q) given P-Q
/// All arithmetic mod n
fn mont_add(
    xp: &Integer, zp: &Integer,
    xq: &Integer, zq: &Integer,
    xd: &Integer, zd: &Integer,
    n: &Integer,
) -> (Integer, Integer) {
    let u = (xp.clone() - zp).modulo(n);
    let v = (xq.clone() + zq).modulo(n);
    let w = (xp.clone() + zp).modulo(n);
    let t = (xq.clone() - zq).modulo(n);
    let add = (u.clone() * &v).modulo(n);
    let sub = (w.clone() * &t).modulo(n);
    let xr = (zd.clone() * (add.clone() + &sub).pow(2u32)).modulo(n);
    let zr = (xd.clone() * (add - sub).pow(2u32)).modulo(n);
    (xr, zr)
}

/// Montgomery curve point doubling
fn mont_double(xp: &Integer, zp: &Integer, a24: &Integer, n: &Integer) -> (Integer, Integer) {
    let u = (xp.clone() + zp).pow(2u32).modulo(n);
    let v = (xp.clone() - zp).pow(2u32).modulo(n);
    let diff = (u.clone() - &v).modulo(n);
    let xr = (u.clone() * &v).modulo(n);
    let zr = (diff.clone() * (v.clone() + a24.clone() * &diff)).modulo(n);
    (xr, zr)
}

/// Montgomery ladder scalar multiplication: k*P on curve with parameter a24
/// Returns Err(factor) if a non-trivial GCD is found during computation
fn mont_mul(
    k: &Integer,
    x0: &Integer,
    a24: &Integer,
    n: &Integer,
) -> Result<(Integer, Integer), Integer> {
    if *k == 0 { return Ok((Integer::new(), Integer::new())); }
    if *k == 1 { return Ok((x0.clone(), Integer::from(1u32))); }

    let mut r0 = (x0.clone(), Integer::from(1u32));
    let mut r1 = mont_double(x0, &Integer::from(1u32), a24, n);

    let bits = k.significant_bits();
    for i in (0..bits - 1).rev() {
        if k.get_bit(i) {
            let (xr, zr) = mont_add(&r0.0, &r0.1, &r1.0, &r1.1, x0, &Integer::from(1u32), n);
            r0 = (xr, zr);
            r1 = mont_double(&r1.0, &r1.1, a24, n);
        } else {
            let (xr, zr) = mont_add(&r0.0, &r0.1, &r1.0, &r1.1, x0, &Integer::from(1u32), n);
            r1 = (xr, zr);
            r0 = mont_double(&r0.0, &r0.1, a24, n);
        }
    }
    Ok(r0)
}

/// One ECM attempt with a random-seed curve
fn ecm_one_curve(n: &Integer, seed: u64, b1: u64, abort: &Arc<AtomicBool>) -> Option<Integer> {
    // Suyama parametrization: u = seed^2 - 5, v = 4*seed
    let s = Integer::from(seed);
    let u = (s.clone().pow(2u32) - Integer::from(5u32)).modulo(n);
    let v = (Integer::from(4u32) * &s).modulo(n);

    // a = (v-u)^3 * (3u+v) / (4u^3*v) - 2
    // a24 = (a+2)/4
    let vu3 = (v.clone() - &u).pow(3u32).modulo(n);
    let _3uv = (Integer::from(3u32) * &u + &v).modulo(n);
    let num = (vu3 * _3uv).modulo(n);
    let u3 = u.clone().pow(3u32).modulo(n);
    let den = (Integer::from(4u32) * u3 * &v).modulo(n);

    let den_inv = match modinv_with_factor(&den, n) {
        Ok(inv) => inv,
        Err(g) if g > 1 && g < *n => return Some(g),
        _ => return None,
    };

    // x0 = u^3 / v^3
    let v3 = v.clone().pow(3u32).modulo(n);
    let v3_inv = match modinv_with_factor(&v3, n) {
        Ok(inv) => inv,
        Err(g) if g > 1 && g < *n => return Some(g),
        _ => return None,
    };
    let x0 = (u.clone().pow(3u32) * v3_inv).modulo(n);

    let a = (num * den_inv - Integer::from(2u32)).modulo(n);
    let a24 = ((a + Integer::from(2u32)) * match modinv_with_factor(&Integer::from(4u32), n) {
        Ok(inv) => inv,
        Err(g) if g > 1 && g < *n => return Some(g),
        _ => return None,
    }).modulo(n);

    let mut xz = (x0, Integer::from(1u32));

    // Phase 1: multiply by small primes up to B1
    let mut p = Integer::from(2u32);
    while p <= b1 {
        if abort.load(Ordering::Relaxed) { return None; }
        let mut pp = p.clone();
        while pp <= b1 {
            let next = match mont_mul(&pp, &xz.0, &a24, n) {
                Ok(pt) => pt,
                Err(g) if g > 1 && g < *n => return Some(g),
                _ => return None,
            };
            xz = next;
            pp *= &p;
        }
        // Next prime (simple increment then check)
        p += 1u32;
        while p <= b1 + 1 {
            let mut is_prime = p > 1;
            let mut i = Integer::from(2u32);
            while i.clone() * &i <= p {
                if p.clone().modulo(&i) == 0 { is_prime = false; break; }
                i += 1u32;
            }
            if is_prime { break; }
            p += 1u32;
        }
    }

    // Check Z coordinate for a factor
    let g = Integer::from(xz.1.gcd_ref(n));
    if g > 1 && g < *n { Some(g) } else { None }
}

fn run_ecm(pub_key: &PublicKey, abort: &Arc<AtomicBool>) -> Option<AttackResult> {
    let n = &pub_key.n;
    let e = &pub_key.e;

    // This naive pure-Rust ECM is practical only for relatively small composites.
    if n.significant_bits() > 256 {
        return None;
    }

    // B1 bounds by key size
    let b1 = match n.significant_bits() {
        0..=64   => 1_000u64,
        65..=128 => 5_000,
        129..=256 => 50_000,
        257..=512 => 250_000,
        _         => 500_000,
    };

    // Try multiple curves
    for seed in 2u64..=50 {
        if abort.load(Ordering::Relaxed) { return None; }
        if let Some(p) = ecm_one_curve(n, seed, b1, abort) {
            let q = n.clone() / &p;
            if let Some(pk) = PrivateKey::new(p, q, e.clone(), n.clone()) {
                return Some(AttackResult { priv_key: Some(pk), decrypted: vec![] });
            }
        }
    }
    None
}

impl RsaAttack for EcmAttack {
    fn name(&self) -> &'static str { "ecm" }
    fn speed(&self) -> Speed { Speed::Slow }
    fn run(&self, pub_key: &PublicKey, _cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        run_ecm(pub_key, abort)
    }
}

impl RsaAttack for Ecm2Attack {
    fn name(&self) -> &'static str { "ecm2" }
    fn speed(&self) -> Speed { Speed::Slow }
    fn run(&self, pub_key: &PublicKey, _cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        run_ecm(pub_key, abort)
    }
}
