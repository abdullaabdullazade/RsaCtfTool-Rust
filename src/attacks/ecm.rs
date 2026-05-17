use rug::{Integer, ops::Pow};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;
use crate::math::next_prime;

pub struct EcmAttack;
pub struct Ecm2Attack;

fn modinv_or_factor(a: &Integer, n: &Integer) -> Result<Integer, Integer> {
    let g = a.clone().gcd(n);
    if g == 1 {
        Ok(a.clone().invert(n).unwrap())
    } else if g == *n {
        Err(Integer::new())
    } else {
        Err(g)
    }
}

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
    let add = (u * &v).modulo(n);
    let sub = (w * &t).modulo(n);
    let xr = (zd.clone() * (add.clone() + &sub).pow(2u32)).modulo(n);
    let zr = (xd.clone() * (add - sub).pow(2u32)).modulo(n);
    (xr, zr)
}

fn mont_double(xp: &Integer, zp: &Integer, a24: &Integer, n: &Integer) -> (Integer, Integer) {
    let u = (xp.clone() + zp).pow(2u32).modulo(n);
    let v = (xp.clone() - zp).pow(2u32).modulo(n);
    let diff = (u.clone() - &v).modulo(n);
    let xr = (u * &v).modulo(n);
    let zr = (diff.clone() * (v + a24.clone() * diff)).modulo(n);
    (xr, zr)
}

fn mont_mul(k: &Integer, x0: &Integer, a24: &Integer, n: &Integer) -> Result<(Integer, Integer), Integer> {
    if *k == 0 { return Ok((Integer::new(), Integer::new())); }
    if *k == 1 { return Ok((x0.clone(), Integer::from(1u32))); }

    let mut r0 = (x0.clone(), Integer::from(1u32));
    let mut r1 = mont_double(x0, &Integer::from(1u32), a24, n);

    let bits = k.significant_bits();
    for i in (0..bits - 1).rev() {
        if k.get_bit(i) {
            r0 = mont_add(&r0.0, &r0.1, &r1.0, &r1.1, x0, &Integer::from(1u32), n);
            r1 = mont_double(&r1.0, &r1.1, a24, n);
        } else {
            r1 = mont_add(&r0.0, &r0.1, &r1.0, &r1.1, x0, &Integer::from(1u32), n);
            r0 = mont_double(&r0.0, &r0.1, a24, n);
        }
    }
    Ok(r0)
}

fn ecm_one_curve(n: &Integer, seed: u64, b1: u64, abort: &Arc<AtomicBool>) -> Option<Integer> {
    let s = Integer::from(seed);
    let u = (s.clone().pow(2u32) - Integer::from(5u32)).modulo(n);
    let v = (Integer::from(4u32) * &s).modulo(n);

    let vu3 = (v.clone() - &u).pow(3u32).modulo(n);
    let t3uv = (Integer::from(3u32) * &u + &v).modulo(n);
    let num = (vu3 * t3uv).modulo(n);
    let u3 = u.clone().pow(3u32).modulo(n);
    let den = (Integer::from(4u32) * u3 * &v).modulo(n);

    let den_inv = match modinv_or_factor(&den, n) {
        Ok(inv) => inv,
        Err(g) if g > 1 && g < *n => return Some(g),
        _ => return None,
    };

    let v3 = v.clone().pow(3u32).modulo(n);
    let v3_inv = match modinv_or_factor(&v3, n) {
        Ok(inv) => inv,
        Err(g) if g > 1 && g < *n => return Some(g),
        _ => return None,
    };
    let x0 = (u.clone().pow(3u32) * v3_inv).modulo(n);

    let a = (num * den_inv - Integer::from(2u32)).modulo(n);
    let inv4 = match modinv_or_factor(&Integer::from(4u32), n) {
        Ok(inv) => inv,
        Err(g) if g > 1 && g < *n => return Some(g),
        _ => return None,
    };
    let a24 = ((a + Integer::from(2u32)) * inv4).modulo(n);

    let mut xz = (x0, Integer::from(1u32));
    let b1_int = Integer::from(b1);
    let mut p = Integer::from(2u32);

    while p <= b1_int {
        if abort.load(Ordering::Relaxed) { return None; }
        let mut pp = p.clone();
        while pp <= b1_int {
            xz = match mont_mul(&pp, &xz.0, &a24, n) {
                Ok(pt) => pt,
                Err(g) if g > 1 && g < *n => return Some(g),
                _ => return None,
            };
            pp *= &p;
        }
        p = next_prime(&p);
    }

    let g = Integer::from(xz.1.gcd_ref(n));
    if g > 1 && g < *n { Some(g) } else { None }
}

fn b1_for_bits(bits: u32) -> u64 {
    match bits {
        0..=64    => 1_000,
        65..=128  => 5_000,
        129..=256 => 50_000,
        257..=512 => 250_000,
        _         => 500_000,
    }
}

fn run_ecm(pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
    let n = &pub_key.n;
    let b1 = b1_for_bits(n.significant_bits());

    for seed in 2u64.. {
        if abort.load(Ordering::Relaxed) { return None; }
        if let Some(p) = ecm_one_curve(n, seed, b1, abort) {
            let q = n.clone() / &p;
            log::debug!("[ecm] found factor with seed={}", seed);
            return make_result(p, q, &pub_key.e, n, cipher);
        }
    }
    None
}

impl RsaAttack for EcmAttack {
    fn name(&self) -> &'static str { "ecm" }
    fn speed(&self) -> Speed { Speed::Slow }
    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        run_ecm(pub_key, cipher, abort)
    }
}

impl RsaAttack for Ecm2Attack {
    fn name(&self) -> &'static str { "ecm2" }
    fn speed(&self) -> Speed { Speed::Slow }
    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        run_ecm(pub_key, cipher, abort)
    }
}
