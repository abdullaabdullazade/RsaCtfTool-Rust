use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;
use crate::math::next_prime;

pub struct MersennePm1GcdAttack;
impl RsaAttack for MersennePm1GcdAttack {
    fn name(&self) -> &'static str { "mersenne_pm1_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let bits = n.significant_bits();
        for i in 2..bits {
            if abort.load(Ordering::Relaxed) { return None; }
            let i2 = Integer::from(1u32) << i;
            for mersenne in [i2.clone() - 1u32, i2 + 1u32] {
                let g = gcd(&mersenne, n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }
        }
        None
    }
}

pub struct PrimorialPm1GcdAttack;
impl RsaAttack for PrimorialPm1GcdAttack {
    fn name(&self) -> &'static str { "primorial_pm1_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let mut prime = Integer::from(1u32);
        let mut primorial = Integer::from(1u32);
        loop {
            if abort.load(Ordering::Relaxed) { return None; }
            prime = next_prime(&prime);
            primorial = (primorial * &prime).modulo(n);
            for p_pm1 in [primorial.clone() - 1u32, primorial.clone() + 1u32] {
                let g = gcd(&p_pm1, n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }
        }
    }
}

pub struct FactorialPm1GcdAttack;
impl RsaAttack for FactorialPm1GcdAttack {
    fn name(&self) -> &'static str { "factorial_pm1_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let mut f = Integer::from(1u32);
        let mut x = 2u32;
        loop {
            if abort.load(Ordering::Relaxed) { return None; }
            f = (f * x).modulo(n);
            for f_pm1 in [f.clone() - 1u32, f.clone() + 1u32] {
                let g = gcd(&f_pm1, n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }
            x += 1;
        }
    }
}

pub struct FermatNumbersGcdAttack;
impl RsaAttack for FermatNumbersGcdAttack {
    fn name(&self) -> &'static str { "fermat_numbers_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        for x in 2u64.. {
            if abort.load(Ordering::Relaxed) { return None; }
            let exp = Integer::from(1u32) << (x as u32);
            let fx_mod = match Integer::from(2u32).pow_mod(&exp, n) {
                Ok(r) => r + 1u32,
                Err(_) => continue,
            };
            let g = gcd(&fx_mod, n);
            if g > 1 && g < *n {
                let q = n.clone() / &g;
                return make_result(g, q, &pub_key.e, n, cipher);
            }
        }
        None
    }
}

#[inline]
fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 { let t = a % b; a = b; b = t; }
    a
}

pub struct LucasGcdAttack;
impl RsaAttack for LucasGcdAttack {
    fn name(&self) -> &'static str { "lucas_gcd" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        if let Some(n_u) = n.to_u128() {
            let mut l_prev = 2u128 % n_u;
            let mut l_cur = 1u128 % n_u;
            loop {
                if abort.load(Ordering::Relaxed) { return None; }
                let g = gcd_u128(l_cur, n_u);
                if g > 1 && g < n_u {
                    let p = Integer::from(g);
                    let q = n.clone() / &p;
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
                let next = (l_prev + l_cur) % n_u;
                l_prev = l_cur;
                l_cur = next;
            }
        }

        let mut l_prev = Integer::from(2u32).modulo(n);
        let mut l_cur = Integer::from(1u32).modulo(n);
        loop {
            if abort.load(Ordering::Relaxed) { return None; }
            let g = gcd(&l_cur, n);
            if g > 1 && g < *n {
                let q = n.clone() / &g;
                return make_result(g, q, &pub_key.e, n, cipher);
            }
            let next = (l_prev + &l_cur).modulo(n);
            l_prev = l_cur;
            l_cur = next;
        }
    }
}

pub struct FibonacciGcdAttack;
impl RsaAttack for FibonacciGcdAttack {
    fn name(&self) -> &'static str { "fibonacci_gcd" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        if let Some(n_u) = n.to_u128() {
            let mut f_prev = 0u128;
            let mut f_cur = 1u128 % n_u;
            loop {
                if abort.load(Ordering::Relaxed) { return None; }
                let g = gcd_u128(f_cur, n_u);
                if g > 1 && g < n_u {
                    let p = Integer::from(g);
                    let q = n.clone() / &p;
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
                let next = (f_prev + f_cur) % n_u;
                f_prev = f_cur;
                f_cur = next;
            }
        }

        let mut f_prev = Integer::new();
        let mut f_cur = Integer::from(1u32).modulo(n);
        loop {
            if abort.load(Ordering::Relaxed) { return None; }
            let g = gcd(&f_cur, n);
            if g > 1 && g < *n {
                let q = n.clone() / &g;
                return make_result(g, q, &pub_key.e, n, cipher);
            }
            let next = (f_prev + &f_cur).modulo(n);
            f_prev = f_cur;
            f_cur = next;
        }
    }
}
