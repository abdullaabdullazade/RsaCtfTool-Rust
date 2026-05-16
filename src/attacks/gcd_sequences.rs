/// GCD-sequence attacks: mersenne_pm1, primorial_pm1, factorial_pm1,
/// fermat_numbers, lucas_gcd, fibonacci_gcd.
/// All match their Python counterparts in RsaCtfTool.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;
use crate::math::next_prime;

// ---------------------------------------------------------------------------
// mersenne_pm1_gcd: GCD(2^i ± 1, n) for i = 2..log2(n)
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// primorial_pm1_gcd: GCD(p# ± 1, n) for first 10000 primes
// ---------------------------------------------------------------------------
pub struct PrimorialPm1GcdAttack;
impl RsaAttack for PrimorialPm1GcdAttack {
    fn name(&self) -> &'static str { "primorial_pm1_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let mut prime = Integer::from(1u32);
        let mut primorial = Integer::from(1u32);
        for _ in 0..10_000 {
            if abort.load(Ordering::Relaxed) { return None; }
            prime = next_prime(&prime);
            primorial *= &prime;
            for p_pm1 in [primorial.clone() - 1u32, primorial.clone() + 1u32] {
                let g = gcd(&p_pm1, n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// factorial_pm1_gcd: GCD(k! ± 1, n) for k = 2..30000
// ---------------------------------------------------------------------------
pub struct FactorialPm1GcdAttack;
impl RsaAttack for FactorialPm1GcdAttack {
    fn name(&self) -> &'static str { "factorial_pm1_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let mut f = Integer::from(1u32);
        for x in 2u32..30_000 {
            if abort.load(Ordering::Relaxed) { return None; }
            f *= x;
            for f_pm1 in [f.clone() - 1u32, f.clone() + 1u32] {
                let g = gcd(&f_pm1, n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// fermat_numbers_gcd: GCD(2^(2^x) + 1, n) for x = 2..30
// ---------------------------------------------------------------------------
pub struct FermatNumbersGcdAttack;
impl RsaAttack for FermatNumbersGcdAttack {
    fn name(&self) -> &'static str { "fermat_numbers_gcd" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        for x in 2u32..30 {
            if abort.load(Ordering::Relaxed) { return None; }
            // f = 2^(2^x) + 1
            let exp: u32 = 1 << x;
            let f = (Integer::from(1u32) << exp) + 1u32;
            let g = gcd(&f, n);
            if g > 1 && g < *n {
                let q = n.clone() / &g;
                return make_result(g, q, &pub_key.e, n, cipher);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// lucas_gcd: GCD(L_k, n) for k = 1..10000
// ---------------------------------------------------------------------------
pub struct LucasGcdAttack;

#[inline]
fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

impl RsaAttack for LucasGcdAttack {
    fn name(&self) -> &'static str { "lucas_gcd" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        if let Some(n_u) = n.to_u128() {
            // Fast path for small/medium moduli: stay in u128 arithmetic.
            let mut l_prev = 2u128 % n_u;
            let mut l_cur = 1u128 % n_u;
            for x in 1u64..10_000 {
                if abort.load(Ordering::Relaxed) { return None; }
                let lx_mod = if x == 1 {
                    l_cur
                } else {
                    let next = (l_prev + l_cur) % n_u;
                    l_prev = l_cur;
                    l_cur = next;
                    l_cur
                };
                let g = gcd_u128(lx_mod, n_u);
                if g > 1 && g < n_u {
                    let p = Integer::from(g);
                    let q = n.clone() / &p;
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
            }
            return None;
        }

        // Compute Lucas numbers modulo n to avoid giant intermediate integers.
        // gcd(L_k mod n, n) == gcd(L_k, n)
        let mut l_prev = Integer::from(2u32).modulo(n); // L_0
        let mut l_cur = Integer::from(1u32).modulo(n);  // L_1
        for x in 1u64..10_000 {
            if abort.load(Ordering::Relaxed) { return None; }
            let lx_mod = if x == 1 {
                l_cur.clone()
            } else {
                let next = (l_prev + &l_cur).modulo(n);
                l_prev = l_cur;
                l_cur = next;
                l_cur.clone()
            };
            let g = gcd(&lx_mod, n);
            if g > 1 && g < *n {
                let q = n.clone() / &g;
                return make_result(g, q, &pub_key.e, n, cipher);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// fibonacci_gcd: GCD(F_k, n) for k = 1..10000
// ---------------------------------------------------------------------------
pub struct FibonacciGcdAttack;
impl RsaAttack for FibonacciGcdAttack {
    fn name(&self) -> &'static str { "fibonacci_gcd" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        if let Some(n_u) = n.to_u128() {
            let mut f_prev = 0u128;
            let mut f_cur = 1u128 % n_u;
            for x in 1u64..10_000 {
                if abort.load(Ordering::Relaxed) { return None; }
                let fx_mod = if x == 1 {
                    f_cur
                } else {
                    let next = (f_prev + f_cur) % n_u;
                    f_prev = f_cur;
                    f_cur = next;
                    f_cur
                };
                let g = gcd_u128(fx_mod, n_u);
                if g > 1 && g < n_u {
                    let p = Integer::from(g);
                    let q = n.clone() / &p;
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
            }
            return None;
        }

        // Compute Fibonacci numbers modulo n to keep values bounded by n.
        // gcd(F_k mod n, n) == gcd(F_k, n)
        let mut f_prev = Integer::new();               // F_0
        let mut f_cur = Integer::from(1u32).modulo(n); // F_1
        for x in 1u64..10_000 {
            if abort.load(Ordering::Relaxed) { return None; }
            let fx_mod = if x == 1 {
                f_cur.clone()
            } else {
                let next = (f_prev + &f_cur).modulo(n);
                f_prev = f_cur;
                f_cur = next;
                f_cur.clone()
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
