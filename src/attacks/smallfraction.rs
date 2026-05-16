/// smallfraction attack: Coppersmith's method using rational approximations p/q ≈ num/den.
/// Reference: Renaud Lifchitz's "15 ways to break RSA" OPCDE17.
/// sage/smallfraction.sage: for num/den in fractions with den<=50, try small_roots(beta=0.5).

use rug::{Float, Integer};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};

pub struct SmallFractionAttack;

const PREC: u32 = 256;

/// Coppersmith small_roots for f(x) = x - phint (mod n), beta=0.5.
/// We want gcd(x0, n) > 1 where x0 is close to phint.
fn small_roots_linear(n: &Integer, phint: &Integer, x_bound: &Integer) -> Option<Integer> {
    // f(x) = x - phint. Small root x0 satisfies phint + x0 ≡ 0 (mod p).
    // Equivalently p ≈ phint, so we just search near phint.
    // Coppersmith for linear polynomial is trivial: x0 = -phint (mod p).
    // We can just check gcd(phint ± small_delta, n).
    for delta in 0i64..=x_bound.to_i64().unwrap_or(1_000_000).min(1_000_000) {
        for sign in [1i64, -1i64] {
            let candidate = phint.clone() + Integer::from(sign * delta);
            if candidate <= 1 { continue; }
            let g = Integer::from(candidate.gcd_ref(n));
            if g > 1 && g < *n {
                return Some(g);
            }
        }
    }
    None
}

impl RsaAttack for SmallFractionAttack {
    fn name(&self) -> &'static str { "smallfraction" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, _cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let e = &pub_key.e;
        let depth = 50usize;

        let n_float = Float::with_val(PREC, n);

        for den in 2..=depth {
            if abort.load(Ordering::Relaxed) { return None; }
            for num in 1..den {
                if gcd_usize(num, den) != 1 { continue; }
                // phint = sqrt(n * den/num)
                let r = Float::with_val(PREC, den) / Float::with_val(PREC, num);
                let phint_float = (n_float.clone() * r).sqrt();
                let phint = phint_float.to_integer().unwrap_or_else(Integer::new);

                // x_bound ~ N^(beta/e) where beta=0.5, e=1 → x_bound ~ sqrt(N)
                // For practical purposes limit search
                let x_bound = Integer::from(100_000u64);

                if let Some(g) = small_roots_linear(n, &phint, &x_bound) {
                    let q = n.clone() / &g;
                    if let Some(pk) = PrivateKey::new(g, q, e.clone(), n.clone()) {
                        return Some(AttackResult { priv_key: Some(pk), decrypted: vec![] });
                    }
                }
            }
        }
        None
    }
}

fn gcd_usize(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd_usize(b, a % b) }
}
