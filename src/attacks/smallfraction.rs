use rug::{Float, Integer};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};

pub struct SmallFractionAttack;

fn small_roots_linear(n: &Integer, phint: &Integer, x_bound: &Integer) -> Option<Integer> {
    let bound = x_bound.to_i64().unwrap_or(1_000_000).min(1_000_000);
    for delta in 0i64..=bound {
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
        let prec = n.significant_bits() + 64;
        let n_float = Float::with_val(prec, n);
        let x_bound = Integer::from(100_000u64);

        for den in 2..=depth {
            if abort.load(Ordering::Relaxed) { return None; }
            for num in 1..den {
                if gcd_usize(num, den) != 1 { continue; }
                let r = Float::with_val(prec, den) / Float::with_val(prec, num);
                let phint = (n_float.clone() * r).sqrt().to_integer().unwrap_or_else(Integer::new);

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
