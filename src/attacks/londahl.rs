/// Londahl close-factor attack: factors N when p and q are close to sqrt(N).
/// Uses BSGS (baby-step giant-step) table over phi approximation.
/// Matches Python's close_factor() in algos.py.

use rug::Integer;
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;
use crate::math::{modinv, factor_from_n_phi};

pub struct LondahlAttack;

impl RsaAttack for LondahlAttack {
    fn name(&self) -> &'static str { "londahl" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let b = 100_000usize; // londahl bound

        // phi_approx = n - 2*sqrt(n) + 1
        let phi_approx = n.clone() - Integer::from(2u32) * n.clone().sqrt() + Integer::from(1u32);
        let parity = phi_approx.clone() & Integer::from(1u32);

        // Baby steps: build lookup table z = 2^i mod n for even/odd i
        let mut look_up: HashMap<Integer, usize> = HashMap::new();
        let mut z = Integer::from(1u32);
        for i in 0..=b {
            if abort.load(Ordering::Relaxed) { return None; }
            let bit = Integer::from(i as u32) & Integer::from(1u32);
            if bit == parity {
                look_up.insert(z.clone(), i);
            }
            z = (z * Integer::from(2u32)).modulo(n);
        }

        // Giant steps: mu = inv(2^phi_approx) mod n, fac = 2^b mod n
        let pow_phi = Integer::from(2u32).pow_mod(&phi_approx, n).ok()?;
        let mu = modinv(&pow_phi, n)?;
        let fac = Integer::from(2u32).pow_mod(&Integer::from(b as u64), n).ok()?;

        let mut mu_cur = mu;
        let max_j = b * b + 1;
        for j in 0..max_j {
            if abort.load(Ordering::Relaxed) { return None; }
            if let Some(&i) = look_up.get(&mu_cur) {
                let phi = phi_approx.clone() + Integer::from(i as i64) - Integer::from(j as i64) * Integer::from(b as u64);
                if let Some((p, q)) = factor_from_n_phi(n, &phi) {
                    if p > 1 && q > 1 {
                        log::debug!("[londahl] found factor at j={}", j);
                        return make_result(p, q, &pub_key.e, n, cipher);
                    }
                }
            }
            mu_cur = (mu_cur * &fac).modulo(n);
        }
        None
    }
}
