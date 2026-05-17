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
        let b = 20_000usize;

        let phi_approx = n.clone() - Integer::from(2u32) * n.clone().sqrt() + Integer::from(1u32);
        let parity = phi_approx.clone() & Integer::from(1u32);

        let mut look_up: HashMap<Integer, usize> = HashMap::new();
        let mut z = Integer::from(1u32);
        for i in 0..=b {
            if abort.load(Ordering::Relaxed) { return None; }
            if Integer::from(i as u32) & Integer::from(1u32) == parity {
                look_up.insert(z.clone(), i);
            }
            z = (z * Integer::from(2u32)).modulo(n);
        }

        let pow_phi = Integer::from(2u32).pow_mod(&phi_approx, n).ok()?;
        let mu = modinv(&pow_phi, n)?;
        let fac = Integer::from(2u32).pow_mod(&Integer::from(b as u64), n).ok()?;

        let mut mu_cur = mu;
        for j in 0usize.. {
            if abort.load(Ordering::Relaxed) { return None; }
            if let Some(&i) = look_up.get(&mu_cur) {
                let phi = phi_approx.clone()
                    + Integer::from(i as i64)
                    - Integer::from(j as i64) * Integer::from(b as u64);
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
