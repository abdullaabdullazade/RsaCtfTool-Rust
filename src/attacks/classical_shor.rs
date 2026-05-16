use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};

pub struct ClassicalShorAttack;

impl RsaAttack for ClassicalShorAttack {
    fn name(&self) -> &'static str { "classical_shor" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, _cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        // Only feasible for small n (classical simulation of quantum period finding)
        if n.significant_bits() > 64 {
            log::debug!("[classical_shor] n too large for classical simulation");
            return None;
        }

        let mut a = Integer::from(2u32);
        while a < *n {
            if abort.load(Ordering::Relaxed) { return None; }

            // gcd(a, n) != 1 → trivial factor
            let g = Integer::from(a.clone().gcd_ref(n));
            if g != 1 {
                let p = g;
                let q = n.clone() / &p;
                if let Some(pk) = PrivateKey::new(p, q, pub_key.e.clone(), n.clone()) {
                    return Some(AttackResult { priv_key: Some(pk), decrypted: vec![] });
                }
            }

            // Find period r: a^r ≡ 1 (mod n), r must be even
            let mut r = Integer::from(2u32);
            while r < *n {
                if abort.load(Ordering::Relaxed) { return None; }
                let ar = a.clone().pow_mod(&r, n).ok()?;
                if ar == 1 {
                    // a^(r/2) mod n
                    let r2 = r.clone() >> 1;
                    let ar2 = a.clone().pow_mod(&r2, n).ok()?;
                    let nm1 = n.clone() - 1u32;
                    if ar2 != nm1 {
                        let g1 = Integer::from((ar2.clone() - 1u32).gcd_ref(n));
                        let g2 = Integer::from((ar2 + 1u32).gcd_ref(n));
                        for g in [g1, g2] {
                            if g > 1 && g < *n {
                                let p = g;
                                let q = n.clone() / &p;
                                if let Some(pk) = PrivateKey::new(p, q, pub_key.e.clone(), n.clone()) {
                                    return Some(AttackResult { priv_key: Some(pk), decrypted: vec![] });
                                }
                            }
                        }
                    }
                    break;
                }
                r += 2u32;
            }
            a += 1u32;
        }
        None
    }
}
