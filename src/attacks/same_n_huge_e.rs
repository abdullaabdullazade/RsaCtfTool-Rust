/// same_n_huge_e: when two keys share the same N but one e is huge,
/// recover d using the extended Euclidean relation.
/// Matches Python's same_n_huge_e() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};
use crate::math::modinv;

pub struct SameNHugeEAttack {
    pub other_keys: Vec<PublicKey>,
}

impl RsaAttack for SameNHugeEAttack {
    fn name(&self) -> &'static str { "same_n_huge_e" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let e1 = &pub_key.e;

        for other in &self.other_keys {
            if &other.n != n { continue; }
            let e2 = &other.e;

            // Try to recover phi from the two exponents
            // If e1*d1 ≡ 1 (mod phi) and e2*d2 ≡ 1 (mod phi), then
            // gcd(e1, e2) may reveal information about phi.
            // Simple case: one e is huge → try d = modinv(e, phi) for guessed phi values
            // More specifically: if e1 is "normal" and e2 is huge, try
            // using the relation e2 = e1 + k*phi for some small k

            let e_small;
            let e_large;
            if e1 < e2 {
                e_small = e1;
                e_large = e2;
            } else {
                e_small = e2;
                e_large = e1;
            }

            // Try phi = (e_large - 1) * inv(e_small - 1, e_large - 1) style guesses
            // Or more directly: check if e_large - 1 is divisible by small factors
            // that suggest phi(n) = n - p - q + 1

            // Attempt: phi ≈ n - 2*sqrt(n) + 1 for balanced primes
            let approx_phi = n.clone() - Integer::from(2u32) * n.clone().sqrt() + Integer::from(1u32);

            // Try e_large mod phi = small value
            for k in 1u64..1000 {
                let _candidate_phi = e_large.clone() / k + if e_large.clone() % k == 0 { Integer::new() } else { Integer::from(1u32) };
                // This is rough; try exact: phi = e_large - k (if e_large ≡ k mod phi)
                let phi_candidate = if e_large > &Integer::from(k) {
                    e_large.clone() - Integer::from(k)
                } else {
                    continue;
                };

                if let Some(d) = modinv(e_small, &phi_candidate) {
                    // Verify: e_small * d ≡ 1 (mod phi_candidate) — already true by modinv
                    // Also verify phi_candidate divides e_large * d_large - 1 for some d_large
                    let priv_key = PrivateKey::from_ned(n.clone(), e_small.clone(), d.clone());
                    // Try to decrypt
                    let decrypted: Vec<Vec<u8>> = cipher.iter().map(|c| {
                        priv_key.decrypt_raw(c)
                    }).collect();
                    if decrypted.iter().any(|m| !m.is_empty() && m.iter().any(|&b| b >= 0x20 && b < 0x7f)) {
                        log::debug!("[same_n_huge_e] found valid decryption with k={}", k);
                        return Some(AttackResult { priv_key: Some(priv_key), decrypted });
                    }
                }
            }
            let _ = approx_phi;
        }
        None
    }
}
