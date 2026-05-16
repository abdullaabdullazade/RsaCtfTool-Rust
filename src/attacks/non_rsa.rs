/// nonRSA attack: detects prime power moduli n = p^k, recovers p.
/// Matches Python's nonRSA() in algos.py.


use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;
use crate::math::{iroot, is_prime};

pub struct NonRsaAttack;

impl RsaAttack for NonRsaAttack {
    fn name(&self) -> &'static str { "nonRSA" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let bits = n.significant_bits() as u32;

        // Try n = p^k for k = 2..log2(n)
        for k in 2..=bits {
            let (root, exact) = iroot(n, k);
            if exact && is_prime(&root) {
                // n = root^k — this is a prime power, not a semiprime
                // For RSA purposes: if n = p^2, then p is the factor
                // We treat it as p * p^(k-1)
                let p = root;
                let q = n.clone() / &p;
                log::debug!("[nonRSA] found n = p^{}: p={}", k, &p);
                return make_result(p, q, &pub_key.e, n, cipher);
            }
            if root == 1 { break; }
        }
        None
    }
}
