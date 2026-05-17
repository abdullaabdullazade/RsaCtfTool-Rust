use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, primes_up_to};
use crate::key::PublicKey;

pub struct SmallqAttack;

impl RsaAttack for SmallqAttack {
    fn name(&self) -> &'static str { "smallq" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        for prime in primes_up_to(100_000) {
            if abort.load(Ordering::Relaxed) { return None; }
            let p = Integer::from(prime);
            if pub_key.n.clone().modulo(&p) == 0 {
                let q = pub_key.n.clone() / &p;
                log::debug!("[smallq] found p={}", p);
                return make_result(p, q, &pub_key.e, &pub_key.n, cipher);
            }
        }
        None
    }
}
