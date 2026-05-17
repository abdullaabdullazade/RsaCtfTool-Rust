use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;

pub struct NoveltyPrimesAttack;

impl RsaAttack for NoveltyPrimesAttack {
    fn name(&self) -> &'static str { "noveltyprimes" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let max_len = 25usize;
        for i in 0..(max_len - 4) {
            // prime = int("3133" + "3"*i + "7")
            let s = format!("3133{}7", "3".repeat(i));
            let prime = Integer::parse(&s).map(Integer::from).ok()?;
            if n.clone().modulo(&prime) == 0 {
                let q = n.clone() / &prime;
                log::debug!("[noveltyprimes] found p={}", &prime);
                return make_result(prime, q, &pub_key.e, n, cipher);
            }
        }
        None
    }
}
