use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct ComfactCnAttack;

impl RsaAttack for ComfactCnAttack {
    fn name(&self) -> &'static str { "comfact_cn" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        for c_bytes in cipher {
            if c_bytes.is_empty() { continue; }
            let c = Integer::from_digits(c_bytes, rug::integer::Order::Msf);
            let g = gcd(&c, n);
            if g > 1 && g < *n {
                let q = n.clone() / &g;
                log::debug!("[comfact_cn] found factor from GCD(c,n)={}", &g);
                return make_result(g, q, &pub_key.e, n, cipher);
            }
        }
        None
    }
}
