use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, is_square, gcd};
use crate::key::PublicKey;

pub struct HartAttack;

impl RsaAttack for HartAttack {
    fn name(&self) -> &'static str { "hart" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let mut i = Integer::from(1u32);
        loop {
            if abort.load(Ordering::Relaxed) { return None; }

            // s = isqrt(n * i) + 1
            let ni = n.clone() * &i;
            let s = ni.sqrt() + 1u32;
            let pow_mod = (s.clone() * &s).modulo(n);

            if let Some(t) = is_square(&pow_mod) {
                let g = gcd(&(s.clone() - &t), n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    log::debug!("[hart] found factor={}", &g);
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }

            i += 1u32;

            // Bail out after reasonable iterations
            if i > 1_000_000u32 {
                return None;
            }
        }
    }
}
