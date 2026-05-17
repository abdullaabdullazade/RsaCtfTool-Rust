use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, is_square};
use crate::key::PublicKey;

pub struct FermatAttack;

impl RsaAttack for FermatAttack {
    fn name(&self) -> &'static str { "fermat" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        // Python checks: if (n - 2) & 3 == 0 → n ≡ 2 (mod 4) → raise FactorizationError
        if (n.clone() - 2u32).modulo(&Integer::from(4u32)) == 0 {
            log::error!("N should not be a 4k+2 number...");
            return None;
        }

        let (mut a, rem) = n.clone().sqrt_rem(Integer::new());
        // a = ceil(sqrt(n))
        if rem != 0 { a += 1u32; }

        // b2 tracks a^2 - n, incremented via c (= 2a+1)
        let mut b2 = a.clone() * &a - n;
        let mut c = (a.clone() << 1) + 1u32; // 2a + 1

        const MAX_ITER: u64 = 1_000_000;
        for _ in 0..MAX_ITER {
            if abort.load(Ordering::Relaxed) { return None; }

            if let Some(b) = is_square(&b2) {
                let p = a.clone() - &b;
                let q = a.clone() + &b;
                if p > 1 && q > 1 && p.clone() * &q == *n {
                    log::debug!("[fermat] p={}, q={}", &p, &q);
                    return make_result(p, q, &pub_key.e, n, cipher);
                }
            }

            b2 += &c;
            c += 2u32;
        }

        None
    }
}
