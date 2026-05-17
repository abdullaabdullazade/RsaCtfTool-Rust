use rug::Integer;
use rand::Rng;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct BrentAttack;

pub fn brent_factor(n: &Integer, abort: &Arc<AtomicBool>) -> Option<Integer> {
    if n.clone() & 1u32 == 0 {
        return Some(Integer::from(2u32));
    }
    let mut rng = rand::thread_rng();
    let n_m1 = n.clone() - 1u32;

    loop {
        if abort.load(Ordering::Relaxed) { return None; }
        let mut y = Integer::from(rng.gen::<u64>()).modulo(&n_m1) + 1u32;
        let c = Integer::from(rng.gen::<u64>()).modulo(&n_m1) + 1u32;
        let m = (rng.gen::<u32>() as u64 % 128) + 16;

        let mut g = Integer::from(1u32);
        let mut r: u64 = 1;
        let mut q = Integer::from(1u32);
        let mut x = Integer::new();
        let mut ys = Integer::new();

        while g == 1 {
            if abort.load(Ordering::Relaxed) { return None; }
            x = y.clone();
            for _ in 0..r {
                y = (y.clone() * &y + &c).modulo(n);
            }
            let mut k: u64 = 0;
            while k < r && g == 1 {
                if abort.load(Ordering::Relaxed) { return None; }
                ys = y.clone();
                let lim = m.min(r - k);
                for _ in 0..lim {
                    y = (y.clone() * &y + &c).modulo(n);
                    let diff = if x > y { x.clone() - &y } else { y.clone() - &x };
                    q = (q * diff).modulo(n);
                }
                g = gcd(&q, n);
                k += m;
            }
            r <<= 1;
        }

        if g == *n {
            loop {
                if abort.load(Ordering::Relaxed) { return None; }
                ys = (ys.clone() * &ys + &c).modulo(n);
                let diff = if x > ys { x.clone() - &ys } else { ys.clone() - &x };
                g = gcd(&diff, n);
                if g > 1 { break; }
            }
        }

        if g > 1 && g < *n {
            return Some(g);
        }
    }
}

impl RsaAttack for BrentAttack {
    fn name(&self) -> &'static str { "brent" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let g = brent_factor(n, abort)?;
        let q = n.clone() / &g;
        log::debug!("[brent] found p={}", &g);
        make_result(g, q, &pub_key.e, n, cipher)
    }
}
