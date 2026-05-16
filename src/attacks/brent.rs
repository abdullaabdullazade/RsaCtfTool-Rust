/// Brent's variant of Pollard Rho. Matches Python's brent() in algos.py.

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
    let max_attempts = if n.significant_bits() <= 128 { 48 } else { 12 };
    let max_steps: u64 = 400_000;
    for _attempt in 0..max_attempts {
        if abort.load(Ordering::Relaxed) { return None; }

        let n_minus_1 = n.clone() - 1u32;
        let y = Integer::from(rng.gen::<u64>()).modulo(&n_minus_1) + 1u32;
        let c = Integer::from(rng.gen::<u64>()).modulo(&n_minus_1) + 1u32;
        let m_u: u64 = (rng.gen::<u32>() as u64 % 128) + 16;

        let mut g = Integer::from(1u32);
        let mut r: u64 = 1;
        let mut q = Integer::from(1u32);
        let mut x = Integer::new();
        let mut ys = Integer::new();
        let mut y_cur = y;
        let mut steps: u64 = 0;

        while g == 1 {
            if abort.load(Ordering::Relaxed) { return None; }
            if steps > max_steps { break; }
            x = y_cur.clone();
            for _ in 0..=r {
                y_cur = (y_cur.clone() * &y_cur + &c).modulo(n);
                steps += 1;
            }
            let mut k: u64 = 0;
            while k < r && g == 1 {
                if abort.load(Ordering::Relaxed) { return None; }
                if steps > max_steps { break; }
                ys = y_cur.clone();
                let lim = m_u.min(r - k);
                for _ in 0..=lim {
                    y_cur = (y_cur.clone() * &y_cur + &c).modulo(n);
                    let diff = if x > y_cur { x.clone() - &y_cur } else { y_cur.clone() - &x };
                    q = (q * diff).modulo(n);
                    steps += 1;
                }
                g = gcd(&q, n);
                k += m_u;
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
                steps += 1;
                if steps > max_steps { break; }
            }
        }

        if g > 1 && g < *n {
            return Some(g);
        }
    }

    None
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
