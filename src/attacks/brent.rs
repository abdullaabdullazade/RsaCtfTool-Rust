/// Brent's variant of Pollard Rho. Matches Python's brent() in algos.py.

use rug::Integer;
use rand::Rng;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct BrentAttack;

impl RsaAttack for BrentAttack {
    fn name(&self) -> &'static str { "brent" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        if n.clone() & 1u32 == 0 {
            return make_result(Integer::from(2u32), n.clone() / 2u32, &pub_key.e, n, cipher);
        }

        let mut rng = rand::thread_rng();
        let n_u64 = n.significant_bits() as u64;

        let mut g = n.clone();
        while g == *n {
            if abort.load(Ordering::Relaxed) { return None; }

            let y_val: u64 = rng.gen_range(1..n_u64.max(2));
            let c_val: u64 = rng.gen_range(1..n_u64.max(2));
            let m_val: u64 = rng.gen_range(1..n_u64.max(2));

            let mut y = Integer::from(y_val);
            let c = Integer::from(c_val);
            let m = Integer::from(m_val);

            g = Integer::from(1u32);
            let mut r = Integer::from(1u32);
            let mut q = Integer::from(1u32);
            let mut x = Integer::new();
            let mut ys = Integer::new();

            while g == 1 {
                if abort.load(Ordering::Relaxed) { return None; }
                x = y.clone();
                let mut i = Integer::new();
                while i <= r {
                    y = (y.clone() * &y + &c).modulo(n);
                    i += 1u32;
                }
                let mut k = Integer::new();
                while k < r && g == 1 {
                    if abort.load(Ordering::Relaxed) { return None; }
                    ys = y.clone();
                    let mut i = Integer::new();
                    let lim = {
                        let diff = r.clone() - &k;
                        if m < diff { m.clone() } else { diff }
                    };
                    while i <= lim {
                        y = (y.clone() * &y + &c).modulo(n);
                        let diff = if x > y { x.clone() - &y } else { y.clone() - &x };
                        q = (q * diff).modulo(n);
                        i += 1u32;
                    }
                    g = gcd(&q, n);
                    k += &m;
                }
                r <<= 1u32;
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
        }

        if g == *n || g == 1 { return None; }
        let q = n.clone() / &g;
        log::debug!("[brent] found p={}", &g);
        make_result(g, q, &pub_key.e, n, cipher)
    }
}
