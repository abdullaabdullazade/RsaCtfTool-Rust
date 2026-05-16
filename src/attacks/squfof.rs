/// SQUFOF (Shanks' Square Forms Factorization). Matches Python's SQUFOF() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct SqUfOfAttack;

const MULTIPLIERS: &[u32] = &[
    1, 3, 5, 7, 11, 15, 21, 33, 35, 55, 77, 105, 165, 231, 385,
];

impl RsaAttack for SqUfOfAttack {
    fn name(&self) -> &'static str { "SQUFOF" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        if n.clone().modulo(&Integer::from(4u32)) == 2 { return None; }

        let s = n.clone().sqrt();
        let l = (Integer::from(2u32) * &s).sqrt() * 2u32;
        let b = Integer::from(3u32) * &l;

        for &mult in MULTIPLIERS {
            if abort.load(Ordering::Relaxed) { return None; }

            let d = n.clone() * mult;
            let po = d.clone().sqrt();
            let mut pprev = po.clone();
            let mut p = po.clone();
            let mut qprev = Integer::from(1u32);
            let mut q = d.clone() - &po * &po;

            let mut found = false;
            let mut r_val = Integer::new();

            for i in 2u64..b.to_u64().unwrap_or(10000) + 1 {
                if abort.load(Ordering::Relaxed) { return None; }
                let bk = (po.clone() + &p) / &q;
                let new_p = bk.clone() * &q - &p;
                let q_prev_tmp = q.clone();
                q = qprev.clone() + bk.clone() * (pprev.clone() - &new_p);
                pprev = p;
                qprev = q_prev_tmp;
                p = new_p;

                if q < 0 { break; }
                let r = q.clone().sqrt();
                if i % 2 == 0 && r.clone() * &r == q {
                    r_val = r;
                    found = true;
                    break;
                }
            }

            if !found { continue; }

            let bk = (po.clone() + &p) / &r_val;
            let _ = p.clone(); // pprev not used after phase-2 init
            p = bk.clone() * &r_val - &p;
            let mut q_tmp = r_val.clone();
            let pp2 = p.clone() * &p;
            if pp2 > d { continue; }
            q = (d.clone() - pp2) / &q_tmp;

            let mut iter2 = 0u64;
            loop {
                if abort.load(Ordering::Relaxed) { return None; }
                if q == 0 || iter2 > 100_000 { break; }
                iter2 += 1;
                let bk = (po.clone() + &p) / &q;
                pprev = p.clone();
                p = bk.clone() * &q - &p;
                let q_old = q.clone();
                q = q_tmp.clone() + bk * (pprev.clone() - &p);
                q_tmp = q_old;
                if p == pprev { break; }
            }

            let factor = gcd(n, &q_tmp);
            if factor > 1 && factor < *n {
                let other = n.clone() / &factor;
                log::debug!("[SQUFOF] found factor={}", &factor);
                return make_result(factor, other, &pub_key.e, n, cipher);
            }
        }
        None
    }
}
