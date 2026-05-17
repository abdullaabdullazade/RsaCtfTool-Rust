use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::attacks::brent::brent_factor;
use crate::key::PublicKey;

pub struct SqUfOfAttack;

const MULTIPLIERS: &[u32] = &[
    1, 3, 5, 7, 11, 15, 21, 33, 35, 55, 77, 105, 165, 231, 385, 1155,
];

#[inline]
fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

#[inline]
fn isqrt_u128(n: u128) -> u128 {
    if n < 2 { return n; }
    let bits = 128 - n.leading_zeros() as u32;
    let mut lo = 1u128;
    let mut hi = (1u128 << ((bits + 1) / 2)) + 1;
    while lo + 1 < hi {
        let mid = (lo + hi) >> 1;
        let sq = mid.saturating_mul(mid);
        if sq == n {
            return mid;
        } else if sq < n {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

fn squfof_u128(n: u128, abort: &Arc<AtomicBool>) -> Option<u128> {
    if ((n.wrapping_sub(2)) & 3) == 0 {
        return None;
    }

    let s = isqrt_u128(n);
    let l = isqrt_u128(s << 1) << 1;
    let b = 3u128.saturating_mul(l);
    let b_cap = b.min(300_000);

    for &mult in MULTIPLIERS {
        if abort.load(Ordering::Relaxed) { return None; }

        let d = n.checked_mul(mult as u128)?;
        let po = isqrt_u128(d);
        let mut pprev = po;
        let mut p = po;
        let mut qprev = 1u128;
        let mut q = d.saturating_sub(po.saturating_mul(po));
        if q == 0 { continue; }

        let mut r = 0u128;
        let mut found = false;
        let mut i = 2u128;
        while i <= b_cap {
            if abort.load(Ordering::Relaxed) { return None; }
            let bk = (po + p) / q;
            p = bk.saturating_mul(q).saturating_sub(p);
            let q_old = q;
            q = qprev + bk.saturating_mul(pprev.saturating_sub(p));
            let rr = isqrt_u128(q);
            if (i & 1) == 0 && rr.saturating_mul(rr) == q {
                r = rr;
                found = true;
                break;
            }
            pprev = p;
            qprev = q_old;
            i += 1;
        }
        if !found || r == 0 { continue; }

        let bk = (po.saturating_sub(p)) / r;
        pprev = bk.saturating_mul(r).saturating_add(p);
        p = pprev;
        qprev = r;
        let p2 = pprev.saturating_mul(pprev);
        if p2 > d { continue; }
        q = (d - p2) / qprev;
        if q == 0 { continue; }

        let mut guard = 0u64;
        let mut cont = true;
        while cont {
            if abort.load(Ordering::Relaxed) { return None; }
            if q == 0 || guard > 1_000_000 { break; }
            guard += 1;
            let bk = (po + p) / q;
            pprev = p;
            p = bk.saturating_mul(q).saturating_sub(p);
            let q_old = q;
            q = qprev + bk.saturating_mul(pprev.saturating_sub(p));
            qprev = q_old;
            cont = p != pprev;
        }

        let g = gcd_u128(n, qprev);
        if g > 1 && g < n {
            return Some(g);
        }
    }
    None
}

impl RsaAttack for SqUfOfAttack {
    fn name(&self) -> &'static str { "SQUFOF" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        // Fast path: for moduli that fit in u128, use a tight integer implementation.
        if let Some(n_u) = n.to_u128() {
            if let Some(f_u) = squfof_u128(n_u, abort) {
                let factor = Integer::from(f_u);
                let other = n.clone() / &factor;
                return make_result(factor, other, &pub_key.e, n, cipher);
            }
            if let Some(factor) = brent_factor(n, abort) {
                if factor > 1 && factor < *n {
                    let other = n.clone() / &factor;
                    return make_result(factor, other, &pub_key.e, n, cipher);
                }
            }
            // For <=128-bit inputs, avoid dropping into very slow big-int SQUFOF paths.
            return None;
        }

        if n.clone().modulo(&Integer::from(4u32)) == 2 { return None; }

        // Reference: RsaCtfTool's SQUFOF in lib/algos.py
        let s = n.clone().sqrt();
        let l = (s << 1u32).sqrt() << 1u32;
        let b = Integer::from(3u32) * &l;
        let b_u64 = b.to_u64().unwrap_or(u64::MAX);

        for &mult in MULTIPLIERS {
            if abort.load(Ordering::Relaxed) { return None; }

            let d = n.clone() * mult;
            let po = d.clone().sqrt();
            let mut pprev = po.clone();
            let mut p = po.clone();
            let mut qprev = Integer::from(1u32);
            let mut q = d.clone() - &po * &po;
            if q == 0 { continue; }

            let mut r_opt: Option<Integer> = None;
            for i in 2u64..=b_u64 {
                if abort.load(Ordering::Relaxed) { return None; }
                let bk = (po.clone() + &p) / &q;
                let new_p = bk.clone() * &q - &p;
                let q_old = q.clone();
                let new_q = qprev.clone() + bk * (pprev.clone() - &new_p);
                let r = new_q.clone().sqrt();

                p = new_p;
                q = new_q;

                if i % 2 == 0 && r.clone() * &r == q {
                    r_opt = Some(r);
                    break;
                }
                pprev = p.clone();
                qprev = q_old;
            }

            let Some(r) = r_opt else { continue };

            let bk = (po.clone() - &p) / &r;
            pprev = bk * &r + &p;
            p = pprev.clone();
            qprev = r.clone();
            let pp2 = pprev.clone() * &pprev;
            if pp2 > d { continue; }
            q = (d.clone() - pp2) / &qprev;

            let mut guard = 0u64;
            while p != pprev || guard == 0 {
                if abort.load(Ordering::Relaxed) { return None; }
                if q == 0 || guard > 1_000_000 { break; }
                guard += 1;
                let bk = (po.clone() + &p) / &q;
                let prev_p = p.clone();
                let new_p = bk.clone() * &q - &p;
                let q_old = q.clone();
                let new_q = qprev.clone() + bk * (prev_p.clone() - &new_p);
                pprev = prev_p;
                p = new_p;
                q = new_q;
                qprev = q_old;
            }

            let factor = gcd(n, &qprev);
            if factor > 1 && factor < *n {
                let other = n.clone() / &factor;
                log::debug!("[SQUFOF] found factor={}", &factor);
                return make_result(factor, other, &pub_key.e, n, cipher);
            }
        }
        None
    }
}
