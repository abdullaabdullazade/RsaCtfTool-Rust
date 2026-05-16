/// Pisano-period factorization: finds phi via 2^x mod N - 1 approximation.
/// Matches Python's pisano_period attack. Practical only for n ≤ ~80 bits.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;
use crate::math::factor_from_n_phi;

pub struct PisanoPeriodAttack;

/// f(x) = 2^x mod N - 1  (Python's "mersenne" shortcut)
fn fib_approx(x: &Integer, n: &Integer) -> Integer {
    match Integer::from(2u32).pow_mod(x, n) {
        Ok(r) => (r - Integer::from(1u32)).modulo(n),
        Err(_) => Integer::new(),
    }
}

impl RsaAttack for PisanoPeriodAttack {
    fn name(&self) -> &'static str { "pisano_period" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let bits = n.significant_bits();

        // Only practical for small n (≤ ~80 bits)
        if bits > 85 { return None; }

        // Baby-step table size: n^(1/6) / 100, bounded to [200, 20_000]
        let search_len: u64 = {
            let est = (bits as f64 / 6.0 / 100.0).exp2() as u64;
            est.clamp(200, 20_000)
        };

        // Baby-step table: { f(x) → x } for x in [0, search_len)
        let mut look_up: HashMap<Integer, Integer> = HashMap::new();
        for x in 0u64..search_len {
            if abort.load(Ordering::Relaxed) { return None; }
            let xi = Integer::from(x);
            let val = fib_approx(&xi, n);
            look_up.insert(val, xi);
        }

        // Giant-step range: search near [n - p_len, n + p_len]
        // p_len = 10^((ilog10(n) + xdiff)/2 + 1) where xdiff=0
        let ilog10_n = n.to_string().len() as u32;
        let p_len_exp = (ilog10_n / 2) + 1;
        let p_len: u64 = 10u64.saturating_pow(p_len_exp).min(1_000_000_000);

        let begin = if n.to_u64().unwrap_or(u64::MAX) > p_len + search_len {
            n.to_u64().unwrap_or(0).saturating_sub(p_len)
        } else {
            search_len
        };
        let end = n.to_u64().unwrap_or(u64::MAX).saturating_add(p_len);

        // Cap total iterations at 100k to avoid hanging on large n
        let max_iters = 100_000u64;
        let step = ((end - begin) / max_iters).max(1);

        let mut randi = begin;
        let mut iters = 0u64;
        while randi <= end && iters < max_iters {
            if abort.load(Ordering::Relaxed) { return None; }
            iters += 1;
            let randi_int = Integer::from(randi);
            let res = fib_approx(&randi_int, n);
            if res > 0 {
                if let Some(res_n) = look_up.get(&res) {
                    let res_n_u64 = res_n.to_u64().unwrap_or(u64::MAX);
                    if randi > res_n_u64 {
                        let phi_guess = Integer::from(randi - res_n_u64);
                        if phi_guess.clone() & Integer::from(1u32) == 0 {
                            let check = fib_approx(&phi_guess, n);
                            if check == 0 {
                                if let Some((p, q)) = factor_from_n_phi(n, &phi_guess) {
                                    if p > 1 && q > 1 {
                                        log::debug!("[pisano_period] found factor");
                                        return make_result(p, q, &pub_key.e, n, cipher);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            randi = randi.saturating_add(step);
        }
        None
    }
}
