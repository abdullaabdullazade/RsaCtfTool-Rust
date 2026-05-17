use rug::{Integer, ops::Pow};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;
use crate::math::factor_from_n_phi;

pub struct PisanoPeriodAttack;

fn pow2_sub1(x: &Integer, n: &Integer) -> Integer {
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

        let search_len: u64 = ((bits as f64 / 6.0 / 100.0).exp2() as u64).clamp(200, 20_000);

        let mut look_up: HashMap<Integer, Integer> = HashMap::new();
        for x in 0u64..search_len {
            if abort.load(Ordering::Relaxed) { return None; }
            let xi = Integer::from(x);
            look_up.insert(pow2_sub1(&xi, n), xi);
        }

        let ilog10_n = n.to_string().len() as u32;
        let p_len_exp = (ilog10_n / 2 + 1).min(18);
        let p_len = Integer::from(10u64).pow(p_len_exp);

        let begin = if n.clone() > p_len.clone() + Integer::from(search_len) {
            n.clone() - &p_len
        } else {
            Integer::from(search_len)
        };
        let end = n.clone() + &p_len;

        let mut randi = begin;
        while randi <= end {
            if abort.load(Ordering::Relaxed) { return None; }
            let res = pow2_sub1(&randi, n);
            if res > 0 {
                if let Some(res_n) = look_up.get(&res) {
                    if randi > *res_n {
                        let phi_guess = randi.clone() - res_n;
                        if phi_guess.clone() & 1u32 == 0 && pow2_sub1(&phi_guess, n) == 0 {
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
            randi += 1u32;
        }
        None
    }
}
