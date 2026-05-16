/// multiple_base_inversion_gcd: GCD of digit-reversed representations of n^k.
/// Matches Python's multiple_base_inversion_gcd attack.

use rug::{Integer, ops::Pow};
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;

pub struct MultipleBaseInversionGcdAttack;

fn reverse_decimal(n: &Integer) -> Integer {
    let s: String = n.to_string().chars().rev().collect();
    Integer::parse(&s).map(Integer::from).unwrap_or_else(|_| Integer::new())
}

fn reverse_binary(n: &Integer) -> Integer {
    let bits = n.significant_bits();
    let mut result = Integer::new();
    for i in 0..bits {
        if n.get_bit(i) {
            result.set_bit(bits - 1 - i, true);
        }
    }
    result
}

fn reverse_hex(n: &Integer) -> Integer {
    let s = format!("{:x}", n);
    let rev: String = s.chars().rev().collect();
    Integer::parse_radix(&rev, 16).map(Integer::from).unwrap_or_else(|_| Integer::new())
}

impl RsaAttack for MultipleBaseInversionGcdAttack {
    fn name(&self) -> &'static str { "multiple_base_inversion_gcd" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        for p in 1u32..=5 {
            let np = n.clone().pow(p);
            for candidate in [
                reverse_decimal(&np),
                reverse_binary(&np),
                reverse_hex(&np),
            ] {
                if candidate < 2 { continue; }
                let g = gcd(&candidate, n);
                if g > 1 && g < *n {
                    let q = n.clone() / &g;
                    log::debug!("[multiple_base_inversion_gcd] found factor");
                    return make_result(g, q, &pub_key.e, n, cipher);
                }
            }
        }
        None
    }
}
