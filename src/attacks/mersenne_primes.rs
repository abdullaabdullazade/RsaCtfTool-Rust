use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;

pub struct MersennePrimesAttack;

const MERSENNE_EXPONENTS: &[u32] = &[
    2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279,
    2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213, 19937, 21701,
    23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433,
    1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20336011,
    24036583, 25964951, 30402457, 32582657, 37156667, 42643801, 43112609,
];

impl RsaAttack for MersennePrimesAttack {
    fn name(&self) -> &'static str { "mersenne_primes" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        for &exp in MERSENNE_EXPONENTS {
            // m = 2^exp - 1
            let m = (Integer::from(1u32) << exp) - Integer::from(1u32);
            if m > *n { break; }
            if n.clone().modulo(&m) == 0 {
                let q = n.clone() / &m;
                if q > 1 && m > 1 {
                    log::debug!("[mersenne_primes] found Mersenne prime 2^{}-1", exp);
                    return make_result(m, q, &pub_key.e, n, cipher);
                }
            }
        }
        None
    }
}
