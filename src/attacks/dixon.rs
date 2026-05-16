/// Dixon's random squares factorization. Matches Python's dixon() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd, primes_up_to, isqrt};
use crate::key::PublicKey;

pub struct DixonAttack;

impl RsaAttack for DixonAttack {
    fn name(&self) -> &'static str { "dixon" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        let bound = 200usize;
        let factor_base: Vec<Integer> = primes_up_to(bound + 100)
            .into_iter()
            .take(bound)
            .map(Integer::from)
            .collect();

        let mut relations: Vec<(Integer, Vec<i32>)> = Vec::new();
        let mut x = isqrt(n) + Integer::from(1u32);

        let max_iter = 10_000u64;
        for _ in 0..max_iter {
            if abort.load(Ordering::Relaxed) { return None; }

            let x2 = x.clone() * &x;
            let mut rem = x2.clone().modulo(n);

            let mut exponents = vec![0i32; factor_base.len()];
            let mut smooth = true;

            for (i, p) in factor_base.iter().enumerate() {
                while rem.clone().modulo(p) == 0 {
                    rem /= p;
                    exponents[i] += 1;
                }
            }

            if rem == 1 {
                relations.push((x.clone(), exponents));

                if relations.len() >= bound + 20 {
                    // Gaussian elimination over GF(2) to find a linear dependency
                    if let Some(factor) = find_factor_gauss(n, &relations) {
                        if factor > 1 && factor < *n {
                            let q = n.clone() / &factor;
                            log::debug!("[dixon] found factor={}", &factor);
                            return make_result(factor, q, &pub_key.e, n, cipher);
                        }
                    }
                    relations.clear();
                }
            } else {
                smooth = false;
            }
            let _ = smooth;

            x += Integer::from(1u32);
        }
        None
    }
}

fn find_factor_gauss(n: &Integer, relations: &[(Integer, Vec<i32>)]) -> Option<Integer> {
    let m = relations.len();
    let k = relations[0].1.len();

    // Build matrix of parities
    let mut matrix: Vec<Vec<u8>> = relations.iter()
        .map(|(_, exp)| exp.iter().map(|&e| (e % 2) as u8).collect())
        .collect();

    let mut pivot_row = vec![0usize; k];
    let mut used = vec![false; m];

    for col in 0..k {
        let pivot = (0..m).find(|&r| !used[r] && matrix[r][col] == 1)?;
        used[pivot] = true;
        pivot_row[col] = pivot;
        for r in 0..m {
            if r != pivot && matrix[r][col] == 1 {
                for c in 0..k {
                    matrix[r][c] ^= matrix[pivot][c];
                }
            }
        }
    }

    // Find zero rows (linear dependency)
    for r in 0..m {
        if matrix[r].iter().all(|&x| x == 0) {
            // Use this relation to find a factor
            let x_prod = relations.iter().enumerate()
                .filter(|(_, (_, exp))| exp.iter().all(|&e| e == 0))
                .fold(Integer::from(1u32), |acc, (_, (x, _))| {
                    (acc * x).modulo(n)
                });

            // Compute y from the full exponent vector
            let mut y_sq = Integer::from(1u32);
            for (xi, expi) in relations.iter() {
                if expi.iter().all(|&e| e % 2 == 0) {
                    let xi_sq = xi.clone() * xi;
                    y_sq = (y_sq * xi_sq).modulo(n);
                }
            }
            let y = y_sq.clone().sqrt();

            let diff = if x_prod > y {
                x_prod.clone() - &y
            } else {
                y.clone() - &x_prod
            };
            let g = gcd(&diff, n);
            if g > 1 && g < *n {
                return Some(g);
            }
        }
    }
    None
}
