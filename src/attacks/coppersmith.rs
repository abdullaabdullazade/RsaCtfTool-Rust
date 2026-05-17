use rug::{Float, Integer, ops::Pow};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

const FLOAT_PREC: u32 = 256;

#[derive(Default)]
pub struct CoppersmithAttack {
    pub partial_plaintext: Option<Integer>,
    pub unknown_bytes: Option<usize>,
}

// ---------------------------------------------------------------------------
// LLL (Lenstra–Lenstra–Lovász) over Integer basis
// ---------------------------------------------------------------------------

fn dot_float(a: &[Float], b: &[Float]) -> Float {
    let mut acc = Float::new(FLOAT_PREC);
    for (x, y) in a.iter().zip(b.iter()) { acc += x.clone() * y; }
    acc
}

fn gram_schmidt(basis: &[Vec<Integer>]) -> (Vec<Vec<Float>>, Vec<Float>) {
    let n = basis.len();
    let mut orth: Vec<Vec<Float>> = Vec::with_capacity(n);
    let mut mu = vec![vec![Float::new(FLOAT_PREC); n]; n];
    let mut dot_self: Vec<Float> = Vec::with_capacity(n);

    for i in 0..n {
        let mut bi: Vec<Float> = basis[i].iter()
            .map(|x| Float::with_val(FLOAT_PREC, x))
            .collect();

        for j in 0..i {
            let dot_ij = dot_float(&bi, &orth[j]);
            let ds = dot_self[j].clone();
            let mu_ij = dot_ij / &ds;
            mu[i][j] = mu_ij.clone();
            for k in 0..bi.len() {
                let sub = mu_ij.clone() * &orth[j][k];
                bi[k] -= &sub;
            }
        }
        let ds = dot_float(&bi, &bi);
        dot_self.push(ds);
        orth.push(bi);
    }
    (mu, dot_self)
}

fn lll_reduce(mut basis: Vec<Vec<Integer>>) -> Vec<Vec<Integer>> {
    let n = basis.len();
    if n <= 1 { return basis; }
    let mut k = 1usize;
    while k < n {
        let (mu, _) = gram_schmidt(&basis);
        for j in (0..k).rev() {
            let rounded = mu[k][j].clone().round();
            let r = rounded.to_integer().unwrap_or(Integer::new());
            if r != 0 {
                let sub: Vec<Integer> = basis[j].iter().map(|x| x.clone() * &r).collect();
                for i in 0..basis[k].len() { basis[k][i] -= &sub[i]; }
            }
        }
        let (mu2, ds2) = gram_schmidt(&basis);
        let delta = Float::with_val(FLOAT_PREC, 3u32) / Float::with_val(FLOAT_PREC, 4u32);
        let lhs = delta * &ds2[k - 1];
        let mu_sq = mu2[k][k - 1].clone().square();
        let rhs = ds2[k].clone() + mu_sq * &ds2[k - 1];
        if lhs > rhs {
            basis.swap(k, k - 1);
            k = k.saturating_sub(1);
        } else {
            k += 1;
        }
    }
    basis
}

// ---------------------------------------------------------------------------
// Polynomial helpers
// ---------------------------------------------------------------------------

fn poly_eval_mod(coeffs: &[Integer], val: &Integer, m: &Integer) -> Integer {
    let mut result = Integer::new();
    let mut power = Integer::from(1u32);
    for c in coeffs {
        result = (result + c.clone() * &power).modulo(m);
        power = (power * val).modulo(m);
    }
    result
}

fn poly_eval_z(coeffs: &[Integer], val: &Integer) -> Integer {
    let mut result = Integer::new();
    let mut power = Integer::from(1u32);
    for c in coeffs { result += c.clone() * &power; power *= val; }
    result
}

/// (m0 + x)^e - c mod n as a polynomial in x. Coefficients [a0..ae].
fn build_f_polynomial(m0: &Integer, e_val: u32, n: &Integer) -> Vec<Integer> {
    let e = e_val as usize;
    let mut binom = vec![Integer::from(1u32); e + 1];
    for i in 1..=e {
        binom[i] = binom[i - 1].clone() * Integer::from((e - i + 1) as u32)
            / Integer::from(i as u32);
    }
    let mut m0_pow = vec![Integer::from(1u32); e + 1];
    for i in 1..=e { m0_pow[i] = (m0_pow[i-1].clone() * m0).modulo(n); }
    let mut coeffs = vec![Integer::new(); e + 1];
    for k in 0..=e {
        coeffs[k] = (binom[k].clone() * &m0_pow[e - k]).modulo(n);
    }
    coeffs
}

fn howgrave_graham_lattice(f_coeffs: &[Integer], n: &Integer, x_bound: &Integer) -> Vec<Vec<Integer>> {
    let e = f_coeffs.len();
    let mut lattice = vec![vec![Integer::new(); e]; e];
    let mut x_power = Integer::from(1u32);
    for row in 0..(e - 1) {
        lattice[row][row] = n.clone() * &x_power;
        x_power *= x_bound;
    }
    x_power = Integer::from(1u32);
    for j in 0..e {
        lattice[e - 1][j] = f_coeffs[j].clone() * &x_power;
        x_power *= x_bound;
    }
    lattice
}

fn extract_polynomial(reduced: &[Vec<Integer>], x_bound: &Integer) -> Vec<Integer> {
    let row = &reduced[0];
    let mut coeffs = Vec::with_capacity(row.len());
    let mut x_power = Integer::from(1u32);
    for j in 0..row.len() {
        let (c, rem) = row[j].clone().div_rem(x_power.clone());
        coeffs.push(if rem == 0 { c } else { row[j].clone() });
        x_power *= x_bound;
    }
    coeffs
}

fn find_integer_root_newton(
    coeffs: &[Integer],
    bound: &Integer,
    n: &Integer,
    abort: &Arc<AtomicBool>,
) -> Option<Integer> {
    if bound.significant_bits() < 24 {
        let mut x = Integer::new();
        while x <= *bound {
            if abort.load(Ordering::Relaxed) { return None; }
            if poly_eval_mod(coeffs, &x, n) == 0 { return Some(x); }
            x += 1u32;
        }
        return None;
    }
    // Newton-Raphson over Z
    let mut x = Integer::new();
    for _ in 0..200 {
        if abort.load(Ordering::Relaxed) { return None; }
        let fx = poly_eval_z(coeffs, &x);
        if fx == 0 { return Some(x); }
        let mut dfx = Integer::new();
        let mut power = Integer::from(1u32);
        for (i, c) in coeffs.iter().enumerate().skip(1) {
            dfx += Integer::from(i as u32) * c * &power;
            power *= &x;
        }
        if dfx == 0 { break; }
        let (step, _) = fx.div_rem(dfx);
        if step == 0 { break; }
        x -= step;
    }
    for delta in [-1i32, 0, 1] {
        let candidate = x.clone() + Integer::from(delta);
        if candidate >= 0 && poly_eval_mod(coeffs, &candidate, n) == 0 {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Attack
// ---------------------------------------------------------------------------

impl RsaAttack for CoppersmithAttack {
    fn name(&self) -> &'static str { "coppersmith" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        use rug::integer::Order;

        if cipher.is_empty() { return None; }

        let n = &pub_key.n;
        let e = &pub_key.e;
        let e_val = e.to_u32()?;
        if e_val > 64 {
            log::debug!("[coppersmith] e={} too large, skipping", e_val);
            return None;
        }

        let m0 = self.partial_plaintext.clone().unwrap_or_else(Integer::new);

        let x_bound = match self.unknown_bytes {
            Some(ub) => Integer::from(1u32) << (ub * 8) as u32,
            None => {
                let n_float = Float::with_val(FLOAT_PREC, n);
                let exp = 1.0f64 / e_val as f64;
                let root = n_float.pow(exp as f32);
                root.to_integer().unwrap_or_else(Integer::new)
            }
        };

        let mut results = vec![];
        for c_bytes in cipher {
            let ciphertext = Integer::from_digits(c_bytes, Order::MsfBe);
            let mut f_coeffs = build_f_polynomial(&m0, e_val, n);
            f_coeffs[0] = (f_coeffs[0].clone() - &ciphertext).modulo(n);

            let lattice = howgrave_graham_lattice(&f_coeffs, n, &x_bound);
            let reduced = lll_reduce(lattice);
            let poly = extract_polynomial(&reduced, &x_bound);

            if let Some(x0) = find_integer_root_newton(&poly, &x_bound, n, abort) {
                let plaintext = m0.clone() + &x0;
                log::debug!("[coppersmith] plaintext={}", &plaintext);
                results.push(plaintext.to_digits::<u8>(Order::MsfBe));
            } else {
                return None;
            }
        }

        if results.is_empty() { return None; }
        Some(AttackResult { priv_key: None, decrypted: results })
    }
}
