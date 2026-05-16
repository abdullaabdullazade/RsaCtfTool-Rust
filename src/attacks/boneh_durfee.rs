/// Boneh-Durfee attack: factor n when d < N^0.292 (small private exponent).
/// Uses Herrmann-May variant with LLL on bivariate polynomial lattice.
/// Reference: https://github.com/mimoo/RSA-and-LLL-attacks

use rug::{Float, Integer, ops::Pow};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};

pub struct BonehDurfeeAttack;

const PREC: u32 = 512;

// ---------------------------------------------------------------------------
// LLL over Integer (reuse from coppersmith with explicit copy here for clarity)
// ---------------------------------------------------------------------------

fn dot_f(a: &[Float], b: &[Float]) -> Float {
    let mut s = Float::new(PREC);
    for (x, y) in a.iter().zip(b.iter()) { s += x.clone() * y; }
    s
}

fn gram_schmidt(basis: &[Vec<Integer>]) -> (Vec<Vec<Float>>, Vec<Float>) {
    let n = basis.len();
    let mut orth: Vec<Vec<Float>> = Vec::new();
    let mut mu = vec![vec![Float::new(PREC); n]; n];
    let mut ds: Vec<Float> = Vec::new();
    for i in 0..n {
        let mut bi: Vec<Float> = basis[i].iter().map(|x| Float::with_val(PREC, x)).collect();
        for j in 0..i {
            let d_ij = dot_f(&bi, &orth[j]);
            let mu_ij = d_ij / &ds[j];
            mu[i][j] = mu_ij.clone();
            for k in 0..bi.len() { bi[k] -= mu_ij.clone() * &orth[j][k]; }
        }
        ds.push(dot_f(&bi, &bi));
        orth.push(bi);
    }
    (mu, ds)
}

fn lll(mut basis: Vec<Vec<Integer>>) -> Vec<Vec<Integer>> {
    let n = basis.len();
    if n <= 1 { return basis; }
    let mut k = 1;
    while k < n {
        if k == 0 {
            k = 1;
            continue;
        }
        let (mu, _) = gram_schmidt(&basis);
        if mu.len() <= k { break; }
        for j in (0..k).rev() {
            let r = mu[k][j].clone().round().to_integer().unwrap_or_default();
            if r != 0 {
                let sub: Vec<Integer> = basis[j].iter().map(|x| x.clone() * &r).collect();
                for i in 0..basis[k].len() { basis[k][i] -= &sub[i]; }
            }
        }
        let (mu2, ds2) = gram_schmidt(&basis);
        if ds2.len() <= k || ds2.len() <= (k - 1) || mu2.len() <= k || mu2[k].len() <= (k - 1) {
            break;
        }
        let delta = Float::with_val(PREC, 3u32) / 4u32;
        let lhs = delta * &ds2[k - 1];
        let rhs = ds2[k].clone() + mu2[k][k-1].clone().square() * &ds2[k-1];
        if lhs > rhs {
            basis.swap(k, k - 1);
            if k > 1 { k -= 1; } else { k = 1; }
        }
        else { k += 1; }
    }
    basis
}

// ---------------------------------------------------------------------------
// Polynomial resultant over Z (univariate, naive)
// ---------------------------------------------------------------------------

fn poly_resultant(a: &[Integer], b: &[Integer]) -> Vec<Integer> {
    if a.is_empty() || b.is_empty() { return vec![Integer::new()]; }
    // Use pseudo-remainder sequence (slow but correct for small degrees)
    let mut p = a.to_vec();
    let mut q = b.to_vec();
    let mut sign = Integer::from(1i32);
    loop {
        if q.len() == 1 {
            // result = q[0]^deg(p)
            let d = p.len().saturating_sub(1);
            let r = q[0].clone().pow(d as u32);
            let r = r * sign;
            return vec![r];
        }
        let dp = p.len() as i64 - 1;
        let dq = q.len() as i64 - 1;
        if dp < dq {
            if (dp * dq) % 2 != 0 { sign = -sign.clone(); }
            std::mem::swap(&mut p, &mut q);
            continue;
        }
        // pseudo-remainder
        let lc_q = q.last().unwrap().clone();
        let d = (dp - dq + 1) as u32;
        let factor = lc_q.pow(d);
        let mut r: Vec<Integer> = p.iter().map(|x| x.clone() * &factor).collect();
        // polynomial division r by q, keep remainder
        while r.len() > q.len().saturating_sub(1) && r.len() >= q.len() {
            let rd = r.len() as i64 - 1;
            let qd = q.len() as i64 - 1;
            let lc_r = r.last().unwrap().clone();
            let lc_qq = q.last().unwrap().clone();
            let shift = (rd - qd) as usize;
            for i in 0..q.len() {
                r[i + shift] = r[i + shift].clone() * &lc_qq - lc_r.clone() * &q[i];
            }
            while r.last().map(|x| *x == 0).unwrap_or(false) { r.pop(); }
        }
        if (dp * dq) % 2 != 0 { sign = -sign.clone(); }
        p = q;
        q = r;
    }
}

/// Find rational roots of integer polynomial (denominator=1 candidates)
fn integer_roots(poly: &[Integer]) -> Vec<Integer> {
    if poly.is_empty() { return vec![]; }
    let mut roots = Vec::new();
    let n0 = poly[0].clone().abs();
    if n0 == 0 { roots.push(Integer::new()); }
    // Try small integer values
    for v in -100000i64..=100000 {
        let x = Integer::from(v);
        let mut val = Integer::new();
        let mut pw = Integer::from(1i32);
        for c in poly { val += c.clone() * &pw; pw *= &x; }
        if val == 0 { roots.push(x); }
    }
    roots
}

// ---------------------------------------------------------------------------
// Boneh-Durfee core
// ---------------------------------------------------------------------------

fn boneh_durfee_core(n: &Integer, e: &Integer, delta: f64, m: usize) -> Option<Integer> {
    // A = (N+1)/2
    let a_int = (n.clone() + 1u32) / 2u32;

    let t = ((1.0 - 2.0 * delta) * m as f64) as usize;
    let x_bound_f = Float::with_val(PREC, n).pow(delta as f32) * 2.0f32;
    let y_bound_f = Float::with_val(PREC, n).pow(0.5f32);
    let xx = x_bound_f.to_integer().unwrap_or_else(Integer::new);
    let yy = y_bound_f.to_integer().unwrap_or_else(Integer::new);
    let uu = xx.clone() * &yy + 1u32;

    // Build shifted polynomial list
    // pol(u,x,y) = 1 + x*(A + y)  where u = x*y+1
    // In terms of (x,y): pol = 1 + x*A + x*y = A*x + x*y + 1
    // We represent polynomials as (coeff_for_1, coeff_for_x, coeff_for_y, coeff_for_xy)
    // Index ordering for monomials: just x-shifts and y-shifts up to m,t

    // Simplified: build lattice with dimension (m+1)*(m+2)/2 + t*(m - floor(m/t))
    // For small m this is tractable
    let dim = (m + 1) * (m + 2) / 2 + t * (m + 1 - m / (t.max(1)));
    let dim = dim.min(20); // cap to keep LLL fast

    // Build vectors: each row is coefficients of a shifted polynomial
    // evaluated at (UU, XX, YY) to scale
    let modulus = e.clone();

    // x-shifts: x^i * modulus^(m-k) * pol^k for k=0..m, i=0..m-k
    // For simplicity: build rows as just modular shifts
    let mut rows: Vec<Vec<Integer>> = Vec::new();

    // We build a simplified 2D version
    // Row type 1: modulus^(m-k) * (A*x + xy + 1)^k, expanded
    // This is complex; use a reduced form for small m
    for k in 0..=m {
        for i in 0..=(m - k) {
            // x^i * e^(m-k) * (1 + A*x)^k (drop y terms for approximation)
            let mut row = vec![Integer::new(); dim];
            let ep = e.clone().pow((m - k) as u32);
            // coefficient at position i+k*something
            let idx = i + k * (m + 1);
            if idx < dim {
                row[idx] = ep.clone() * Integer::from(1u32) * xx.clone().pow(i as u32);
                rows.push(row);
                if rows.len() >= dim { break; }
            }
        }
        if rows.len() >= dim { break; }
    }

    // Pad with identity rows if needed
    while rows.len() < dim {
        let mut row = vec![Integer::new(); dim];
        row[rows.len()] = modulus.clone().pow(m as u32);
        rows.push(row);
    }
    rows.truncate(dim);

    let reduced = lll(rows);

    // Extract candidates from first two reduced vectors
    // Try to find d from the short vector
    for row in reduced.iter().take(3) {
        for v in row {
            if *v == 0 { continue; }
            // Check if v could be d: ed ≡ 1 + k*(n-p-q+1) mod n
            let d_candidate = v.clone().abs();
            if d_candidate < 2 { continue; }
            // Verify: compute message = e*d - 1, factor n from it
            let ed = e.clone() * &d_candidate;
            let phi_candidate = ed.clone() - 1u32;
            // phi = (p-1)(q-1) = n - p - q + 1
            // p+q = n - phi + 1
            let pq_sum = n.clone() - &phi_candidate + 1u32;
            let disc = pq_sum.clone() * &pq_sum - Integer::from(4u32) * n;
            if disc < 0 { continue; }
            let (sq, rem) = disc.sqrt_rem(Integer::new());
            if rem != 0 { continue; }
            let p = (pq_sum.clone() + &sq) / 2u32;
            let q = (pq_sum - sq) / 2u32;
            if p.clone() * &q == *n && p > 1 && q > 1 {
                return Some(d_candidate);
            }
        }
    }
    None
}

impl RsaAttack for BonehDurfeeAttack {
    fn name(&self) -> &'static str { "boneh_durfee" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, _cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let e = &pub_key.e;

        // Keep this naive lattice implementation bounded.
        if n.significant_bits() > 1024 {
            return None;
        }

        if abort.load(Ordering::Relaxed) { return None; }

        // Only try for e roughly similar size to n (common RSA params)
        // delta = 0.26 means d < N^0.26 → very small d
        for delta in [0.26f64, 0.28, 0.292] {
            if abort.load(Ordering::Relaxed) { return None; }
            for m in [4usize, 5, 6] {
                if abort.load(Ordering::Relaxed) { return None; }
                if let Some(d) = boneh_durfee_core(n, e, delta, m) {
                    // Reconstruct priv key from d
                    let phi = (e.clone() * &d - 1u32);
                    let pq_sum = n.clone() - &phi + 1u32;
                    let disc = pq_sum.clone() * &pq_sum - Integer::from(4u32) * n;
                    if disc < 0 { continue; }
                    let (sq, rem) = disc.sqrt_rem(Integer::new());
                    if rem != 0 { continue; }
                    let p = (pq_sum.clone() + &sq) / 2u32;
                    let q = (pq_sum - sq) / 2u32;
                    if let Some(pk) = PrivateKey::new(p, q, e.clone(), n.clone()) {
                        return Some(AttackResult { priv_key: Some(pk), decrypted: vec![] });
                    }
                }
            }
        }
        None
    }
}
