/// z3_solver attack: SMT-based RSA modeling attack (Python version uses z3).
///
/// Important operational note:
/// - This style of attack is generally practical only for toy-size RSA instances
///   (typically <= 64-bit modulus) or game-like CTF challenges.
/// - `solver.check()` in Z3 is synchronous/blocking; it does not automatically
///   observe this tool's `_abort` flag from inside the solver call.
/// - A production-grade Rust implementation must enforce explicit solver timeouts
///   (both solver-level and outer watchdog timeout) to avoid freezing the process.
///
/// Current status in this project:
/// - compatibility stub only (`can_run = false`)
/// - attack name/CLI parity is preserved, runtime execution is intentionally disabled
///   until a safe native integration is added.

use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct Z3SolverAttack;

impl RsaAttack for Z3SolverAttack {
    fn name(&self) -> &'static str { "z3_solver" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn can_run(&self) -> bool { false }

    fn run(&self, _pub_key: &PublicKey, _cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        None
    }
}
