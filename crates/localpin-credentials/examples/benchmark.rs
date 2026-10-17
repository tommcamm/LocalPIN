//! Synthetic KDF timing only; no host authentication or TPM operation.

use localpin_core::{
    limits::{KdfParameters, ResourceBudget, WorkKind},
    secret::Pin,
    types::Uid,
};
use localpin_credentials::derive;
use std::{hint::black_box, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations: usize = std::env::args()
        .nth(1)
        .map_or(Ok(20), |value| value.parse())?;
    if !(1..=1000).contains(&iterations) {
        return Err("iteration count must be between 1 and 1000".into());
    }
    let uid = Uid::new(1000).map_err(|_| "invalid synthetic UID")?;
    let pin = Pin::parse(b"000001").map_err(|_| "invalid synthetic PIN")?;
    let budget = ResourceBudget::default();
    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let permit = budget
            .try_work(uid, KdfParameters::ENROLLMENT, WorkKind::Verification)
            .map_err(|_| "KDF capacity unavailable")?;
        let output = derive(&pin, &[7; 16], KdfParameters::ENROLLMENT, &permit)?;
        black_box(output.expose());
        drop(output);
        drop(permit);
        timings.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    timings.sort_by(f64::total_cmp);
    println!(
        "Argon2id v19; 65536 KiB; 3 passes; 1 lane; {iterations} samples; includes memory allocation and erasure"
    );
    println!(
        "min={:.2} ms median={:.2} ms p95={:.2} ms max={:.2} ms",
        timings[0],
        timings[iterations / 2],
        timings[(iterations * 95).div_ceil(100).saturating_sub(1)],
        timings[iterations - 1],
    );
    Ok(())
}
