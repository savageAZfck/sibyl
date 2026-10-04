//! A sealed memory opens only when the oracle says the world is ready.
use sibyl::*;

fn main() {
    let owner = Identity::generate();
    let oracle = Identity::generate(); // a peer organism, a nagi custodian…
    let mut log = GateLog::new();

    // The owner seals a memory for the organism to carry — sealed against
    // the condition "succession-ceremony-complete".
    let (gate, k2) = Gate::seal(
        b"the spare freezer key is taped under the third drawer",
        "succession-ceremony-complete",
        &oracle.public_key(),
        &owner,
    );
    log.record("sealed", &gate.id, &gate.condition);
    println!("sealed gate {}…", &gate.id[..16]);
    println!("  organism holds: ciphertext + k1 + commit(k2)");
    println!("  oracle holds:   k2 — organism cannot open early\n");

    // The organism tries to open it — no artifact exists yet.
    // (unlock is the only path and it demands a signed release.)
    println!("organism attempts recall: NO RELEASE ARTIFACT — stays sealed\n");

    // The event happens; the oracle issues the release.
    let artifact = oracle_issue(&oracle, &gate, &k2).unwrap();
    log.record("released", &gate.id, "oracle signed the claim");

    let payload = gate.unlock(&artifact).unwrap();
    log.record("opened", &gate.id, "payload disclosed");
    println!("event occurred — oracle released");
    println!(
        "organism recalls: \"{}\"",
        String::from_utf8_lossy(&payload)
    );

    log.verify().expect("gate log verifies");
    println!("\ngate log: {} events, verified", log.events.len());
}
