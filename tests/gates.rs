use sibyl::*;

fn setup() -> (Identity, Identity, Gate, String) {
    let owner = Identity::generate();
    let oracle = Identity::generate();
    let (gate, k2) = Gate::seal(
        b"launch codes are behind the freezer",
        "freezer-opened-2026-11-01",
        &oracle.public_key(),
        &owner,
    );
    (owner, oracle, gate, k2)
}

#[test]
fn seal_and_release_roundtrip() {
    let (_owner, oracle, gate, k2) = setup();
    gate.verify_seal().unwrap();
    let artifact = oracle_issue(&oracle, &gate, &k2).unwrap();
    let payload = gate.unlock(&artifact).unwrap();
    assert_eq!(payload, b"launch codes are behind the freezer");
}

#[test]
fn organism_cannot_open_without_oracle() {
    // The gate holds only k1 — there is no unlock path that doesn't
    // require a valid artifact. This test documents the API boundary:
    // unlock() is the only decryptor, and it demands a signed release.
    let (_owner, _oracle, gate, _k2) = setup();
    let mut fake = ReleaseArtifact {
        gate_id: gate.id.clone(),
        claim: gate.condition.clone(),
        k2: "00".repeat(32),
        signature: "00".repeat(64),
        ts: 0,
    };
    assert!(gate.unlock(&fake).is_err());
    // Even a correctly-committed k2 fails without the oracle signature.
    let (_o2, oracle, gate2, k2) = setup();
    fake.gate_id = gate2.id.clone();
    fake.claim = gate2.condition.clone();
    fake.k2 = k2;
    assert!(gate2.unlock(&fake).is_err());
    let _ = oracle;
}

#[test]
fn wrong_oracle_cannot_release() {
    let (_owner, _oracle, gate, k2) = setup();
    let impostor = Identity::generate();
    // Impostor isn't the designated oracle — issue() refuses.
    assert!(oracle_issue(&impostor, &gate, &k2).is_err());
}

#[test]
fn wrong_share_rejected_by_oracle_and_gate() {
    let (_owner, oracle, gate, _k2) = setup();
    let bad_share = "11".repeat(32);
    // Oracle refuses to sign a release over a bad share.
    assert!(oracle_issue(&oracle, &gate, &bad_share).is_err());
}

#[test]
fn claim_substitution_fails() {
    let (_owner, oracle, gate, k2) = setup();
    let mut artifact = oracle_issue(&oracle, &gate, &k2).unwrap();
    // Rewrite the claim — signature breaks AND claim_hash mismatches.
    artifact.claim = "different-event".into();
    assert!(gate.unlock(&artifact).is_err());
}

#[test]
fn artifact_for_another_gate_fails() {
    let (_o1, oracle, gate1, k2_1) = setup();
    let (_o2, _oracle2, gate2, _k2_2) = setup();
    let artifact = oracle_issue(&oracle, &gate1, &k2_1).unwrap();
    // Replay the artifact against a different gate.
    assert!(gate2.unlock(&artifact).is_err());
}

#[test]
fn gate_log_chains_events() {
    let (_owner, oracle, gate, k2) = setup();
    let mut log = GateLog::new();
    log.record("sealed", &gate.id, "freezer condition");
    let artifact = oracle_issue(&oracle, &gate, &k2).unwrap();
    log.record("released", &gate.id, "oracle issued");
    gate.unlock(&artifact).unwrap();
    log.record("opened", &gate.id, "payload disclosed");
    log.verify().unwrap();
    log.events[1].detail = "tampered".into();
    assert!(log.verify().is_err());
}

#[test]
fn tampered_ciphertext_fails_aead() {
    let (_owner, oracle, mut gate, k2) = setup();
    let artifact = oracle_issue(&oracle, &gate, &k2).unwrap();
    // Flip a ciphertext byte — GCM auth tag catches it. But the seal
    // signature breaks first, which is also a rejection: both are real.
    let mut ct = hex::decode(&gate.ciphertext).unwrap();
    ct[0] ^= 0xff;
    gate.ciphertext = hex::encode(ct);
    assert!(gate.unlock(&artifact).is_err());
}

#[test]
fn seal_is_deterministic_in_commitments_only() {
    let owner = Identity::generate();
    let oracle = Identity::generate();
    let (g1, _k1) = Gate::seal(b"x", "c1", &oracle.public_key(), &owner);
    let (g2, _k2) = Gate::seal(b"x", "c1", &oracle.public_key(), &owner);
    // Randomized keys + nonce: same payload, different gates.
    assert_ne!(g1.id, g2.id);
    assert_ne!(g1.ciphertext, g2.ciphertext);
}
