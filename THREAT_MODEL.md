# Threat model — sibyl

The organism opens early — it holds ciphertext + one share; the oracle share is committed but unreleased. The oracle is compelled to open everything — each release artifact is gate-scoped and signed. A forged release opens the gate — the artifact must verify against the oracle key and the commitment. The payload is swapped — AES-GCM auth fails. The gate history is denied — the gate log is hash-chained.

## What this crate guarantees

- Before oracle release, no usable key material exists on the organism side.
- Release artifacts are signed, gate-scoped, and bound to the commitment.
- The gate log (seal/release/open) is hash-chained and offline-verifiable.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
