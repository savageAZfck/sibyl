# sibyl

**Oracle-gated memory — secrets sealed behind events. The organism carries what it cannot open.**

Named for the Sibyl — who held knowledge she would not release until the appointed sign.

## Why this exists

Sometimes "remember this" means "remember it *when the world is ready*": a memory that unlocks when a peer attests an event, a ceremony completes, a treaty activates. A note to your future self. A secret the organism carries but cannot open early — not by policy, but because **it lacks the key share.**

## The gate (real crypto, honest trust model)

1. **Seal** — owner encrypts under random `K`, splits `K = k1 ⊕ k2`. The organism's gate holds ciphertext + `k1` + `sha256(k2)` + the oracle pubkey + the `claim_hash` of the event that must be signed. `k2` goes to the oracle custodian.
2. **Hold** — the organism *physically* cannot decrypt: no `k2`, and the commitment stops share substitution. Unlock is a single function that demands a signed release.
3. **Release** — the oracle signs the claim (which must hash to the sealed `claim_hash`) and issues the artifact carrying `k2`. Three checks gate the open: oracle signature, claim-match, share-commitment.

**Trust model, honestly:** the oracle can't read the memory (only `k2`); the organism can't open it early (lacks `k2`); oracle + full-gate collusion breaks it — put oracle custody where `nagi` custodians sit.

## What it gives you

- `Gate::seal / unlock` — AES-256-GCM sealed payloads with two-share release
- `oracle_issue` — the oracle's signed release ceremony
- `GateLog` — hash-chained record of seals, releases, opens — sealed memory is auditable too
- Sealer provenance signatures — a gate proves who sealed it

## Try it

```bash
cargo run --example sibyl
cargo test
```

## Pair with

- `nagi` — custodian infrastructure for the oracle share
- `wolakota` — treaty activation as a release condition
- `mictlan` — posthumous gates: memories that open only after death
