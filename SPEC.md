# SPEC — sibyl (oracle-gated memory)

## Custody

Sealing splits the payload key into two shares:

- **Organism share** — held locally, alone it opens nothing.
- **Oracle share** — held by the oracle; committed to (`commitment =
  sha256(share)`) but not released until the gate's condition is
  attested.

The payload is AES-256-GCM sealed under the combined key. Before
oracle release, no usable key material exists on the organism side.

## Gate

```json
{
  "id": "…", "condition": "event description",
  "ciphertext": "…", "nonce": "…",
  "organism_share_commit": "…", "oracle_share_commit": "…",
  "oracle": "pubkey", "owner": "pubkey",
  "sealed_at": 0
}
```

## Release artifact

`oracle_issue(oracle, gate, oracle_share)` → signed
`{ gate_id, condition, oracle_share, ts, signature }`. `unlock()`
verifies the artifact against the gate's oracle pubkey, checks the
share against `oracle_share_commit`, combines shares, and decrypts —
any forgery fails signature, commitment, or GCM auth.

## Gate log

Seal / release / open are recorded on a hash-chained `GateLog`;
`verify()` replays linkage offline.

## Invariants

- The organism cannot unlock early — the oracle share is absent by
  construction, not policy.
- Each artifact is gate-scoped — one oracle cannot mass-release.
- Opening leaves a committed record.
