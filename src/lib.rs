//! sibyl — oracle-gated memory.
//!
//! Named for the Sibyl — who held knowledge she would not release
//! until the appointed sign.
//!
//! Sometimes the right answer to "remember this" is "remember it when
//! the world is ready": a memory that unlocks when a peer attests an
//! event, when a deadline passes, when a treaty activates. A note to
//! your future self. A secret the organism carries but cannot open
//! early.
//!
//! The gate is cryptographic, not promised:
//!
//! 1. **Seal** — the owner encrypts the payload under a random key `K`,
//!    split into shares `k1` and `k2` with `K = k1 ⊕ k2`. The [`Gate`]
//!    given to the organism holds the ciphertext, `k1`, a commitment
//!    `sha256(k2)`, the oracle's public key, and the `claim_hash` of the
//!    event the oracle must sign. `k2` goes to the oracle custodian.
//! 2. **Hold** — the organism physically cannot decrypt: it has `k1`
//!    and the ciphertext but not `k2`, and the commitment stops anyone
//!    substituting a different share.
//! 3. **Release** — when the condition event occurs, the oracle signs
//!    the claim and issues a [`ReleaseArtifact`] carrying `k2`. The
//!    organism verifies: oracle signature, claim matches the gate's
//!    `claim_hash`, and `sha256(k2)` matches the commitment. Only then
//!    does `K` exist inside the organism.
//!
//! Trust model, stated honestly: the oracle cannot read the memory (it
//! holds only `k2`); the organism cannot open it early (it lacks `k2`);
//! collusion between oracle and whoever holds the full gate breaks it —
//! so oracle custody should sit where `nagi` custodians sit.
//!
//! ```no_run
//! use sibyl::{oracle_issue, Identity, Gate};
//!
//! let owner = Identity::generate();
//! let oracle = Identity::generate();
//! let (gate, k2) = Gate::seal(
//!     b"the launch codes live in the freezer",
//!     "freezer-opened",
//!     &oracle.public_key(),
//!     &owner,
//! );
//! // … hand k2 to the oracle custodian, gate to the organism …
//! // later, the event happens and the oracle releases:
//! let artifact = oracle_issue(&oracle, &gate, &k2).unwrap();
//! let payload = gate.unlock(&artifact).unwrap();
//! ```

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("canonical json")
}

#[derive(Debug)]
pub enum Error {
    BadSignature(String),
    BadGate(String),
    ConditionUnmet(String),
    BadShare(String),
    Crypto(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature(m) => write!(f, "signature failure: {m}"),
            Error::BadGate(m) => write!(f, "invalid gate: {m}"),
            Error::ConditionUnmet(m) => write!(f, "condition unmet: {m}"),
            Error::BadShare(m) => write!(f, "bad key share: {m}"),
            Error::Crypto(m) => write!(f, "crypto: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

// ---------------------------------------------------------------- identity

pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.key.sign(msg).to_bytes())
    }
}

pub fn verify_signature(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::BadSignature(format!("pubkey hex: {e}")))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("pubkey not 32 bytes".into()))?,
    )
    .map_err(|e| Error::BadSignature(format!("pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| Error::BadSignature(format!("sig hex: {e}")))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("sig not 64 bytes".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("verification failed".into()))
}

// ---------------------------------------------------------------- gate

/// A sealed memory: ciphertext the organism holds but cannot open until
/// the oracle releases the second share under a signed claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gate {
    /// Content-derived id.
    pub id: String,
    /// Oracle authorized to release (hex pubkey).
    pub oracle: String,
    /// Human-readable condition ("when peer 9f2e attests ceremony-7").
    pub condition: String,
    /// SHA-256 of the exact claim text the oracle must sign — binds the
    /// release to the real event, not a paraphrase.
    pub claim_hash: String,
    /// First key share, held by the gate (hex).
    pub k1: String,
    /// Commitment to the second share: sha256(k2) — substitution-proof.
    pub commit_k2: String,
    /// AES-256-GCM nonce (hex).
    pub nonce: String,
    /// Sealed payload (hex).
    pub ciphertext: String,
    /// Who sealed it (hex pubkey).
    pub sealed_by: String,
    pub ts: u64,
    /// Sealer's signature over the canonical gate body — proves provenance.
    pub signature: String,
}

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;
    Ok((nonce.to_vec(), ct))
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|e| Error::Crypto(format!("decrypt: {e}")))
}

impl Gate {
    /// Seal a payload behind an oracle condition. Returns the gate (for
    /// the organism) and `k2` (for the oracle custodian). The sealer
    /// must then forget `k2` — the whole point is that opening requires
    /// the oracle.
    pub fn seal(
        payload: &[u8],
        condition: &str,
        oracle_pubkey: &str,
        sealer: &Identity,
    ) -> (Gate, String) {
        let mut k = [0u8; 32];
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k1);
        rand::thread_rng().fill_bytes(&mut k2);
        for i in 0..32 {
            k[i] = k1[i] ^ k2[i];
        }
        let (nonce, ct) = aes_encrypt(&k, payload).expect("encrypt");
        let claim_hash = sha256_hex(condition.as_bytes());
        let ts = now_secs();
        let id = sha256_hex(&canonical(&json!({
            "oracle": oracle_pubkey,
            "claim_hash": claim_hash,
            "commit_k2": sha256_hex(&k2),
            "ts": ts,
        })));
        let mut gate = Gate {
            id,
            oracle: oracle_pubkey.to_string(),
            condition: condition.to_string(),
            claim_hash,
            k1: hex::encode(k1),
            commit_k2: sha256_hex(&k2),
            nonce: hex::encode(&nonce),
            ciphertext: hex::encode(&ct),
            sealed_by: sealer.public_key(),
            ts,
            signature: String::new(),
        };
        gate.signature = sealer.sign(&canonical(&gate.body()));
        (gate, hex::encode(k2))
    }

    fn body(&self) -> Value {
        json!({
            "id": self.id,
            "oracle": self.oracle,
            "condition": self.condition,
            "claim_hash": self.claim_hash,
            "k1": self.k1,
            "commit_k2": self.commit_k2,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "sealed_by": self.sealed_by,
            "ts": self.ts,
        })
    }

    /// Verify the sealer's provenance signature.
    pub fn verify_seal(&self) -> Result<(), Error> {
        verify_signature(&self.sealed_by, &canonical(&self.body()), &self.signature)
    }

    /// Attempt to unlock with an oracle release artifact. Verifies:
    /// oracle signature over (gate_id + claim), claim matches the gate's
    /// claim_hash, and k2 matches the commitment — then decrypts.
    pub fn unlock(&self, artifact: &ReleaseArtifact) -> Result<Vec<u8>, Error> {
        self.verify_seal()?;
        if artifact.gate_id != self.id {
            return Err(Error::BadGate("artifact is for a different gate".into()));
        }
        // The signed claim must be exactly the sealed condition.
        if sha256_hex(artifact.claim.as_bytes()) != self.claim_hash {
            return Err(Error::ConditionUnmet(
                "release claim does not match sealed condition".into(),
            ));
        }
        artifact.verify(&self.oracle)?;
        let k2 = hex::decode(&artifact.k2).map_err(|e| Error::BadShare(format!("k2 hex: {e}")))?;
        if sha256_hex(&k2) != self.commit_k2 {
            return Err(Error::BadShare("k2 does not match commitment".into()));
        }
        let k1 = hex::decode(&self.k1).map_err(|e| Error::BadShare(format!("k1 hex: {e}")))?;
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = k1[i] ^ k2[i];
        }
        let nonce =
            hex::decode(&self.nonce).map_err(|e| Error::BadGate(format!("nonce hex: {e}")))?;
        let ct = hex::decode(&self.ciphertext)
            .map_err(|e| Error::BadGate(format!("ciphertext hex: {e}")))?;
        aes_decrypt(&k, &nonce, &ct)
    }
}

/// The oracle's release: the signed claim plus the custody share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    pub gate_id: String,
    /// The exact claim text — must hash to the gate's claim_hash.
    pub claim: String,
    /// The oracle's custody share (hex).
    pub k2: String,
    /// Oracle signature over canonical {gate_id, claim, k2_commitment}.
    pub signature: String,
    pub ts: u64,
}

impl ReleaseArtifact {
    fn body(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "claim": self.claim,
            "k2_commitment": sha256_hex(
                &hex::decode(&self.k2).unwrap_or_default()
            ),
        })
    }

    /// Verify the oracle signature — the caller supplies the expected
    /// oracle pubkey from the gate (never trust an artifact's own key).
    pub fn verify(&self, oracle_pubkey: &str) -> Result<(), Error> {
        verify_signature(oracle_pubkey, &canonical(&self.body()), &self.signature)
    }
}

/// Oracle-side ceremony: verify this oracle is the gate's designated
/// oracle, then sign the release carrying the custody share.
pub fn oracle_issue(
    oracle: &Identity,
    gate: &Gate,
    k2_hex: &str,
) -> Result<ReleaseArtifact, Error> {
    if oracle.public_key() != gate.oracle {
        return Err(Error::BadSignature(
            "this identity is not the gate's oracle".into(),
        ));
    }
    let k2 = hex::decode(k2_hex).map_err(|e| Error::BadShare(format!("k2 hex: {e}")))?;
    if sha256_hex(&k2) != gate.commit_k2 {
        return Err(Error::BadShare("custody share does not match gate".into()));
    }
    let mut artifact = ReleaseArtifact {
        gate_id: gate.id.clone(),
        claim: gate.condition.clone(),
        k2: k2_hex.to_string(),
        signature: String::new(),
        ts: now_secs(),
    };
    artifact.signature = oracle.sign(&canonical(&artifact.body()));
    Ok(artifact)
}

// ---------------------------------------------------------------- gate log

/// The organism's hash-chained record of gates held, releases attempted,
/// and openings — sealed memory is auditable like everything else.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateLog {
    pub events: Vec<GateEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateEvent {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    /// "sealed" | "released" | "denied"
    pub kind: String,
    pub gate_id: String,
    pub detail: String,
    pub ts: u64,
}

impl Default for GateLog {
    fn default() -> Self {
        Self::new()
    }
}

impl GateLog {
    pub fn new() -> Self {
        GateLog { events: Vec::new() }
    }

    fn tip(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64))
    }

    pub fn record(&mut self, kind: &str, gate_id: &str, detail: &str) {
        let seq = self.events.len() as u64;
        let prev = self.tip();
        let ts = now_secs();
        let hash = sha256_hex(&canonical(&json!({
            "seq": seq, "prev": prev, "kind": kind,
            "gate_id": gate_id, "detail": detail, "ts": ts,
        })));
        self.events.push(GateEvent {
            seq,
            prev,
            hash,
            kind: kind.to_string(),
            gate_id: gate_id.to_string(),
            detail: detail.to_string(),
            ts,
        });
    }

    pub fn verify(&self) -> Result<(), Error> {
        let mut prev = "0".repeat(64);
        for (i, e) in self.events.iter().enumerate() {
            if e.seq != i as u64 || e.prev != prev {
                return Err(Error::BadGate(format!("gate log broken at {i}")));
            }
            let hash = sha256_hex(&canonical(&json!({
                "seq": e.seq, "prev": e.prev, "kind": e.kind,
                "gate_id": e.gate_id, "detail": e.detail, "ts": e.ts,
            })));
            if hash != e.hash {
                return Err(Error::BadGate(format!("gate log hash mismatch at {i}")));
            }
            prev = e.hash.clone();
        }
        Ok(())
    }
}
