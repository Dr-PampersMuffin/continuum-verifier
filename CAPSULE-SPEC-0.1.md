# Continuum Evidence Capsule — Spec 0.1

A capsule is one portable, self-verifying object. A stranger with no internet, no
access to the issuer, and only this spec can hand the capsule to a fresh
implementation and get a verdict. It is the forward-durable, offline unit of
Continuum evidence.

## What it carries (nothing is fetched at verify time)

- `content` — the material's fingerprint (hash + algorithm) and media type. The
  capsule proves custody of the fingerprint; proving a file *matches* needs the
  file in hand, which the verifier recomputes when the file is present.
- `consent_chain` — the sealed record(s): the leaves whose Merkle root is
  anchored.
- `root` — the Merkle `root_hash` plus, per record, an `inclusion_proof` (the
  sibling path), so the root is recomputable from the record offline.
- `key_provenance` — the issuer id, public key, algorithm, and the issuer
  signature over `root_hash`. This is the Day-0 trust root; it must be learned
  out of band (it does not become trustworthy by sitting inside the capsule).
- `anchors[]` — one or more public-witness commitments to `root_hash`. A witness
  in the verifier's durable set (bitcoin-ots, ct-log, nist-beacon) upgrades the
  verdict; a self-asserted witness does not.
- `timestamps[]` — the re-stamp trail (RFC 4998 ERS in spirit): each entry
  re-commits `root_hash` under a named algorithm at a time. This is the battery
  swap that keeps the capsule alive as crypto ages.
- `trust_horizons` — the honest date each algorithm stops being trusted. The
  verifier compares the NEWEST re-stamp's algorithm against its horizon.

## Verification algorithm (language-agnostic; re-implement anywhere)

Canonical bytes = JSON with sorted keys and no spaces: `(",",":")`. Hash = the
named algorithm over canonical bytes, hex. Signature = Ed25519 over the stated
message bytes. Only two primitives are needed: a hash (SHA-256/SHA3 are in most
stdlibs) and an Ed25519 verify (present in every language; the one dependency a
pure-stdlib implementation lacks).

1. Parse and structural-check. Missing required fields -> FAILED.
2. Inclusion: for each record, fold its leaf hash up `inclusion_proof`
   (`side=L` -> `H(sibling || h)`, `side=R` -> `H(h || sibling)`). Computed root
   must equal `root.root_hash`. Mismatch -> WITHHELD.
3. Issuer signature and authentication: Ed25519-verify
   `key_provenance.issuer_signature` over `root_hash` with `issuer_pubkey`. Fail
   -> WITHHELD. The `issuer_pubkey` is carried in the file, so a valid signature
   proves self-consistency, not that the EXPECTED issuer signed it (swap the key,
   re-sign the same root, and it still verifies against itself). If an expected
   issuer key is supplied out of band, compare it to `issuer_pubkey`: mismatch ->
   WITHHELD; match -> the issuer is authenticated. With no expected issuer, the
   issuer is UNVERIFIED and the verdict cannot exceed SELF_CONSISTENT.
4. Anchors: for each, verify its signature over the canonical
   `{root, witness, observed_at}` with its pubkey. Record whether ANY verifying
   anchor's witness is in the durable set.
5. Re-stamp trail: for each entry, recompute `digest = H_alg(root_hash)` and
   Ed25519-verify its signature; any failure -> WITHHELD. Take the newest entry;
   if its algorithm's horizon is in the past -> RESTAMP_NEEDED.
6. Verdict precedence: WITHHELD (any check failed, including issuer mismatch) >
   RESTAMP_NEEDED (newest crypto past horizon) > SELF_CONSISTENT (internal checks
   pass but missing a durable anchor and/or an authenticated expected issuer) >
   VERIFIED (internal checks pass AND a durable anchor verified AND the issuer is
   authenticated against an out-of-band expected key AND crypto not expired).

Exit codes: 0 VERIFIED, 1 WITHHELD, 2 FAILED (unparseable), 3 SELF_CONSISTENT,
4 RESTAMP_NEEDED.

## Honest boundaries (state these, do not bury them)

- **Forward only.** A capsule proves what was true at the moment it was sealed,
  carried forward. It cannot certify un-witnessed history. A tool that could is a
  forgery machine; this one refuses by having no path to do it.
- **Not frozen, kept alive.** There is no seal-once-verify-in-70-years with
  today's crypto. Survival past ~a decade requires re-stamping onto fresh
  algorithms before the old ones weaken. `RESTAMP_NEEDED` is the verifier telling
  you the battery is low. The product is a maintained archive, not a dead object.
- **Durability of the root is external.** Offline verification proves the capsule
  is internally self-consistent and self-authenticating against a pinned key.
  Whether that key and root survive decades depends on welding the anchor to real,
  independent, long-lived public witnesses. In this sandbox the witnesses and the
  re-stamp signatures are simulated with local keys; `SELF_CONSISTENT` is the
  honest verdict until a real durable witness is wired.
- **Provenance, not truth.** As with the rest of Continuum, the capsule attests
  custody and integrity, not the truth of the underlying facts.
- **Crypto-agility is partial here.** The re-stamp trail demonstrates the
  mechanism by rotating the hash family (SHA-256 -> SHA3-512). A real deployment
  rotates the *signature* to a post-quantum scheme (e.g. ML-DSA); this sandbox
  still signs with Ed25519 and says so.
