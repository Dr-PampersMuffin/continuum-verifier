# Continuum Evidence Capsule — Spec 0.2

A capsule is one portable, self-verifying object. A stranger with no internet, no
access to the issuer, and only this spec can hand the capsule to a fresh
implementation and get a verdict. It is the forward-durable, offline unit of
Continuum evidence.

0.2 supersedes 0.1 after an external boundary review. The format is not
backward-compatible: a 0.1 capsule is rejected (re-issue under 0.2). The four
changes are listed at the end.

## What it carries (nothing is fetched at verify time)

- `content` — the material's fingerprint (hash + algorithm) and media type. The
  capsule proves custody of the fingerprint; proving a file *matches* needs the
  file in hand, which the verifier recomputes when the file is present.
- `consent_chain.records` — the sealed record(s): the leaves, after `content`,
  whose Merkle root is anchored.
- `root` — the Merkle `root_hash`, the `merkle_alg`, the ordered `leaf_ids` and
  `leaf_count` (the committed leaf vector), and per-leaf `inclusion_proofs`.
- `key_provenance` — the issuer id, public key, algorithm, and the issuer
  signature over the **signed root header** (see below). The issuer key is the
  Day-0 trust root; it must be learned out of band.
- `anchors[]` — public-witness commitments to `root_hash`. A witness is treated as
  durable only if it is in the durable set AND its key matches an out-of-band pin.
- `timestamps[]` — the timestamp-renewal trail. Each entry signs its whole
  envelope `{alg, stamped_at, digest, root}` and names the root it covers.
- `tree_renewals[]` — the hash-tree-renewal chain (may be empty). Each entry
  rebuilds the tree over the same leaf data under a new hash, chains to the prior
  root, and is signed by a renewer key.
- `trust_horizons` — ADVISORY only. A hint of when each algorithm stops being
  trusted. The verifier does not use it; horizons are the verifier's own policy,
  held out of band (see step 8). Editing this field cannot change a verdict.

## Canonical form and primitives

Canonical bytes = JSON with sorted keys and no spaces: separators `(",",":")`,
UTF-8. Hash = the named algorithm over canonical bytes, hex. Signature = Ed25519
over the stated message bytes. Two primitives only: a hash (SHA-256/SHA3 are in
most stdlibs) and an Ed25519 verify.

## The signed root header (binds the record set)

The issuer does not sign the bare `root_hash`. It signs:

```
header = {"root_hash":<hex>, "merkle_alg":"sha256",
          "leaf_ids":[<ordered ids, CONTENT first>], "leaf_count":<n>}
issuer_signature = Ed25519(header canonical-bytes)
```

Because the ordered leaf vector is signed, the presented records must reproduce it
exactly. Omitting or duplicating a record changes `leaf_ids` or its length and
breaks the check.

## Verification algorithm (language-agnostic; re-implement anywhere)

1. **Version / structure.** `capsule_version` must be `0.2`, else WITHHELD.
   Missing required fields -> FAILED.
2. **Leaf-set commitment.** Reconstruct the leaves: `CONTENT` (the content object
   with `id=CONTENT`, `type=CONTENT_COMMITMENT`) followed by each record. Their
   ids, in order, must equal `root.leaf_ids`; `leaf_count` must match; no duplicate
   ids. Mismatch -> WITHHELD.
3. **Inclusion.** For each leaf, fold its hash up `inclusion_proofs[id]` under
   `root.merkle_alg` (`side=L` -> `H(sibling||h)`, `side=R` -> `H(h||sibling)`).
   Computed root must equal `root.root_hash`. Mismatch -> WITHHELD.
4. **Issuer signature and authentication.** Ed25519-verify `issuer_signature` over
   the canonical signed root header with `issuer_pubkey`. Fail -> WITHHELD. The key
   travels in the file, so a valid signature is self-consistency only. If
   `--expected-issuer` is supplied out of band and matches `issuer_pubkey`, the
   issuer is authenticated; if supplied and different -> WITHHELD; if absent, the
   issuer is UNVERIFIED and the verdict cannot exceed SELF_CONSISTENT.
5. **Anchors.** For each, verify its signature over canonical
   `{root, witness, observed_at}` and that `root == root_hash`. A broken anchor
   signature -> WITHHELD; no binding anchor -> WITHHELD. An anchor is **durable**
   only when its witness is in the durable set `{bitcoin-ots, ct-log, nist-beacon}`
   AND its key equals the out-of-band pin `--expected-witness NAME=<hex>`. A
   self-asserted or unpinned anchor verifies but is not durable.
6. **Hash-tree renewals.** For each entry in `tree_renewals`, in order: recompute
   the leaves under the entry's `merkle_alg`, fold each via the entry's
   `inclusion_proofs` to its `root_hash`; check `leaf_ids`/`leaf_count` match the
   presented set; check `prev_root` equals the previous effective root (the
   original `root_hash` for the first entry); Ed25519-verify `renewer_signature`
   over the entry's header `{root_hash, merkle_alg, leaf_ids, leaf_count,
   prev_root}`. Any failure -> WITHHELD. The **effective tree** is the newest valid
   renewal (or the original tree if none); its hash is the **effective tree hash**.
   For VERIFIED, the newest renewer key must be the issuer key or match
   `--expected-renewer`.
7. **Timestamps.** For each entry, recompute `digest = H_alg(entry.root)` and
   Ed25519-verify the signature over the canonical envelope
   `{alg, stamped_at, digest, root}`. Any failure -> WITHHELD. A stamp counts
   toward currency only if its key matches `--expected-stamper` (when pins are
   supplied). A stamp is **current** if it covers the effective tree root and its
   algorithm's horizon is in the future.
8. **Horizons.** Trust horizons come from the **verifier's policy**, held out of
   band (built-in defaults, overridable per relying party). The `trust_horizons`
   field inside the capsule is advisory and is NOT read for the verdict, so a
   tampered horizon cannot revive stale crypto. `RESTAMP_NEEDED` if, under that
   policy, the effective tree hash is past its horizon (needs `renew-tree`) OR there
   is no current pinned timestamp over the effective root (needs `restamp`).
9. **Verdict precedence.** WITHHELD (any check failed) > RESTAMP_NEEDED (past a
   horizon) > VERIFIED (all checks pass AND a pinned durable witness verified AND
   the issuer is authenticated AND a pinned current timestamp exists AND, if there
   are renewals, the newest renewer is authenticated) > SELF_CONSISTENT (internal
   checks pass but a trust root is unpinned).

Exit codes: 0 VERIFIED, 1 WITHHELD, 2 FAILED, 3 SELF_CONSISTENT, 4 RESTAMP_NEEDED.

## Honest boundaries (state these, do not bury them)

- **Forward only.** A capsule proves what was true at the moment it was sealed,
  carried forward. It cannot certify un-witnessed history.
- **Durability of the root is external.** Offline verification proves the capsule
  is internally self-consistent and self-authenticating against pinned keys.
  Whether those keys and the root survive decades depends on welding the anchor to
  real, independent, long-lived public witnesses whose own proofs are checked. In
  this sandbox the witnesses and renewal signatures are simulated with local keys;
  `SELF_CONSISTENT` is the honest default until a real durable witness is wired.
- **Two renewals, not one.** Timestamp renewal (a fresh stamp over the current
  root) and hash-tree renewal (rebuilding the tree under a new hash) are distinct,
  per RFC 4998 §1.2 and §5.2. A capsule past the tree-hash horizon needs the
  latter; a timestamp-only renewal will not lift it.
- **Provenance, not truth.** The capsule attests custody and integrity, not the
  truth of the underlying facts.
- **Crypto-agility is partial here.** Renewal rotates the hash family. Rotating the
  *signature* to a post-quantum scheme (e.g. ML-DSA) is future work; this sandbox
  still signs with Ed25519 and says so.

## Changes from 0.1

1. The issuer signs the ordered leaf vector (completeness and uniqueness), not the
   bare root.
2. Timestamps sign their whole envelope including `stamped_at` and the covered
   `root` (no malleable time; each stamp names its root).
3. Witness and stamper keys are authenticated against out-of-band pins, like the
   issuer. A self-asserted anchor is never durable; an unpinned stamp never lifts
   the verdict.
4. Hash-tree renewal is a first-class, verified, chained operation, separate from
   timestamp renewal, and the verifier checks the tree-hash horizon.

## 0.2.1 (verifier hardening, no capsule-format change)

5. Trust horizons are verifier policy, held out of band, not read from the capsule.
   A 0.2 capsule is unaffected; the `trust_horizons` field it carries is now treated
   as advisory and ignored, closing an edit that could revive expired crypto to
   VERIFIED when every key was pinned.
