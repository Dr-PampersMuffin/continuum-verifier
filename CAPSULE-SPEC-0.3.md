# Continuum Evidence Capsule — Spec 0.3

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
header = {"capsule_version":"0.3", "root_hash":<hex>, "merkle_alg":"sha256",
          "leaf_ids":[<ordered ids, CONTENT first>], "leaf_count":<n>,
          "issuer_id":<str>, "pubkey_alg":"ed25519"}
issuer_signature = Ed25519(header canonical-bytes)
```

Because the ordered leaf vector is signed, the presented records must reproduce it
exactly. Omitting or duplicating a record changes `leaf_ids` or its length and
breaks the check. Binding `capsule_version` blocks a downgrade that would skip the
newer checks.

## Exact byte forms (so an independent reader needs no source)

- **Content leaf.** The content object becomes a leaf by adding two fields:
  `id = "CONTENT"` and `type = "CONTENT_COMMITMENT"`. Both are present when it is
  canonicalized and hashed.
- **Leaf hash.** `leaf = H_alg(canonical(leaf_object))`, `alg` = the tree's
  `merkle_alg`.
- **Merkle fold over hex text.** Siblings are hex strings and are concatenated AS
  TEXT, then UTF-8 encoded, then hashed: `side=L -> H_alg((sibling + h).encode())`,
  `side=R -> H_alg((h + sibling).encode())`. The raw digest bytes are not
  concatenated; the hex strings are.
- **Anchor signature.** An anchor signs canonical `{root, witness, observed_at}`.
- **Timestamp.** `digest = H_hashpart(root.encode())` where `root` is the hex string
  of the covered root and `hashpart` is the part of `alg` before `+`. The stamp signs
  canonical `{alg, stamped_at, digest, root, prev}`, so the stamp time, covered root
  and chain link are inside the signature.
- **Timestamp chain.** `prev` is `""` for the first timestamp, and otherwise the
  SHA-256 hex of the canonical bytes of the whole previous timestamp object (all its
  fields including its signature). This links the timestamps into a hash chain, so
  "the next timestamp" is cryptographic, not merely array order, which the RFC 4998
  5.3 check below relies on.
- **Hash-tree renewal.** The renewer signs canonical `{root_hash, merkle_alg,
  leaf_ids, leaf_count, prev_root, renewed_at}`. `renewed_at` is inside the signature,
  so the renewal time is not malleable.

## Verification algorithm (language-agnostic; re-implement anywhere)

1. **Version / structure.** `capsule_version` must be `0.3`, else WITHHELD.
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
   prev_root, renewed_at}`. Any failure -> WITHHELD. The **effective tree** is the newest valid
   renewal (or the original tree if none); its hash is the **effective tree hash**.
   For VERIFIED, the newest renewer key must be the issuer key or match
   `--expected-renewer`.
7. **Timestamps.** For each entry in order, check the chain link `prev` (`""` for the
   first, else SHA-256 of the canonical previous entry), recompute
   `digest = H_alg(entry.root)`, and Ed25519-verify the signature over the canonical
   envelope `{alg, stamped_at, digest, root, prev}`. Any failure, including a broken
   chain link, -> WITHHELD. A stamp counts toward currency only if its key matches
   `--expected-stamper` (when pins are supplied). A stamp is **current** if it covers
   the effective tree root and its algorithm's horizon is in the future.
8. **Horizons.** Trust horizons come from the **verifier's policy**, held out of
   band (built-in defaults, overridable per relying party). The `trust_horizons`
   field inside the capsule is advisory and is NOT read for the verdict, so a
   tampered horizon cannot revive stale crypto. `RESTAMP_NEEDED` if, under that
   policy, the effective tree hash is past its horizon (needs `renew-tree`) OR there
   is no current pinned timestamp over the effective root (needs `restamp`).
8b. **Ordering.** Renewal and stamp times must be coherent. Because `renewed_at`
   (renewal) and `stamped_at` (stamp) are inside signatures, they are authenticated.
   A renewal must not be dated before the root it renews: its `renewed_at` is at or
   after the LATEST signed time over the prior root (the latest stamp or anchor on it,
   and the previous renewal), not the earliest, so a backdated stamp cannot lower the
   floor. A stamp over a renewal root is at or after that renewal. Any violation
   -> WITHHELD.
8c. **Rollback (optional, fail-closed).** A relying party may pin
   `expected_newest`, the hex of the newest root it knows exists. If that root is not
   present among the capsule's roots (original plus every renewal), the capsule may be
   a truncated or rolled-back prefix -> WITHHELD. Absent the pin, this check is skipped.
8d. **RFC 4998 5.3 timestamp validity.** Every timestamp that has a NEXT one in the
   chain must have been valid at the moment the next was applied, the reference time
   being the next timestamp's signed `stamped_at`. "Valid" means: the stamp's hash was
   within horizon at the reference time, AND, when a key validity window is supplied as
   policy (`stamper_windows`, keyed by pubkey), the reference time falls within it. A
   key pinned with no window is trusted at all reference times for the key check; the
   hash-horizon check still applies. Each hash-tree renewal must likewise have been
   made while the PRIOR tree hash was still within horizon. Any violation -> WITHHELD.
   The newest timestamp has no next; its freshness at V is the horizon check of step 8
   (RESTAMP_NEEDED), not a 5.3 failure. Because every timestamp signature is checked,
   an invalid earlier signature fails even when later links are valid.
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

## 0.2.2 (renewal hardening, from the shared renewal vector)

6. `renewed_at` moved inside the renewer-signed header, so a renewal's time is
   authenticated, not malleable.
7. **Ordering** is checked (step 8b): a renewal dated before the root it renews, or
   out of order, is WITHHELD.
8. **Anti-rollback** (step 8c): an optional `expected_newest` pin fails closed on a
   truncated prefix.
9. Deprecated (`sha1`, `md5`) and unknown hash algorithms are **refused at renewal
   time** by the packer tools, not only flagged by horizon at verify time.
10. The exact byte forms (content-leaf `type`, hex-text Merkle fold, anchor and stamp
    and renewal signed messages) are written out above, so an independent reader needs
    no source. Known honest limit, shared with RFC 4998 renewal: a hash-tree renewal
    re-digests the leaf OBJECTS under the new hash, but the content leaf still binds
    the external content through its `sha256` fingerprint; re-binding the content
    itself under a new hash requires the content at renewal time and is not yet done.

## 0.3 (timestamp chain and RFC 4998 5.3; capsule-format change)

A 0.2 capsule does not verify under 0.3; re-issue. The changes:

11. `capsule_version` is inside the issuer-signed root header, blocking a version
    downgrade that would skip the newer checks.
12. Timestamps form a hash chain: each carries a `prev` link (SHA-256 of the previous
    timestamp), inside its signature. "The next timestamp" is now cryptographic.
13. **RFC 4998 5.3** is enforced (step 8d): each covered timestamp must have been valid
    (hash within horizon, and within its key window when windows are given as policy)
    at the time the next timestamp was applied, and each renewal made while the prior
    tree hash was in horizon. Reference time is the next timestamp's signed time.
14. Stamper key validity windows may be supplied as verifier policy
    (`stamper_windows` / `--stamper-window`). A pinned key with no window is trusted at
    all times for the key check; the hash-horizon check always applies.
