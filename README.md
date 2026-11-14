# Continuum Evidence Capsule

An open, offline verifier for portable provenance records.

A **capsule** is one self-contained file that carries a content fingerprint, a
chain of signed records (who attested to what, and when), Merkle inclusion
proofs, the issuer's key, public-witness anchors, and a renewal trail. A
stranger with no internet, no access to the issuer, and only this repo can hand
the capsule to the verifier and get an answer. That is the point: the proof
travels, and it keeps working after the system that made it is gone.

The verifier imports **nothing** from any server or private engine. It reads
only the capsule. The test suite proves this by running the verifier in a bare
directory that holds nothing but the verifier and a capsule.

## Quickstart

```bash
# verify a capsule (offline, no keys, no network). With no pins, the honest
# default verdict is SELF_CONSISTENT: the file agrees with itself, nothing more.
python3 capsule_verify.py samples/sample_capsule_durable.json

# run the adversarial suite: clean capsules + every tamper + the renewal paths
# + the external-review boundary regressions
python3 attack_capsule.py        # 30/30 expected

# make your own capsule
python3 capsule_pack.py mycap.json --witness nist-beacon

# timestamp renewal (battery swap): a new stamp over the current root, fresh crypto
python3 capsule_restamp.py mycap.json mycap.v2.json --mode restamp --alg sha3_512+ed25519

# hash-tree renewal: rebuild the tree under a new hash before the old one weakens
python3 capsule_restamp.py mycap.json mycap.v2.json --mode renew-tree --alg sha3_512

# VERIFIED requires trust roots pinned OUT OF BAND, not read from the file:
python3 capsule_verify.py mycap.json \
  --expected-issuer  <issuer_pubkey_hex> \
  --expected-witness nist-beacon=<witness_pubkey_hex> \
  --expected-stamper <stamper_pubkey_hex>
```

Only dependency beyond the Python standard library is an Ed25519 verify
(`pip install cryptography`). Everything else is stdlib.

## Verdicts

- **VERIFIED** — every check passes; a **pinned** durable public witness anchors the root; the issuer and the current timestamp authority are authenticated against keys pinned out of band; and both the tree hash and the newest timestamp are within their trust horizons.
- **SELF_CONSISTENT** — internally self-verifying, but a trust root is unpinned (witness, issuer, and/or stamper). The record agrees with itself; it is not authenticated.
- **RESTAMP_NEEDED** — self-verifying, but the tree hash and/or the newest timestamp is past its trust horizon. Renew (re-stamp or renew-tree) before trusting.
- **WITHHELD** — a hash, signature, inclusion, or leaf-set check failed, or a key does not match its out-of-band pin. No confident answer, by design.
- **FAILED** — not parseable as a 0.2 capsule.

## Trust roots come from outside the file

Every key that travels **inside** the capsule proves only that the file agrees
with itself: swap an embedded key, re-sign, and it still "verifies." That is
self-consistency, not authentication. To authenticate, the verifier takes the
key from outside the file, pinned out of band:

- `--expected-issuer <hex>` — the issuer key. Without it, the issuer is UNVERIFIED.
- `--expected-witness NAME=<hex>` — the durable-witness key. Without it, a witness
  named `nist-beacon` is just a self-asserted string and is **not** treated as durable.
- `--expected-stamper <hex>` — the timestamp-authority key whose stamp establishes
  currency. Without it, a fresh self-generated stamp cannot lift the verdict.

This rule is uniform: issuer, witness, and stamper are all authenticated the same
way, or not at all.

**Trust horizons are policy, not payload.** When each algorithm stops being trusted
is the verifier's decision, held out of band, with built-in defaults and an optional
`--horizon NAME=ISO` override. Any `trust_horizons` value carried inside a capsule is
advisory and ignored, so editing it cannot revive stale crypto.

## What it proves, and what it does not

Proves: a verified record was attested by a pinned key, is unmodified, is the
**exact committed set** of records (no omission, no duplication — the issuer
signs the ordered leaf vector, not just the root), folds into a single anchored
root (content included, not as decoration), and carries crypto within its trust
horizon for both the hash tree and the timestamp.

Does **not** prove: the truth of the underlying facts. A capsule attests custody
and integrity. Whether a claim inside it is true is a separate question.

## Honest status (read before relying on it)

This is a reference implementation at **v0.2**, published to be read and broken.

- The public witnesses and renewal signatures in the samples are **simulated with
  local keys**. A sample witness named `nist-beacon` is a stand-in; VERIFIED here
  means "would verify against a pinned durable witness," not "is welded to a live
  one." Wiring a real durable witness (OpenTimestamps, a transparency log, whose
  own proof format is checked, not an Ed25519 signature we mint) is the next step.
- Signatures are Ed25519. Rotating the signature to a post-quantum scheme is not
  done yet; the hash family already rotates (SHA-256 to SHA3-512) via renewal.
- Forward only: a capsule attests what was true when it was sealed, carried
  forward. It cannot certify history that was never witnessed.

## 0.2: what changed, and why

0.2 closes four boundary gaps raised in external review (K. Gruszka, Nov 2026),
each now a named regression in `attack_capsule.py`:

1. **Durable witness was forgeable.** The anchor key was read from the capsule, so
   a self-signed `nist-beacon` anchor reached VERIFIED. Fixed: witness keys are
   pinned out of band; a self-asserted anchor is never durable.
2. **Timestamps were malleable and unpinned.** The signature covered only the
   digest, so `stamped_at` could be edited freely, and a fresh unpinned key could
   lift a stale capsule. Fixed: the whole stamp envelope (alg, time, digest, root)
   is signed, and only a pinned stamper establishes currency.
3. **Inclusion was not completeness.** Dropping or duplicating a record still
   verified. Fixed: the issuer signs the ordered leaf vector, and the presented
   records must match it exactly.
4. **Renewal conflated two things.** A re-stamp renewed the timestamp but left the
   SHA-256 tree in place (RFC 4998 §5.2 distinguishes the two). Fixed: the verifier
   checks the tree hash horizon as well, and `--mode renew-tree` rebuilds the tree
   under a fresh hash, chained to the old root.

5. **Trust horizons were attacker-controlled.** The verifier read `trust_horizons`
   from the capsule, so with every key pinned, editing a horizon to a far-future
   date revived expired crypto to VERIFIED. Fixed: horizons are verifier policy
   (built-in defaults, `--horizon` to override); the capsule's copy is ignored.

See `CAPSULE-SPEC-0.2.md` for the full, language-agnostic verification algorithm.

## Break it

If you find an input that verifies and should not, that is the most useful issue
you can open. PRs and adversarial test cases welcome — the four above came in that
way and made the format stronger.

## License

MIT. See `LICENSE`.
