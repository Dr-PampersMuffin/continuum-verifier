# Continuum Evidence Capsule

An open, offline verifier for portable provenance records.

A **capsule** is one self-contained file that carries a content fingerprint, a
chain of signed records (who attested to what, and when), Merkle inclusion
proofs, the issuer's key, public-witness anchors, and a re-stamp trail. A
stranger with no internet, no access to the issuer, and only this repo can hand
the capsule to the verifier and get an answer. That is the point: the proof
travels, and it keeps working after the system that made it is gone.

The verifier imports **nothing** from any server or private engine. It reads
only the capsule. The test suite proves this by running the verifier in a bare
directory that holds nothing but the verifier and a capsule.

## Quickstart

```bash
# verify a capsule (offline, no keys, no network)
python3 capsule_verify.py samples/sample_capsule_durable.json

# the self-asserted sample (no durable witness) returns SELF_CONSISTENT
python3 capsule_verify.py samples/sample_capsule_selfasserted.json

# run the adversarial suite: clean capsules + every tamper + the battery swap
python3 attack_capsule.py        # 14/14 expected

# make your own capsule, then re-stamp it onto fresh crypto
python3 capsule_pack.py mycap.json --witness nist-beacon
python3 capsule_restamp.py mycap.json mycap.v2.json
```

Only dependency beyond the Python standard library is an Ed25519 verify
(`pip install cryptography`). Everything else is stdlib.

## Verdicts

- **VERIFIED** — every check passes AND a durable public witness anchors the root.
- **SELF_CONSISTENT** — internally self-verifying, but the witness is self-asserted; durability over time is unproven.
- **RESTAMP_NEEDED** — self-verifying, but the newest crypto is past its trust horizon. The verifier is telling you the proof needs re-stamping before you trust it.
- **WITHHELD** — a hash, signature, or inclusion check failed. No confident answer, by design.
- **FAILED** — not parseable as a capsule.

## What it proves, and what it does not

Proves: a verified record was attested by a named key, is unmodified, folds into
a single anchored root (content included, not as decoration), and carries no
crypto past its trust horizon. The format is designed so that proving *when*
something was attested is a first-class check, not an afterthought.

Does **not** prove: the truth of the underlying facts. A capsule attests
custody and integrity. Whether a claim inside it is true is a separate question.

## Honest status (read before relying on it)

This is a reference implementation at **v0.1**, published to be read and broken.

- The public witnesses and re-stamp signatures in the samples are **simulated
  with local keys**. A sample witness named `nist-beacon` is a stand-in.
  VERIFIED here means "would verify against a durable witness," not "is welded
  to one." Wiring a real durable witness (OpenTimestamps, a transparency log) is
  the next step.
- The re-stamp trail rotates the hash family (SHA-256 to SHA3-512) to show the
  mechanism. Rotating the signature to a post-quantum scheme is not done yet.
- Forward only: a capsule attests what was true when it was sealed, carried
  forward. It cannot certify history that was never witnessed.

See `CAPSULE-SPEC-0.1.md` for the full, language-agnostic verification algorithm
and the complete list of boundaries.

## Break it

The suite ships 10+ tampers and a stress test, all expected to return WITHHELD.
If you find an input that verifies and should not, that is the most useful issue
you can open. PRs and adversarial test cases welcome.

## License

MIT. See `LICENSE`. (Can be relicensed to Apache-2.0 later if a standards body
prefers its patent grant.)
