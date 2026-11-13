#!/usr/bin/env python3
"""
capsule_pack.py — issuer-side: assemble a Continuum Evidence Capsule (spec 0.2).

0.2 changes (all driven by the external boundary review):
  - the issuer signs a SIGNED ROOT HEADER that commits to the ordered leaf vector
    (ids + count), not just root_hash, so the presented record set is pinned
    (no silent omission or duplication).
  - timestamps sign the whole envelope (alg + stamped_at + digest + root), so the
    stamp time is not malleable, and each stamp names the root it covers.
  - anchors and stampers are still carried in-file, but the verifier trusts their
    keys only when pinned out of band (see capsule_verify.py). Pack does not
    decide trust; it only produces the material.

Keys here are generated locally for the sandbox; in production the issuer key is
HSM-held and its PUBLIC half is pinned out of band by the verifier.
"""
import json, hashlib, argparse
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

CAPSULE_VERSION = "0.2"


def cbytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def H(alg: str, b: bytes) -> str:
    return hashlib.new(alg, b).hexdigest()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def pk_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def build_merkle(leaves, alg="sha256"):
    """(root_hash, {leaf_index: inclusion_proof}) under hash `alg`."""
    level = list(leaves)
    proofs = {i: [] for i in range(len(leaves))}
    idx = {i: i for i in range(len(leaves))}
    if len(level) == 1:
        return level[0], proofs
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            L, Rn = level[i], level[i + 1]
            parent = H(alg, (L + Rn).encode())
            nxt.append(parent)
            for o, p in idx.items():
                if p == i:
                    proofs[o].append({"side": "R", "hash": Rn})
                elif p == i + 1:
                    proofs[o].append({"side": "L", "hash": L})
        idx = {o: p // 2 for o, p in idx.items()}
        level = nxt
    return level[0], proofs


def leaf_objects(records, content):
    content_leaf = dict(content)
    content_leaf["id"] = "CONTENT"
    content_leaf["type"] = "CONTENT_COMMITMENT"
    return [content_leaf] + records


def signed_root_header(root_hash, leaf_ids, merkle_alg="sha256"):
    """The object the issuer signs: binds root_hash AND the ordered leaf vector."""
    return {"root_hash": root_hash, "merkle_alg": merkle_alg,
            "leaf_ids": list(leaf_ids), "leaf_count": len(leaf_ids)}


def make_stamp(sk, covered_root, alg, at=None):
    hp = alg.split("+")[0]
    digest = H(hp, covered_root.encode())
    at = at or now_iso()
    env = {"alg": alg, "stamped_at": at, "digest": digest, "root": covered_root}
    return {"alg": alg, "stamped_at": at, "digest": digest, "root": covered_root,
            "pubkey": pk_hex(sk), "signature": sk.sign(cbytes(env)).hex()}


def make_anchor(sk, root_hash, witness, observed=None):
    observed = observed or now_iso()
    env = {"root": root_hash, "witness": witness, "observed_at": observed}
    return {"witness": witness, "root": root_hash, "observed_at": observed,
            "anchor_pubkey": pk_hex(sk), "anchor_signature": sk.sign(cbytes(env)).hex()}


def pack(records, content, witness="demo-beacon", stamp_alg="sha256+ed25519", horizons=None):
    issuer = Ed25519PrivateKey.generate()
    anchor = Ed25519PrivateKey.generate()
    stamper = Ed25519PrivateKey.generate()

    objs = leaf_objects(records, content)
    leaf_ids = [o["id"] for o in objs]
    if len(set(leaf_ids)) != len(leaf_ids):
        raise ValueError("duplicate leaf ids at pack time")
    leaves = [sha256(cbytes(o)) for o in objs]
    root_hash, proofs = build_merkle(leaves, "sha256")
    inclusion = {leaf_ids[i]: proofs[i] for i in range(len(objs))}

    sr = signed_root_header(root_hash, leaf_ids, "sha256")
    issuer_sig = issuer.sign(cbytes(sr)).hex()

    return {
        "capsule_version": CAPSULE_VERSION,
        "spec_ref": "CONTINUUM-CAPSULE-SPEC-0.2",
        "content": content,
        "consent_chain": {"records": records},
        "root": {"root_hash": root_hash, "merkle_alg": "sha256",
                 "leaf_ids": leaf_ids, "leaf_count": len(leaf_ids),
                 "inclusion_proofs": inclusion},
        "key_provenance": {"issuer_id": "CONTINUUM-ISSUER-01", "pubkey_alg": "ed25519",
                           "issuer_pubkey": pk_hex(issuer), "issuer_signature": issuer_sig,
                           "note": "sandbox key; production pins this pubkey out of band"},
        "anchors": [make_anchor(anchor, root_hash, witness)],
        "timestamps": [make_stamp(stamper, root_hash, stamp_alg)],
        "tree_renewals": [],
        "trust_horizons": horizons or {"sha256": "2035-01-01T00:00:00Z",
                                       "sha3_512": "2050-01-01T00:00:00Z",
                                       "sha1": "2017-01-01T00:00:00Z"},
    }


def sample_records():
    return [
        {"id": "REC-0001", "type": "SOURCE_ATTESTATION",
         "source": "licensed-news-corpus-A", "license": "commercial-redistribution",
         "approved_by": "data-governance-lead", "approved_at": "2026-03-01T00:00:00Z",
         "scope": "model:foundation-v2:pretraining"},
        {"id": "REC-0002", "type": "INGEST", "source_ref": "REC-0001",
         "ingested_at": "2026-03-02T00:00:00Z"},
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--witness", default="demo-beacon")
    ap.add_argument("--stamp-alg", default="sha256+ed25519")
    args = ap.parse_args()
    content = {"fingerprint": sha256(b"training-corpus-manifest-bytes"),
               "fingerprint_alg": "sha256", "media_type": "application/jsonl",
               "description": "training corpus source manifest"}
    cap = pack(sample_records(), content, witness=args.witness, stamp_alg=args.stamp_alg)
    with open(args.out, "w") as f:
        json.dump(cap, f, indent=2)
    print(f"packed {args.out}  root={cap['root']['root_hash'][:24]}...  "
          f"witness={args.witness}  stamp={args.stamp_alg}  v{CAPSULE_VERSION}")


if __name__ == "__main__":
    main()
