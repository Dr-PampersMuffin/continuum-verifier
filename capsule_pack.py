#!/usr/bin/env python3
"""
capsule_pack.py — issuer-side: assemble a Continuum Evidence Capsule.

Produces a self-contained capsule that capsule_verify.py can check offline with
no engine. Keys here are generated locally for the sandbox; in production the
issuer key is HSM-held and its PUBLIC half is pinned out of band by the verifier.
"""
import sys, json, hashlib, argparse
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def cbytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def pk_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def build_merkle(leaves):
    """Return (root_hash, {leaf_index: inclusion_proof}). Proof step:
    {'side':'L'|'R','hash':sibling} where side is the SIBLING's position."""
    level = list(leaves)
    proofs = {i: [] for i in range(len(leaves))}
    idx_at_level = {i: i for i in range(len(leaves))}
    if len(level) == 1:
        return level[0], proofs
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            L, Rn = level[i], level[i + 1]
            parent = sha256((L + Rn).encode())
            nxt.append(parent)
            for orig, pos in idx_at_level.items():
                if pos == i:
                    proofs[orig].append({"side": "R", "hash": Rn})
                elif pos == i + 1:
                    proofs[orig].append({"side": "L", "hash": L})
        idx_at_level = {orig: pos // 2 for orig, pos in idx_at_level.items()}
        level = nxt
    return level[0], proofs


def pack(records, content, witness="demo-beacon", stamp_alg="sha256+ed25519",
         horizons=None):
    issuer = Ed25519PrivateKey.generate()
    anchor = Ed25519PrivateKey.generate()
    stamper = Ed25519PrivateKey.generate()

    # Content is a leaf, so it is bound into the signed + anchored root.
    content_leaf = dict(content); content_leaf["id"] = "CONTENT"
    content_leaf["type"] = "CONTENT_COMMITMENT"
    leaf_objs = [content_leaf] + records
    leaves = [sha256(cbytes(o)) for o in leaf_objs]
    root_hash, proofs = build_merkle(leaves)
    inclusion_proofs = {leaf_objs[i]["id"]: proofs[i] for i in range(len(leaf_objs))}

    issuer_sig = issuer.sign(root_hash.encode()).hex()

    observed = now_iso()
    anchor_obj = {"witness": witness, "root": root_hash, "observed_at": observed}
    anchor_sig = anchor.sign(cbytes({"root": root_hash, "witness": witness,
                                     "observed_at": observed})).hex()

    hash_part = stamp_alg.split("+")[0]
    digest = hashlib.new(hash_part, root_hash.encode()).hexdigest()
    stamp = {"alg": stamp_alg, "stamped_at": now_iso(), "digest": digest,
             "pubkey": pk_hex(stamper), "signature": stamper.sign(digest.encode()).hex()}

    return {
        "capsule_version": "0.1",
        "spec_ref": "CONTINUUM-CAPSULE-SPEC-0.1",
        "content": content,
        "consent_chain": {"records": records},
        "root": {"root_hash": root_hash, "merkle_alg": "sha256",
                 "inclusion_proofs": inclusion_proofs},
        "key_provenance": {"issuer_id": "CONTINUUM-ISSUER-01",
                           "pubkey_alg": "ed25519",
                           "issuer_pubkey": pk_hex(issuer),
                           "issuer_signature": issuer_sig,
                           "note": "sandbox key; production pins this pubkey out of band"},
        "anchors": [dict(anchor_obj, anchor_pubkey=pk_hex(anchor), anchor_signature=anchor_sig)],
        "timestamps": [stamp],
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
    print(f"packed {args.out}  root={cap['root']['root_hash'][:24]}...  witness={args.witness}  stamp={args.stamp_alg}")


if __name__ == "__main__":
    main()
