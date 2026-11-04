#!/usr/bin/env python3
"""
capsule_restamp.py — the battery swap. Re-commit a capsule's root under a fresh
algorithm before the old one weakens, extending its life. RFC 4998 ERS in spirit.

A re-stamp never rewrites history: it appends a new timestamp over the SAME
root_hash. The existing stamps stay; the newest one carries the current crypto.
"""
import sys, json, hashlib, argparse
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def pk_hex(sk):
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def restamp(capsule, alg="sha3_512+ed25519", at=None):
    root_hash = capsule["root"]["root_hash"]
    hash_part = alg.split("+")[0]
    if hash_part not in hashlib.algorithms_available:
        raise SystemExit(f"hash algorithm unavailable here: {hash_part}")
    digest = hashlib.new(hash_part, root_hash.encode()).hexdigest()
    sk = Ed25519PrivateKey.generate()
    capsule["timestamps"].append({
        "alg": alg, "stamped_at": at or now_iso(), "digest": digest,
        "pubkey": pk_hex(sk), "signature": sk.sign(digest.encode()).hex()})
    capsule.setdefault("trust_horizons", {}).setdefault(
        hash_part, {"sha3_512": "2050-01-01T00:00:00Z"}.get(hash_part, "2050-01-01T00:00:00Z"))
    return capsule


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capsule")
    ap.add_argument("out")
    ap.add_argument("--alg", default="sha3_512+ed25519")
    ap.add_argument("--at", help="ISO timestamp for the new stamp (testing)")
    args = ap.parse_args()
    with open(args.capsule) as f:
        cap = json.load(f)
    cap = restamp(cap, alg=args.alg, at=args.at)
    with open(args.out, "w") as f:
        json.dump(cap, f, indent=2)
    print(f"re-stamped {args.capsule} -> {args.out} under {args.alg} ({len(cap['timestamps'])} stamps total)")


if __name__ == "__main__":
    main()
