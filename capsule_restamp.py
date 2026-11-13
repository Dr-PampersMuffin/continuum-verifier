#!/usr/bin/env python3
"""
capsule_restamp.py — keep a capsule alive as crypto ages. Spec 0.2 separates the
two RFC 4998 renewal kinds that 0.1 collapsed into one:

  TIMESTAMP RENEWAL (--restamp):   append a new timestamp over the CURRENT effective
      root under a fresh signature/hash. Protects against the timestamp's own crypto
      ageing. Does NOT renew the hash-tree.

  HASH-TREE RENEWAL (--renew-tree): re-hash the leaf DATA under a new hash algorithm,
      rebuild the Merkle tree under it, chain the new root to the previous one, and
      sign the new signed-root header. This is what survives a break in the TREE hash
      (RFC 4998 s5.2). A renewer key signs it and must be pinned out of band, exactly
      like the issuer key.

Neither rewrites history: both append. Old stamps and old trees remain.
"""
import json, hashlib, argparse
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import capsule_pack as P


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def pk_hex(sk):
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def effective_root(capsule):
    """The root the capsule's integrity currently hangs on: the newest tree
    renewal's root, or the original root_hash if there are none."""
    rns = capsule.get("tree_renewals", [])
    return rns[-1]["root_hash"] if rns else capsule["root"]["root_hash"]


def restamp(capsule, alg="sha3_512+ed25519", at=None, stamper=None):
    """Timestamp renewal: stamp the CURRENT effective root under a fresh alg."""
    sk = stamper or Ed25519PrivateKey.generate()
    root = effective_root(capsule)
    capsule["timestamps"].append(P.make_stamp(sk, root, alg, at=at))
    hp = alg.split("+")[0]
    capsule.setdefault("trust_horizons", {}).setdefault(
        hp, {"sha3_512": "2050-01-01T00:00:00Z"}.get(hp, "2050-01-01T00:00:00Z"))
    return capsule


def renew_tree(capsule, records, content, alg="sha3_512", renewer=None, at=None, stamp=True):
    """Hash-tree renewal: rebuild the tree over the SAME leaf data under a new hash
    `alg`, chain it to the previous root, sign the new header with a renewer key.
    The caller passes the same records/content the capsule was built from (the leaf
    data a renewer legitimately holds)."""
    sk = renewer or Ed25519PrivateKey.generate()
    objs = P.leaf_objects(records, content)
    leaf_ids = [o["id"] for o in objs]
    leaves = [P.H(alg, P.cbytes(o)) for o in objs]
    new_root, proofs = P.build_merkle(leaves, alg)
    inclusion = {leaf_ids[i]: proofs[i] for i in range(len(objs))}
    prev = effective_root(capsule)
    header = {"root_hash": new_root, "merkle_alg": alg,
              "leaf_ids": leaf_ids, "leaf_count": len(leaf_ids), "prev_root": prev}
    entry = dict(header,
                 inclusion_proofs=inclusion,
                 renewed_at=at or now_iso(),
                 renewer_pubkey=pk_hex(sk),
                 renewer_signature=sk.sign(P.cbytes(header)).hex())
    capsule.setdefault("tree_renewals", []).append(entry)
    capsule.setdefault("trust_horizons", {}).setdefault(
        alg, {"sha3_512": "2050-01-01T00:00:00Z"}.get(alg, "2050-01-01T00:00:00Z"))
    if stamp:
        # a fresh timestamp over the NEW effective root, so currency follows the new tree
        restamp(capsule, alg=f"{alg}+ed25519", at=at)
    return capsule


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capsule")
    ap.add_argument("out")
    ap.add_argument("--mode", choices=["restamp", "renew-tree"], default="restamp")
    ap.add_argument("--alg", default=None)
    ap.add_argument("--at")
    args = ap.parse_args()
    with open(args.capsule) as f:
        cap = json.load(f)
    if args.mode == "restamp":
        cap = restamp(cap, alg=args.alg or "sha3_512+ed25519", at=args.at)
        print(f"timestamp-renewed {args.capsule} -> {args.out} "
              f"({len(cap['timestamps'])} stamps)")
    else:
        recs = cap["consent_chain"]["records"]
        cap = renew_tree(cap, recs, cap["content"], alg=args.alg or "sha3_512", at=args.at)
        print(f"hash-tree-renewed {args.capsule} -> {args.out} under {args.alg or 'sha3_512'} "
              f"({len(cap['tree_renewals'])} renewal(s))")
    with open(args.out, "w") as f:
        json.dump(cap, f, indent=2)


if __name__ == "__main__":
    main()
