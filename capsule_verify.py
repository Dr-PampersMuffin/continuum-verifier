#!/usr/bin/env python3
"""
capsule_verify.py — offline, self-contained verifier for a Continuum Evidence Capsule.

The point of this file: it imports NOTHING from the Continuum engine. It reads
only the capsule handed to it, using the Python standard library plus a single
Ed25519 verify (the one primitive stdlib lacks; present in every language). This
is the "stranger in 2050 with only the spec" test. If this file needs the engine,
the capsule is not self-contained.

Verdicts / exit codes: 0 VERIFIED, 1 WITHHELD, 2 FAILED, 3 SELF_CONSISTENT,
4 RESTAMP_NEEDED. See CAPSULE-SPEC-0.1.md.
"""
import sys, json, hashlib, argparse
from datetime import datetime, timezone

# The only non-stdlib primitive: Ed25519 verify.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DURABLE_WITNESSES = {"bitcoin-ots", "ct-log", "nist-beacon"}
REQUIRED = {"capsule_version", "content", "consent_chain", "root",
            "key_provenance", "anchors", "timestamps", "trust_horizons"}


def cbytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def h_alg(name: str, b: bytes) -> str:
    if name not in hashlib.algorithms_available:
        raise ValueError(f"hash algorithm unavailable: {name}")
    return hashlib.new(name, b).hexdigest()


def ed25519_verify(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))


class R:
    def __init__(self, name, ok, detail=""):
        self.name, self.ok, self.detail = name, ok, detail
    def __repr__(self):
        return f"[{'PASS' if self.ok else 'FAIL'}] {self.name}" + (f"  ->  {self.detail}" if self.detail else "")


def fold_inclusion(leaf_hash: str, proof: list) -> str:
    h = leaf_hash
    for step in proof:
        sib = step["hash"]
        if step["side"] == "L":
            h = hashlib.sha256((sib + h).encode()).hexdigest()
        elif step["side"] == "R":
            h = hashlib.sha256((h + sib).encode()).hexdigest()
        else:
            raise ValueError(f"bad inclusion side: {step['side']}")
    return h


def leaf_hash(entry) -> str:
    return hashlib.sha256(cbytes(entry)).hexdigest()


def verify(capsule: dict, now: datetime = None, expected_issuer: str = None):
    now = now or datetime.now(timezone.utc)
    res = []

    missing = REQUIRED - set(capsule.keys())
    if missing:
        return "FAILED", [R("structural", False, f"missing fields: {sorted(missing)}")]
    res.append(R("structural", True, f"capsule v{capsule['capsule_version']}"))

    root_hash = capsule["root"].get("root_hash")
    if not root_hash:
        return "FAILED", res + [R("structural", False, "root.root_hash missing")]

    # 2. inclusion — the content commitment AND every record must fold to the
    #    anchored root. Content is a leaf, not decoration: editing the fingerprint
    #    changes its leaf hash and breaks the fold.
    records = capsule["consent_chain"].get("records", [])
    proofs = capsule["root"].get("inclusion_proofs", {})
    if not records:
        return "FAILED", res + [R("structural", False, "consent_chain.records empty")]
    content_leaf = dict(capsule["content"]); content_leaf["id"] = "CONTENT"
    content_leaf["type"] = "CONTENT_COMMITMENT"
    leaves = [("CONTENT", content_leaf)] + [(r.get("id"), r) for r in records]
    inc_ok = True
    for lid, obj in leaves:
        if lid not in proofs:
            inc_ok = False
            res.append(R("inclusion", False, f"no inclusion proof for leaf {lid!r} (stripped?)"))
            break
        computed = fold_inclusion(leaf_hash(obj), proofs[lid])
        if computed != root_hash:
            inc_ok = False
            res.append(R("inclusion", False,
                         f"leaf {lid}: folds to {computed[:16]}... != root {root_hash[:16]}..."))
            break
    if inc_ok:
        res.append(R("inclusion", True,
                     f"content + {len(records)} record(s) fold to the anchored root"))

    # 3. issuer signature over root, and (if pinned) authentication against the
    #    EXPECTED issuer. Trusted issuer identity must come from OUTSIDE the file:
    #    a self-asserted key proves self-consistency, not that the expected issuer
    #    signed it (swap the embedded key, re-sign, and the file still agrees with
    #    itself). --expected-issuer supplies that out-of-band pin.
    kp = capsule["key_provenance"]
    issuer_authenticated = False
    if not ed25519_verify(kp.get("issuer_pubkey", ""), root_hash.encode(),
                          kp.get("issuer_signature", "")):
        res.append(R("issuer_signature", False, "issuer signature does not verify over root_hash"))
    elif expected_issuer is None:
        res.append(R("issuer_signature", True,
                     f"self-asserted key for issuer {kp.get('issuer_id')!r} "
                     "(no expected issuer pinned; identity UNVERIFIED)"))
    elif kp.get("issuer_pubkey", "").lower() == expected_issuer.lower():
        issuer_authenticated = True
        res.append(R("issuer_signature", True,
                     f"authenticated as the expected issuer {kp.get('issuer_id')!r}"))
    else:
        res.append(R("issuer_signature", False,
                     "authenticated key does NOT match the expected issuer pinned "
                     "out of band (issuer-key substitution)"))

    # 4. anchors — any durable witness?
    durable = False
    any_anchor_ok = False
    for a in capsule["anchors"]:
        msg = cbytes({"root": a.get("root"), "witness": a.get("witness"),
                      "observed_at": a.get("observed_at")})
        ok = (a.get("root") == root_hash) and ed25519_verify(a.get("anchor_pubkey", ""), msg,
                                                             a.get("anchor_signature", ""))
        if ok:
            any_anchor_ok = True
            if a.get("witness") in DURABLE_WITNESSES:
                durable = True
    res.append(R("anchor", any_anchor_ok,
                 ("durable witness verified" if durable else
                  "anchor verifies but witness is self-asserted (not in durable set)")
                 if any_anchor_ok else "no anchor signature verifies over root"))

    # 5. re-stamp trail + crypto horizon
    stamps = capsule["timestamps"]
    horizons = capsule["trust_horizons"]
    stamps_ok = True
    for s in stamps:
        hash_part = s.get("alg", "").split("+")[0]
        try:
            digest = h_alg(hash_part, root_hash.encode())
        except ValueError as e:
            stamps_ok = False
            res.append(R("restamp_trail", False, str(e))); break
        ok = (digest == s.get("digest")) and ed25519_verify(
            s.get("pubkey", ""), s.get("digest", "").encode(), s.get("signature", ""))
        if not ok:
            stamps_ok = False
            res.append(R("restamp_trail", False, f"stamp alg={s.get('alg')} failed")); break
    restamp_needed = False
    newest_alg = None
    if stamps_ok and stamps:
        newest = sorted(stamps, key=lambda s: _iso(s["stamped_at"]))[-1]
        newest_alg = newest.get("alg")
        hash_part = newest_alg.split("+")[0]
        horizon = horizons.get(hash_part) or horizons.get(newest_alg)
        if horizon and _iso(horizon) < now:
            restamp_needed = True
        res.append(R("restamp_trail", True,
                     f"{len(stamps)} stamp(s); newest {newest_alg} horizon {horizon}"
                     + ("  PAST HORIZON" if restamp_needed else "")))
    elif stamps_ok:
        res.append(R("restamp_trail", False, "no timestamps present"))
        stamps_ok = False

    # 6. precedence
    all_pass = all(r.ok for r in res)
    if not all_pass:
        return "WITHHELD", res
    if restamp_needed:
        return "RESTAMP_NEEDED", res
    if durable and issuer_authenticated:
        return "VERIFIED", res
    return "SELF_CONSISTENT", res


EXIT = {"VERIFIED": 0, "WITHHELD": 1, "FAILED": 2, "SELF_CONSISTENT": 3, "RESTAMP_NEEDED": 4}


def render(verdict, res, path):
    print(f"capsule_verify.py  ·  {path}  ·  engine imports: none")
    print("-" * 74)
    for r in res:
        print(r)
    print("-" * 74)
    msg = {
        "VERIFIED": "checks pass, a durable witness anchors the root, and the key is authenticated as the expected issuer",
        "WITHHELD": "a check failed; tampered or malformed; no confident answer by design",
        "FAILED": "not parseable as a Continuum Evidence Capsule",
        "SELF_CONSISTENT": "internally self-verifying, but not bound to BOTH a durable witness and an expected issuer; self-consistent, not authenticated",
        "RESTAMP_NEEDED": "self-verifying, but newest crypto is past its trust horizon; re-stamp before trusting",
    }[verdict]
    print(f"VERDICT: {verdict}   {msg}")
    return verdict


def main():
    ap = argparse.ArgumentParser(description="Offline verifier for a Continuum Evidence Capsule")
    ap.add_argument("capsule")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--now", help="override 'now' as ISO (for testing crypto horizons)")
    ap.add_argument("--expected-issuer",
                    help="hex Ed25519 public key of the expected issuer, pinned out of band; "
                         "required for a VERIFIED verdict (otherwise the issuer is UNVERIFIED)")
    args = ap.parse_args()
    try:
        with open(args.capsule) as f:
            cap = json.load(f)
    except Exception as e:
        if not args.quiet:
            print(f"FAILED to load {args.capsule}: {e}")
        sys.exit(2)
    now = _iso(args.now) if args.now else None
    verdict, res = verify(cap, now=now, expected_issuer=args.expected_issuer)
    if not args.quiet:
        render(verdict, res, args.capsule)
    sys.exit(EXIT[verdict])


if __name__ == "__main__":
    main()
