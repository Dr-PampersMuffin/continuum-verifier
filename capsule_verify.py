#!/usr/bin/env python3
"""
capsule_verify.py — offline, self-contained verifier for a Continuum Evidence
Capsule (spec 0.2). Imports NOTHING from the Continuum engine: standard library
plus a single Ed25519 verify. The "stranger in 2050 with only the spec" test.

Spec 0.2 closes four boundary gaps found in external review:
  1. Durable witness keys are trusted only when PINNED out of band
     (--expected-witness NAME=HEX). A self-signed anchor is never "durable".
  2. Timestamps sign the whole envelope (alg + stamped_at + digest + root), so the
     stamp time is not malleable; stamper keys count toward currency only when
     pinned (--expected-stamper HEX).
  3. The issuer signs a SIGNED ROOT HEADER committing to the ordered leaf vector,
     so the presented record set must match exactly: no omission, no duplication.
  4. Timestamp renewal and hash-tree renewal are distinct. The verifier checks BOTH
     the newest timestamp's horizon AND the effective tree hash's horizon, and can
     verify a chained hash-tree renewal under a fresh hash algorithm.

Verdicts / exit codes: 0 VERIFIED, 1 WITHHELD, 2 FAILED, 3 SELF_CONSISTENT,
4 RESTAMP_NEEDED. See CAPSULE-SPEC-0.2.md.
"""
import sys, json, hashlib, argparse
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

SPEC_VERSION = "0.2"
DURABLE_WITNESSES = {"bitcoin-ots", "ct-log", "nist-beacon"}
# Trust horizons are the VERIFIER's policy, held out of band, NOT read from the
# capsule. A capsule may carry an advisory `trust_horizons` hint, but it is ignored
# for the verdict: a tampered hint must not be able to revive stale crypto.
DEFAULT_HORIZONS = {"md5": "2010-01-01T00:00:00Z", "sha1": "2017-01-01T00:00:00Z",
                    "sha256": "2035-01-01T00:00:00Z", "sha384": "2045-01-01T00:00:00Z",
                    "sha512": "2050-01-01T00:00:00Z", "sha3_256": "2045-01-01T00:00:00Z",
                    "sha3_512": "2050-01-01T00:00:00Z"}
REQUIRED = {"capsule_version", "content", "consent_chain", "root",
            "key_provenance", "anchors", "timestamps"}


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


def fold(leaf_hash: str, proof: list, alg: str) -> str:
    h = leaf_hash
    for step in proof:
        sib = step["hash"]
        if step["side"] == "L":
            h = h_alg(alg, (sib + h).encode())
        elif step["side"] == "R":
            h = h_alg(alg, (h + sib).encode())
        else:
            raise ValueError(f"bad inclusion side: {step['side']}")
    return h


def leaf_hash(entry, alg: str) -> str:
    return h_alg(alg, cbytes(entry))


def _pin_map(pairs):
    out = {}
    for p in pairs or []:
        k, _, v = p.partition("=")
        out[k.strip()] = v.strip().lower()
    return out


def verify(capsule, now=None, expected_issuer=None,
           expected_witnesses=None, expected_stampers=None, expected_renewer=None,
           horizons=None, expected_newest=None):
    now = now or datetime.now(timezone.utc)
    policy = {**DEFAULT_HORIZONS, **(horizons or {})}
    expected_witnesses = {k: v.lower() for k, v in (expected_witnesses or {}).items()}
    expected_stampers = set(s.lower() for s in expected_stampers) if expected_stampers else None
    res = []

    if capsule.get("capsule_version") != SPEC_VERSION:
        return "WITHHELD", [R("version", False,
            f"capsule_version {capsule.get('capsule_version')!r}; this verifier requires {SPEC_VERSION} (re-issue)")]

    missing = REQUIRED - set(capsule.keys())
    if missing:
        return "FAILED", [R("structural", False, f"missing fields: {sorted(missing)}")]
    res.append(R("structural", True, f"capsule v{capsule['capsule_version']}"))

    root = capsule["root"]
    root_hash = root.get("root_hash")
    if not root_hash:
        return "FAILED", res + [R("structural", False, "root.root_hash missing")]

    # reconstruct the leaf objects the issuer committed to
    records = capsule["consent_chain"].get("records", [])
    if not records:
        return "FAILED", res + [R("structural", False, "consent_chain.records empty")]
    content_leaf = dict(capsule["content"]); content_leaf["id"] = "CONTENT"
    content_leaf["type"] = "CONTENT_COMMITMENT"
    objs = [content_leaf] + records
    present_ids = [o.get("id") for o in objs]

    # (3) LEAF-SET COMMITMENT — presented leaves must match the committed vector
    committed = root.get("leaf_ids")
    if committed is None or root.get("leaf_count") != len(committed):
        res.append(R("leaf_set", False, "root.leaf_ids / leaf_count missing or inconsistent"))
    elif len(set(present_ids)) != len(present_ids):
        res.append(R("leaf_set", False, f"duplicate leaf id among presented leaves {present_ids}"))
    elif present_ids != committed:
        res.append(R("leaf_set", False, f"presented {present_ids} != committed {committed} (omission/addition)"))
    else:
        res.append(R("leaf_set", True, f"presented leaves match the committed set exactly ({len(committed)} leaves)"))

    # (2a) INCLUSION under the original tree hash
    proofs = root.get("inclusion_proofs", {})
    inc_ok = True
    for o in objs:
        lid = o.get("id")
        if lid not in proofs:
            inc_ok = False; res.append(R("inclusion", False, f"no inclusion proof for leaf {lid!r} (stripped?)")); break
        if fold(leaf_hash(o, "sha256"), proofs[lid], "sha256") != root_hash:
            inc_ok = False; res.append(R("inclusion", False, f"leaf {lid} does not fold to the anchored root")); break
    if inc_ok:
        res.append(R("inclusion", True, f"content + {len(records)} record(s) fold to the anchored root"))

    # (3) ISSUER SIGNATURE over the signed root header (binds root AND leaf vector)
    kp = capsule["key_provenance"]
    header = {"root_hash": root_hash, "merkle_alg": root.get("merkle_alg", "sha256"),
              "leaf_ids": committed, "leaf_count": root.get("leaf_count")}
    issuer_authenticated = False
    if not ed25519_verify(kp.get("issuer_pubkey", ""), cbytes(header), kp.get("issuer_signature", "")):
        res.append(R("issuer_signature", False, "issuer signature does not verify over the signed root header"))
    elif expected_issuer is None:
        res.append(R("issuer_signature", True,
                     f"self-asserted key for issuer {kp.get('issuer_id')!r} (no expected issuer pinned; identity UNVERIFIED)"))
    elif kp.get("issuer_pubkey", "").lower() == expected_issuer.lower():
        issuer_authenticated = True
        res.append(R("issuer_signature", True, f"authenticated as the expected issuer {kp.get('issuer_id')!r}"))
    else:
        res.append(R("issuer_signature", False,
                     "authenticated key does NOT match the expected issuer pinned out of band (issuer-key substitution)"))

    # (1) ANCHORS — durable only when the witness key is pinned out of band
    res.append(_anchor_result(capsule, root_hash, expected_witnesses))

    # (4) HASH-TREE RENEWAL chain — verify each renewal folds under its own hash,
    #     chains to the prior root, and is signed; track the effective tree.
    renewals = capsule.get("tree_renewals", [])
    tree_alg = root.get("merkle_alg", "sha256")
    eff_root = root_hash
    renewal_ok = True
    renewer_authenticated = True  # vacuously true when there are no renewals
    prev = root_hash
    for i, rn in enumerate(renewals):
        alg = rn.get("merkle_alg")
        if rn.get("leaf_ids") != present_ids or rn.get("leaf_count") != len(present_ids):
            renewal_ok = False; res.append(R("tree_renewal", False, f"renewal {i}: leaf vector mismatch")); break
        rproofs = rn.get("inclusion_proofs", {})
        ok = True
        for o in objs:
            lid = o.get("id")
            if lid not in rproofs or fold(leaf_hash(o, alg), rproofs[lid], alg) != rn.get("root_hash"):
                ok = False; break
        if not ok:
            renewal_ok = False; res.append(R("tree_renewal", False, f"renewal {i}: leaves do not fold under {alg}")); break
        if rn.get("prev_root") != prev:
            renewal_ok = False; res.append(R("tree_renewal", False, f"renewal {i}: broken chain to prior root")); break
        rheader = {"root_hash": rn.get("root_hash"), "merkle_alg": alg,
                   "leaf_ids": rn.get("leaf_ids"), "leaf_count": rn.get("leaf_count"),
                   "prev_root": prev, "renewed_at": rn.get("renewed_at")}
        if not ed25519_verify(rn.get("renewer_pubkey", ""), cbytes(rheader), rn.get("renewer_signature", "")):
            renewal_ok = False; res.append(R("tree_renewal", False, f"renewal {i}: renewer signature invalid")); break
        rk = rn.get("renewer_pubkey", "").lower()
        this_auth = (rk == kp.get("issuer_pubkey", "").lower()) or \
                    (expected_renewer is not None and rk == expected_renewer.lower())
        renewer_authenticated = this_auth  # only the latest one matters for the verdict
        prev = rn.get("root_hash"); tree_alg = alg; eff_root = rn.get("root_hash")
    if renewals and renewal_ok:
        res.append(R("tree_renewal", True, f"{len(renewals)} hash-tree renewal(s); effective tree hash {tree_alg}"))

    # (2) TIMESTAMP TRAIL — envelope-signed; stampers count toward currency only if pinned
    stamps = capsule["timestamps"]
    stamp_broken = False
    counting = []
    if not stamps:
        stamp_broken = True; res.append(R("restamp_trail", False, "no timestamps present"))
    for s in stamps:
        hp = s.get("alg", "").split("+")[0]
        covered = s.get("root", root_hash)
        try:
            digest = h_alg(hp, covered.encode())
        except ValueError as e:
            stamp_broken = True; res.append(R("restamp_trail", False, str(e))); break
        env = {"alg": s.get("alg"), "stamped_at": s.get("stamped_at"),
               "digest": s.get("digest"), "root": covered}
        if digest != s.get("digest") or not ed25519_verify(s.get("pubkey", ""), cbytes(env), s.get("signature", "")):
            stamp_broken = True
            res.append(R("restamp_trail", False, f"stamp alg={s.get('alg')} fails (digest or envelope signature)")); break
        if expected_stampers is None or s.get("pubkey", "").lower() in expected_stampers:
            counting.append(s)

    # currency: a counting stamp over the CURRENT effective root, under an in-horizon alg.
    # Horizons come from verifier POLICY (out of band), never from the capsule.
    def in_horizon(alg_name):
        hz = policy.get(alg_name.split("+")[0]) or policy.get(alg_name)
        return (hz is not None) and (_iso(hz) > now)
    stamp_current = any(s.get("root", root_hash) == eff_root and in_horizon(s.get("alg", ""))
                        for s in counting)
    tree_in_horizon = in_horizon(tree_alg)
    restamp_needed = (not stamp_current) or (not tree_in_horizon)
    stamper_authenticated = (expected_stampers is not None) and stamp_current

    if not stamp_broken:
        why = []
        if not tree_in_horizon: why.append(f"tree hash {tree_alg} past horizon (renew-tree)")
        if not stamp_current: why.append("no current pinned timestamp over the effective root (re-stamp)")
        res.append(R("restamp_trail", True,
                     (f"{len(stamps)} stamp(s); " + ("; ".join(why) if why else f"current under {tree_alg}"))))

    res.append(R("trust_horizons", True,
                 "horizons from verifier policy; any value carried in the capsule is advisory and ignored"))

    # ordering: renewal times are signed (inside the renewer header) and must be
    # coherent. A renewal cannot predate the root it renews; a stamp cannot predate
    # the renewal it covers.
    def _t(x):
        try:
            return _iso(x)
        except Exception:
            return None
    order_ok = True
    order_detail = "renewal and stamp times are coherent"
    prev_ren_t = None
    established_roots = {root_hash}  # roots that already exist before a given renewal
    for i, rn in enumerate(renewals):
        prev_root = rn.get("prev_root")
        new_root = rn.get("root_hash")
        rt = _t(rn.get("renewed_at"))
        if rt is None:
            order_ok = False; order_detail = f"renewal {i} has no parseable renewed_at"; break
        # Floor = the LATEST signed evidence over the root being renewed, not the
        # earliest. Using the earliest let a backdated stamp over that root lower the
        # floor; using the latest means a renewal must follow everything already
        # committed over the root it supersedes.
        floor_pts = [_t(s.get("stamped_at")) for s in stamps if s.get("root") == prev_root]
        floor_pts += [_t(a.get("observed_at")) for a in capsule["anchors"] if a.get("root") == prev_root]
        floor_pts = [t for t in floor_pts if t is not None]
        if prev_ren_t is not None:
            floor_pts.append(prev_ren_t)
        floor = max(floor_pts) if floor_pts else None
        if floor is not None and rt < floor:
            order_ok = False
            order_detail = f"renewal {i} is dated before the latest signed evidence over the root it renews"
            break
        # A stamp over a root that THIS renewal first establishes cannot predate it.
        # If new_root already existed (e.g. a renewal to the same hash/data), earlier
        # stamps over it legitimately predate this renewal, so only check new roots.
        if new_root not in established_roots:
            if any(s.get("root") == new_root and (_t(s.get("stamped_at")) or rt) < rt for s in stamps):
                order_ok = False; order_detail = f"a stamp over renewal {i} predates the renewal"; break
            established_roots.add(new_root)
        prev_ren_t = rt
    res.append(R("ordering", order_ok, order_detail))

    # anti-rollback: a relying party may pin the newest root it knows exists; if that
    # root is absent here, this capsule may be a truncated/rolled-back prefix.
    if expected_newest is not None:
        known = {r.lower() for r in ([root_hash] + [rn.get("root_hash") for rn in renewals]) if r}
        rb_ok = expected_newest.lower() in known
        res.append(R("no_rollback", rb_ok,
                     "pinned newest root present" if rb_ok else
                     "pinned newest root absent: possible truncation to an older prefix (fail-closed)"))

    # precedence
    all_pass = all(r.ok for r in res)
    if not all_pass:
        return "WITHHELD", res
    if restamp_needed:
        return "RESTAMP_NEEDED", res
    durable = _durable(capsule, root_hash, expected_witnesses)
    if durable and issuer_authenticated and stamper_authenticated and renewer_authenticated:
        return "VERIFIED", res
    return "SELF_CONSISTENT", res


def _durable(capsule, root_hash, expected_witnesses):
    for a in capsule["anchors"]:
        env = {"root": a.get("root"), "witness": a.get("witness"), "observed_at": a.get("observed_at")}
        if a.get("root") == root_hash and ed25519_verify(a.get("anchor_pubkey", ""), cbytes(env), a.get("anchor_signature", "")):
            w = a.get("witness")
            if w in DURABLE_WITNESSES and expected_witnesses.get(w) == a.get("anchor_pubkey", "").lower():
                return True
    return False


# anchor check must also populate a result line; done inside verify via a helper pass.
def _anchor_result(capsule, root_hash, expected_witnesses):
    any_ok = False; broken = False; durable = False
    for a in capsule["anchors"]:
        env = {"root": a.get("root"), "witness": a.get("witness"), "observed_at": a.get("observed_at")}
        sig_ok = ed25519_verify(a.get("anchor_pubkey", ""), cbytes(env), a.get("anchor_signature", ""))
        if not sig_ok:
            broken = True; continue
        if a.get("root") == root_hash:
            any_ok = True
            w = a.get("witness")
            if w in DURABLE_WITNESSES and expected_witnesses.get(w) == a.get("anchor_pubkey", "").lower():
                durable = True
    if broken:
        return R("anchor", False, "an anchor signature does not verify over its envelope")
    if not any_ok:
        return R("anchor", False, "no anchor binds the root")
    return R("anchor", True, "durable witness pinned and verified" if durable
             else "anchor verifies, but the witness is self-asserted or its key is not pinned (not durable)")


EXIT = {"VERIFIED": 0, "WITHHELD": 1, "FAILED": 2, "SELF_CONSISTENT": 3, "RESTAMP_NEEDED": 4}


def render(verdict, res, path):
    print(f"capsule_verify.py  ·  {path}  ·  engine imports: none  ·  spec {SPEC_VERSION}")
    print("-" * 74)
    for r in res:
        print(r)
    print("-" * 74)
    msg = {
        "VERIFIED": "all checks pass; a PINNED durable witness anchors the root, the issuer and the current timestamp are authenticated out of band, and both the tree hash and the timestamp are within horizon",
        "WITHHELD": "a check failed; tampered, incomplete, or malformed; no confident answer by design",
        "FAILED": "not parseable as a Continuum Evidence Capsule 0.2",
        "SELF_CONSISTENT": "internally self-verifying, but not bound to a pinned durable witness and/or an authenticated issuer and timestamp; self-consistent, not authenticated",
        "RESTAMP_NEEDED": "self-verifying, but the tree hash and/or the newest timestamp is past its trust horizon; renew before trusting",
    }[verdict]
    print(f"VERDICT: {verdict}   {msg}")
    return verdict


def main():
    ap = argparse.ArgumentParser(description="Offline verifier for a Continuum Evidence Capsule (0.2)")
    ap.add_argument("capsule")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--now", help="override 'now' as ISO (for testing horizons)")
    ap.add_argument("--expected-issuer", help="hex Ed25519 public key of the expected issuer, pinned out of band")
    ap.add_argument("--expected-witness", action="append", default=[],
                    help="NAME=HEX pinned durable-witness key (repeatable); required for a durable verdict")
    ap.add_argument("--expected-stamper", action="append", default=[],
                    help="hex pinned timestamp-authority key (repeatable); required for a VERIFIED verdict")
    ap.add_argument("--expected-renewer", help="hex pinned hash-tree renewer key (if not the issuer)")
    ap.add_argument("--horizon", action="append", default=[],
                    help="NAME=ISO trust-horizon override, held as verifier policy (repeatable); "
                         "defaults are built in and any horizon inside the capsule is ignored")
    ap.add_argument("--expect-newest-root",
                    help="hex of the newest root the relying party knows exists; if absent from the "
                         "capsule, verification fails closed on a possible rollback")
    args = ap.parse_args()
    horizons = {}
    for p in args.horizon:
        k, _, v = p.partition("="); horizons[k.strip()] = v.strip()
    try:
        with open(args.capsule) as f:
            cap = json.load(f)
    except Exception as e:
        if not args.quiet:
            print(f"FAILED to load {args.capsule}: {e}")
        sys.exit(2)
    now = _iso(args.now) if args.now else None
    verdict, res = verify(cap, now=now, expected_issuer=args.expected_issuer,
                          expected_witnesses=_pin_map(args.expected_witness),
                          expected_stampers=args.expected_stamper or None,
                          expected_renewer=args.expected_renewer,
                          horizons=horizons or None,
                          expected_newest=args.expect_newest_root)
    if not args.quiet:
        render(verdict, res, args.capsule)
    sys.exit(EXIT[verdict])


if __name__ == "__main__":
    main()
