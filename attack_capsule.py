#!/usr/bin/env python3
"""
attack_capsule.py — validate the capsule (spec 0.2): honest verdicts on clean
capsules, WITHHELD on every tamper, the self-containment proof, and the four
boundary regressions from external review (Gruszka, Nov 2026) that must now be
rejected instead of silently reaching VERIFIED.
"""
import copy, json, hashlib, subprocess, sys, os, tempfile, shutil
from datetime import datetime, timezone
import capsule_pack as P
import capsule_restamp as RS
from capsule_verify import verify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as _ser

RESULTS = []
def check(name, expected, got, extra=""):
    ok = (got == expected)
    RESULTS.append(ok)
    print(f"  {'OK ' if ok else 'XX '} {name:<40} expected={expected:<15} got={got:<15} {extra}")

def pins(cap):
    """All out-of-band pins a legitimate verifier would hold for THIS capsule."""
    p = dict(expected_issuer=cap["key_provenance"]["issuer_pubkey"],
             expected_witnesses={a["witness"]: a["anchor_pubkey"] for a in cap["anchors"]},
             expected_stampers=[s["pubkey"] for s in cap["timestamps"]])
    if cap.get("tree_renewals"):
        p["expected_renewer"] = cap["tree_renewals"][-1]["renewer_pubkey"]
    return p

def pk(sk):
    return sk.public_key().public_bytes(encoding=_ser.Encoding.Raw, format=_ser.PublicFormat.Raw).hex()

content = {"fingerprint": P.sha256(b"m"), "fingerprint_alg": "sha256",
           "media_type": "image/jpeg", "description": "s"}

print("CLEAN CAPSULES (honest verdicts)")
durable = P.pack(P.sample_records(), content, witness="nist-beacon")
check("durable + all pins", "VERIFIED", verify(durable, **pins(durable))[0])
check("durable, issuer UNpinned", "SELF_CONSISTENT",
      verify(durable, expected_witnesses=pins(durable)["expected_witnesses"],
             expected_stampers=pins(durable)["expected_stampers"])[0])
check("durable, witness UNpinned", "SELF_CONSISTENT",
      verify(durable, expected_issuer=durable["key_provenance"]["issuer_pubkey"],
             expected_stampers=pins(durable)["expected_stampers"])[0])
selfc = P.pack(P.sample_records(), content, witness="demo-beacon")
check("self-asserted witness (not durable set)", "SELF_CONSISTENT", verify(selfc, **pins(selfc))[0])
expired = P.pack(P.sample_records(), content, witness="nist-beacon", stamp_alg="sha1+ed25519")
check("stale crypto (sha1 stamp)", "RESTAMP_NEEDED", verify(expired, **pins(expired))[0])

print("\nTAMPER (every one must be WITHHELD)")
t = copy.deepcopy(durable); t["consent_chain"]["records"][0]["scope"] = "film:ALL-TITLES"
check("record field edit", "WITHHELD", verify(t, **pins(durable))[0])
t = copy.deepcopy(durable); t["root"]["inclusion_proofs"]["REC-0001"] = []
check("inclusion proof strip", "WITHHELD", verify(t, **pins(durable))[0])
t = copy.deepcopy(durable); t["root"]["root_hash"] = "0"*64
check("root swap", "WITHHELD", verify(t, **pins(durable))[0])
t = copy.deepcopy(durable); t["key_provenance"]["issuer_signature"] = "00"*64
check("issuer signature forge", "WITHHELD", verify(t, **pins(durable))[0])
t = copy.deepcopy(durable); t["anchors"][0]["anchor_signature"] = "00"*64
check("anchor signature forge", "WITHHELD", verify(t, **pins(durable))[0])
t = copy.deepcopy(durable); t["timestamps"][0]["digest"] = "ab"*32
check("re-stamp digest tamper", "WITHHELD", verify(t, **pins(durable))[0])
t = copy.deepcopy(durable); t["content"]["fingerprint"] = "ff"*32
check("content fingerprint swap", "WITHHELD", verify(t, **pins(durable))[0])

print("\nBATTERY SWAP (timestamp renewal extends a capsule BEFORE its hash expires)")
fresh = P.pack(P.sample_records(), content, witness="nist-beacon", stamp_alg="sha256+ed25519")
revived = RS.restamp(copy.deepcopy(fresh), alg="sha3_512+ed25519")
check("sha256 re-stamped to sha3_512 in time", "VERIFIED", verify(revived, **pins(revived))[0])
# RFC 4998 5.3: re-stamping a hash that is ALREADY past horizon is too late
too_late = RS.restamp(copy.deepcopy(expired), alg="sha3_512+ed25519")
check("re-stamp of an already-expired sha1 stamp", "WITHHELD",
      verify(too_late, **pins(too_late))[0], "sha1 was past horizon when covered (5.3)")

print("\nFORWARD DURABILITY over simulated time (tree hash ages too)")
future = datetime(2040, 1, 1, tzinfo=timezone.utc)
check("durable @2040 (sha256 tree stale)", "RESTAMP_NEEDED", verify(durable, now=future, **pins(durable))[0])
restamp_only = RS.restamp(copy.deepcopy(durable), alg="sha3_512+ed25519")
check("timestamp-only restamp @2040 (tree still sha256)", "RESTAMP_NEEDED",
      verify(restamp_only, now=future, **pins(restamp_only))[0])
renewed = RS.renew_tree(copy.deepcopy(durable), P.sample_records(), content, alg="sha3_512")
check("hash-tree renewal @2040", "VERIFIED", verify(renewed, now=future, **pins(renewed))[0])

print("\nSELF-CONTAINMENT (verify runs with the engine nowhere on the path)")
tmp = tempfile.mkdtemp(prefix="stranger2050_")
try:
    shutil.copy(os.path.join(os.path.dirname(__file__), "capsule_verify.py"),
                os.path.join(tmp, "capsule_verify.py"))
    json.dump(durable, open(os.path.join(tmp, "cap.json"), "w"))
    flags = ["--quiet", "--expected-issuer", durable["key_provenance"]["issuer_pubkey"],
             "--expected-stamper", durable["timestamps"][0]["pubkey"]]
    for a in durable["anchors"]:
        flags += ["--expected-witness", f'{a["witness"]}={a["anchor_pubkey"]}']
    proc = subprocess.run([sys.executable, "-I", "capsule_verify.py", "cap.json", *flags], cwd=tmp)
    rev = {0:"VERIFIED",1:"WITHHELD",2:"FAILED",3:"SELF_CONSISTENT",4:"RESTAMP_NEEDED"}
    check("bare-dir verify", "VERIFIED", rev.get(proc.returncode, f"exit{proc.returncode}"),
          extra=f"dir held only {sorted(os.listdir(tmp))}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("\nISSUER AUTHENTICATION (out-of-band pin)")
genuine = P.pack(P.sample_records(), content, witness="nist-beacon")
check("key matches pin", "VERIFIED", verify(genuine, **pins(genuine))[0])
swap = copy.deepcopy(genuine)
atk = Ed25519PrivateKey.generate()
swap["key_provenance"]["issuer_pubkey"] = pk(atk)
# re-sign the SAME signed-root header with the attacker key (header binds the version)
hdr = {"capsule_version": genuine["capsule_version"], "root_hash": genuine["root"]["root_hash"],
       "merkle_alg": "sha256", "leaf_ids": genuine["root"]["leaf_ids"],
       "leaf_count": genuine["root"]["leaf_count"]}
swap["key_provenance"]["issuer_signature"] = atk.sign(P.cbytes(hdr)).hex()
check("issuer-key swap vs pin", "WITHHELD", verify(swap, **pins(genuine))[0])
check("issuer-key swap, no pin", "SELF_CONSISTENT", verify(swap)[0])

print("\nBOUNDARY REGRESSIONS (Gruszka, Nov 2026 — each must now be rejected)")
# K1: forge a 'nist-beacon' anchor with an attacker key; the real witness key is pinned
base = P.pack(P.sample_records(), content, witness="nist-beacon")
P1 = pins(base)  # captures the REAL witness key as the out-of-band pin
k1 = copy.deepcopy(base)
atk = Ed25519PrivateKey.generate()
a = k1["anchors"][0]
a["anchor_pubkey"] = pk(atk)
a["anchor_signature"] = atk.sign(P.cbytes({"root": a["root"], "witness": "nist-beacon",
                                           "observed_at": a["observed_at"]})).hex()
check("K1 forged durable anchor key", "SELF_CONSISTENT", verify(k1, **P1)[0],
      "was VERIFIED in 0.1")

# K2a: append a properly chained fresh-key stamp to lift a stale capsule
k2 = copy.deepcopy(expired)
s = Ed25519PrivateKey.generate()
k2["timestamps"].append(P.make_stamp(s, k2["root"]["root_hash"], "sha256+ed25519",
                                     at="2030-01-01T00:00:00Z",
                                     prev=P.stamp_link(k2["timestamps"][-1])))
check("K2a fresh unpinned stamp key", "WITHHELD",
      verify(k2, **pins(expired))[0], "sha1 was past horizon when covered; 5.3 rejects it")

# K2b: edit stamped_at on a stamp without re-signing (now inside the signed envelope)
k2b = copy.deepcopy(durable)
k2b["timestamps"][0]["stamped_at"] = "2099-01-01T00:00:00Z"
check("K2b stamped_at edited, not re-signed", "WITHHELD", verify(k2b, **pins(durable))[0],
      "envelope signature now covers stamped_at")

# K3a: drop the ingest record and its proof
k3a = copy.deepcopy(durable)
k3a["consent_chain"]["records"] = [r for r in k3a["consent_chain"]["records"] if r["id"] != "REC-0002"]
del k3a["root"]["inclusion_proofs"]["REC-0002"]
check("K3a record omission (REC-0002)", "WITHHELD", verify(k3a, **pins(durable))[0],
      "leaf vector no longer matches the signed set")

# K3b: duplicate a record
k3b = copy.deepcopy(durable)
rec1 = [r for r in k3b["consent_chain"]["records"] if r["id"] == "REC-0001"][0]
k3b["consent_chain"]["records"].append(copy.deepcopy(rec1))
check("K3b record duplication (REC-0001)", "WITHHELD", verify(k3b, **pins(durable))[0],
      "duplicate leaf id rejected")

# K4: timestamp renewal is NOT hash-tree renewal
k4_stamp = RS.restamp(copy.deepcopy(durable), alg="sha3_512+ed25519")
k4_tree = RS.renew_tree(copy.deepcopy(durable), P.sample_records(), content, alg="sha3_512")
check("K4 restamp-only past tree horizon", "RESTAMP_NEEDED",
      verify(k4_stamp, now=future, **pins(k4_stamp))[0], "tree hash still sha256")
check("K4 hash-tree renewal past horizon", "VERIFIED",
      verify(k4_tree, now=future, **pins(k4_tree))[0], "tree rebuilt under sha3_512")

# K5: trust_horizons is verifier policy, not a capsule field an attacker can edit
k5a = copy.deepcopy(expired)
k5a["trust_horizons"]["sha1"] = "2099-01-01T00:00:00Z"
check("K5a sha1 horizon edited to 2099", "RESTAMP_NEEDED", verify(k5a, **pins(expired))[0],
      "capsule horizon ignored; policy governs")
k5b = RS.restamp(copy.deepcopy(durable), alg="sha3_512+ed25519")
k5b["trust_horizons"]["sha256"] = "2099-01-01T00:00:00Z"
check("K5b sha256 horizon edited, @2040", "RESTAMP_NEEDED",
      verify(k5b, now=future, **pins(k5b))[0], "capsule horizon ignored; policy governs")
# and a verifier-policy override is honoured (out of band), proving the knob still exists
check("K5c policy override extends sha256 to 2099", "VERIFIED",
      verify(durable, now=future, horizons={"sha256": "2099-01-01T00:00:00Z"}, **pins(durable))[0],
      "horizon set by the verifier, not the file")

print("\nRENEWAL ORDERING, ROLLBACK, WEAK-ALG REFUSAL (collaborative review, Nov 2026)")
# K6: a renewal dated before the root it renews must be rejected (times are signed)
k6 = RS.renew_tree(copy.deepcopy(durable), P.sample_records(), content, alg="sha3_512",
                   at="2000-01-01T00:00:00Z")
check("K6 renewal predates its root", "WITHHELD", verify(k6, **pins(k6))[0],
      "renewed_at is inside the signed header and ordered")

# K7: anti-rollback. Pin the newest root; a truncated prefix fails closed.
renewed = RS.renew_tree(copy.deepcopy(durable), P.sample_records(), content, alg="sha3_512")
newest_root = renewed["tree_renewals"][-1]["root_hash"]
check("K7a pinned newest root present", "VERIFIED",
      verify(renewed, expected_newest=newest_root, **pins(renewed))[0])
check("K7b rolled-back prefix, newest root pinned", "WITHHELD",
      verify(durable, expected_newest=newest_root, **pins(durable))[0],
      "durable lacks the pinned renewal root")

# K8: weak/unknown hash refused at renewal time, before any work
def _raises(fn):
    try:
        fn(); return "allowed"
    except ValueError:
        return "refused"
check("K8a renew-tree refuses sha1", "refused",
      _raises(lambda: RS.renew_tree(copy.deepcopy(durable), P.sample_records(), content, alg="sha1")))
check("K8b restamp refuses md5", "refused",
      _raises(lambda: RS.restamp(copy.deepcopy(durable), alg="md5+ed25519")))
check("K8c renew-tree refuses unknown alg", "refused",
      _raises(lambda: RS.renew_tree(copy.deepcopy(durable), P.sample_records(), content, alg="foo-256")))

# K9: a backdated timestamp renewal must not lower the ordering floor (Gruszka)
import datetime as _dt
def _pp(s): return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
def _ff(d): return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")
base9 = P.pack(P.sample_records(), content, witness="nist-beacon")
t9 = _pp(base9["timestamps"][0]["stamped_at"])
k9 = RS.restamp(copy.deepcopy(base9), alg="sha256+ed25519", at=_ff(t9 - _dt.timedelta(hours=2)))
k9 = RS.renew_tree(k9, P.sample_records(), content, alg="sha3_512", at=_ff(t9 - _dt.timedelta(hours=1)))
check("K9 backdated restamp lowers floor", "WITHHELD", verify(k9, **pins(k9))[0],
      "floor is the latest evidence over the prior root, not the earliest")

# K10/K11: the ordering floor must NOT false-reject legitimate multi-renewals
t10 = _pp(base9["timestamps"][0]["stamped_at"])
k10 = RS.renew_tree(copy.deepcopy(base9), P.sample_records(), content, alg="sha384",
                    at=_ff(t10 + _dt.timedelta(hours=1)))
k10 = RS.renew_tree(k10, P.sample_records(), content, alg="sha3_512",
                    at=_ff(t10 + _dt.timedelta(hours=2)))
check("K10 two renewals, distinct algs, ascending", "VERIFIED", verify(k10, **pins(k10))[0],
      "legitimate chain must not be rejected")
k11 = RS.renew_tree(copy.deepcopy(base9), P.sample_records(), content, alg="sha3_512",
                    at=_ff(t10 + _dt.timedelta(hours=1)))
k11 = RS.renew_tree(k11, P.sample_records(), content, alg="sha3_512",
                    at=_ff(t10 + _dt.timedelta(hours=2)))
check("K11 same-alg renewal (shared root) not false-rejected", "VERIFIED",
      verify(k11, **pins(k11))[0], "a pre-existing root's earlier stamps may predate a later renewal")

print("\nRFC 4998 5.3: each timestamp valid when the next one covered it")
_T1, _T2, _T3, _V = ("2026-01-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z",
                     "2028-01-01T00:00:00.000Z", _dt.datetime(2029, 1, 1, tzinfo=_dt.timezone.utc))
_GEN = {"sha256": "2035-01-01T00:00:00Z", "sha3_512": "2050-01-01T00:00:00Z"}
def _vec53():
    c = P.pack(P.sample_records(), content, witness="nist-beacon", stamp_alg="sha256+ed25519", sealed_at=_T1)
    c = RS.restamp(c, alg="sha256+ed25519", at=_T2)
    c = RS.renew_tree(c, P.sample_records(), content, alg="sha3_512", at=_T3)
    return c
def _k(c): return [s["pubkey"] for s in c["timestamps"]]       # [T1, T2, T3]
_c = _vec53(); _kT1, _kT2, _kT3 = _k(_c)
_winall = {k: {"not_after": "2029-06-01T00:00:00Z"} for k in (_kT1, _kT2, _kT3)}
check("K12 all valid at refs and T3 at V", "VERIFIED",
      verify(_c, now=_V, horizons=_GEN, stamper_windows=_winall, **pins(_c))[0])
_c = _vec53(); _kT1 = _k(_c)[0]; _w = dict(_winall); _w[_kT1] = {"not_after": "2026-06-01T00:00:00Z"}
check("K13 T1 key ends before T2", "WITHHELD",
      verify(_c, now=_V, horizons=_GEN, stamper_windows=_w, **pins(_c))[0], "fails at T1 (5.3)")
_c = _vec53(); _kT1 = _k(_c)[0]; _w = dict(_winall); _w[_kT1] = {"not_after": "2027-06-01T00:00:00Z"}
check("K14 T1 key ends after T2 before V", "VERIFIED",
      verify(_c, now=_V, horizons=_GEN, stamper_windows=_w, **pins(_c))[0], "valid when T2 covered it")
_c = _vec53()
check("K15 first hash horizon before renewal", "WITHHELD",
      verify(_c, now=_V, horizons={"sha256": "2027-06-01T00:00:00Z", "sha3_512": "2050-01-01T00:00:00Z"},
             stamper_windows=_winall, **pins(_c))[0], "renewed too late")
# T1 signature corrupted, with T2 and T3 rebuilt over it so links + later sigs are
# valid: only T1's signature is bad. A chain+newest-only verifier would pass this.
_c = _vec53(); _t1 = _c["timestamps"][0]; _t1["signature"] = "00"*64
_k2, _k3 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
_t2, _t3 = _c["timestamps"][1], _c["timestamps"][2]
_nt2 = P.make_stamp(_k2, _t2["root"], _t2["alg"], at=_t2["stamped_at"], prev=P.stamp_link(_t1))
_nt3 = P.make_stamp(_k3, _t3["root"], _t3["alg"], at=_t3["stamped_at"], prev=P.stamp_link(_nt2))
_c["timestamps"] = [_t1, _nt2, _nt3]
_w16 = {k: {"not_after": "2029-06-01T00:00:00Z"} for k in _k(_c)}
check("K16 only T1 signature invalid, chain + later sigs valid", "WITHHELD",
      verify(_c, now=_V, horizons=_GEN, stamper_windows=_w16, **pins(_c))[0],
      "every stamp signature checked, not only the newest")

print("\n" + "="*78)
print(f"SUMMARY: {sum(RESULTS)}/{len(RESULTS)} behaved as expected")
sys.exit(0 if all(RESULTS) else 1)
