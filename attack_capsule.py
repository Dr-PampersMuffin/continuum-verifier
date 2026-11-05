#!/usr/bin/env python3
"""
attack_capsule.py — validate the capsule: honest verdicts on clean capsules,
WITHHELD on every tamper, and the decisive self-containment proof (verify runs
with the engine nowhere on the path).
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
    print(f"  {'OK ' if ok else 'XX '} {name:<34} expected={expected:<15} got={got:<15} {extra}")

content = {"fingerprint": P.sha256(b"m"), "fingerprint_alg": "sha256",
           "media_type": "image/jpeg", "description": "s"}

print("CLEAN CAPSULES (honest verdicts)")
durable = P.pack(P.sample_records(), content, witness="nist-beacon")
EXP = durable["key_provenance"]["issuer_pubkey"]   # the out-of-band pinned issuer key
check("durable + pinned issuer", "VERIFIED", verify(durable, expected_issuer=EXP)[0])
check("durable, issuer UNpinned", "SELF_CONSISTENT", verify(durable)[0])
selfc = P.pack(P.sample_records(), content, witness="demo-beacon")
check("self-asserted witness", "SELF_CONSISTENT", verify(selfc)[0])
expired = P.pack(P.sample_records(), content, witness="nist-beacon", stamp_alg="sha1+ed25519")
check("stale crypto (sha1)", "RESTAMP_NEEDED", verify(expired)[0])

print("\nTAMPER (every one must be WITHHELD)")
t = copy.deepcopy(durable); t["consent_chain"]["records"][0]["scope"] = "film:ALL-TITLES"
check("record field edit", "WITHHELD", verify(t)[0])
t = copy.deepcopy(durable); t["root"]["inclusion_proofs"]["REC-0001"] = []
check("inclusion proof strip", "WITHHELD", verify(t)[0])
t = copy.deepcopy(durable); t["root"]["root_hash"] = "0"*64
check("root swap", "WITHHELD", verify(t)[0])
t = copy.deepcopy(durable); t["key_provenance"]["issuer_signature"] = "00"*64
check("issuer signature forge", "WITHHELD", verify(t)[0])
t = copy.deepcopy(durable); t["anchors"][0]["anchor_signature"] = "00"*64
check("anchor signature forge", "WITHHELD", verify(t)[0])
t = copy.deepcopy(durable); t["timestamps"][0]["digest"] = "ab"*32
check("re-stamp digest tamper", "WITHHELD", verify(t)[0])
t = copy.deepcopy(durable)
t["content"]["fingerprint"] = "ff"*32   # content is a leaf field -> breaks inclusion
check("content fingerprint swap", "WITHHELD", verify(t)[0])

print("\nBATTERY SWAP (re-stamp revives an expired capsule)")
revived = RS.restamp(copy.deepcopy(expired), alg="sha3_512+ed25519")
check("expired -> re-stamped", "VERIFIED",
      verify(revived, expected_issuer=revived["key_provenance"]["issuer_pubkey"])[0])

print("\nFORWARD-DURABILITY over simulated time")
# same durable capsule checked at a future date past sha256's horizon
future = datetime(2040,1,1,tzinfo=timezone.utc)
check("durable @2040 (sha256 stale)", "RESTAMP_NEEDED", verify(durable, now=future)[0])
revived2 = RS.restamp(copy.deepcopy(durable), alg="sha3_512+ed25519")
check("re-stamped @2040", "VERIFIED",
      verify(revived2, now=future, expected_issuer=EXP)[0])

print("\nSELF-CONTAINMENT (verify runs with the engine nowhere on the path)")
tmp = tempfile.mkdtemp(prefix="stranger2050_")
try:
    shutil.copy(os.path.join(os.path.dirname(__file__), "capsule_verify.py"),
                os.path.join(tmp, "capsule_verify.py"))
    json.dump(durable, open(os.path.join(tmp, "cap.json"), "w"))
    # bare dir: only the verifier + the capsule. No pack, no engine, no spec code.
    proc = subprocess.run([sys.executable, "-I", "capsule_verify.py", "cap.json",
                           "--quiet", "--expected-issuer", EXP], cwd=tmp)
    rev = {0:"VERIFIED",1:"WITHHELD",2:"FAILED",3:"SELF_CONSISTENT",4:"RESTAMP_NEEDED"}
    listing = sorted(os.listdir(tmp))
    check("bare-dir verify", "VERIFIED", rev.get(proc.returncode, f"exit{proc.returncode}"),
          extra=f"dir held only {listing}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("\nISSUER AUTHENTICATION (the trust boundary, out-of-band pin)")
genuine = P.pack(P.sample_records(), content, witness="nist-beacon")
gpub = genuine["key_provenance"]["issuer_pubkey"]
check("key matches pin", "VERIFIED", verify(genuine, expected_issuer=gpub)[0])
# swap the embedded issuer key, re-sign the same root, keep the claimed id unchanged
swap = copy.deepcopy(genuine)
atk = Ed25519PrivateKey.generate()
atkpub = atk.public_key().public_bytes(
    encoding=_ser.Encoding.Raw, format=_ser.PublicFormat.Raw).hex()
swap["key_provenance"]["issuer_pubkey"] = atkpub
swap["key_provenance"]["issuer_signature"] = atk.sign(
    genuine["root"]["root_hash"].encode()).hex()
check("issuer-key swap vs pin", "WITHHELD", verify(swap, expected_issuer=gpub)[0])
check("issuer-key swap, no pin", "SELF_CONSISTENT", verify(swap)[0])

print("\n" + "="*72)
print(f"SUMMARY: {sum(RESULTS)}/{len(RESULTS)} behaved as expected")
sys.exit(0 if all(RESULTS) else 1)
