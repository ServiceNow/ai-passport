# The core of a gateway's AI Passport check, on one screen (AI Passport v1 §1).
#
# Single trusted issuer, the presenter already authenticated as (authority, identifier).
# It covers the common case only: no refetch (§10), no multi-issuer ranking (§9.2), no
# caching (Revocation Check v1 §5.3) and no I-JSON character checks (§4). It does fail
# closed on any status other than 200 and on redirects (Revocation Check v1 §4, §5.2).
# Run your real implementation through conformance/run.py; that is what tells you it is complete.
#
# pip install requests rfc8785 cryptography      (Python 3.11 or later)
import base64, json, requests, rfc8785
from datetime import datetime, timezone
from urllib.parse import quote
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

ISSUER = "https://issuer.example.com"                # configured, never taken from a Passport
JWKS = requests.get(ISSUER + "/jwks", timeout=2).json()

def b64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def need(ok):
    if not ok: raise PermissionError
def strict(kv): need(len({k for k, _ in kv}) == len(kv)); return dict(kv)    # no duplicate members

def verify(p):
    [sig] = p.pop("signatures")                      # exactly one signature
    hdr = json.loads(b64(sig["protected"]), object_pairs_hook=strict)
    need(hdr["alg"] == "ES256" and "crit" not in hdr)
    need(hdr.get("typ", "jose").lower() in {"ai-passport+jws", "application/ai-passport+jws",
         "jose", "application/jose"})
    k = next(k for k in JWKS["keys"] if k["kid"] == hdr["kid"])
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(b64(k["x"])), int.from_bytes(b64(k["y"])),
                                        ec.SECP256R1()).public_key()
    raw, body = b64(sig["signature"]), base64.urlsafe_b64encode(rfc8785.dumps(p)).rstrip(b"=")
    key.verify(utils.encode_dss_signature(int.from_bytes(raw[:32]), int.from_bytes(raw[32:])),
               sig["protected"].encode() + b"." + body, ec.ECDSA(hashes.SHA256()))
    return p

def get(uri, **params):                               # 200 only, no redirects followed
    resp = requests.get(uri, params=params, timeout=2, allow_redirects=False)
    need(resp.status_code == 200)
    return json.loads(resp.text, object_pairs_hook=strict)

def check(authority, identifier):
    """Business context for the agent you authenticated as (authority, identifier), or None: deny."""
    try:
        p = verify(get(f"{ISSUER}/passports", authority=authority, identifier=identifier))
        now = datetime.now(timezone.utc)
        need(p["schema_version"] == "1" and p["issuer"] == ISSUER)
        need(p["subject_type"] in {"agent", "harness", "tool_server", "model_endpoint"})
        need(p.get("issuance_class") in {None, "owned", "proxy"})
        need(p.get("parent") is None or (p["parent"].get("issuer") == ISSUER and p["parent"].get("subject")))
        need(datetime.fromisoformat(p["valid_from"]) <= now <= datetime.fromisoformat(p["valid_to"]))
        need(any(a["role"] == "manager" and (a.get("principal") or a.get("name"))
             for a in p["business_context"]["accountable"]))
        need(any(b["authority"].get("id") == authority and b["identifier"] == identifier
             for b in p["bindings"]))
        uri = p["status"]["revocation_check"]["uri"].replace("{subject}", quote(p["subject"], safe=""))
        need(uri.startswith(ISSUER + "/"))
        r = get(uri)
        need(r["revoked"] is False and r["revoked_scopes"] == [] and r["subject"] == p["subject"])
        need(r["min_required_revision"] <= p["revision"])
        return p["business_context"]
    except Exception:
        return None                                  # unable to tell means deny
