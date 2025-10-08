import json, uuid, datetime
from pathlib import Path
from didkit_wrap import DIDKitAPI

ISSUER_NAME = "EMA"                                   # the one who issues VC (needs to have JWK)
ISSUER_JWK  = Path("keys/actors/EMA.jwk")
DIDS_PATH   = Path("policies/dids.json")
OUT_DIR     = Path("credentials/issued")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def issue_license_vc(subject_name: str, has_license: bool = True):
    api = DIDKitAPI()
    dids = load_json(DIDS_PATH)

    if subject_name not in dids:
        raise ValueError(f"Unknown subject '{subject_name}' in {DIDS_PATH}")

    issuer_jwk = ISSUER_JWK.read_text(encoding="utf-8")
    issuer_did = api.key_to_did("key", issuer_jwk)
    vm = api.key_to_verification_method("key", issuer_jwk)

    subject_did = dids[subject_name]
    cred = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "DistributorLicenseCredential"],
        "issuer": issuer_did,
        "issuanceDate": now_iso(),
        "credentialSubject": {
            "id": subject_did,
            "hasLicense": bool(has_license)
        }
    }
    proof_opts = {
        "proofPurpose": "assertionMethod",
        "verificationMethod": vm
    }
    vc_signed = api.issue_credential(json.dumps(cred), json.dumps(proof_opts), issuer_jwk)

    out = OUT_DIR / f"license_{subject_name}.vc.jsonld"
    out.write_text(vc_signed, encoding="utf-8")
    print(f"[OK] VC issued: {out}")

if __name__ == "__main__":
    issue_license_vc("EuroLogistics", has_license=True) # example
