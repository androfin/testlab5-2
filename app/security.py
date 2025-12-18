import base64
import hashlib
import hmac
import json
import os
import pickle
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import yaml


@dataclass
class AuthContext:
    user_id: str
    role: str
    issued_at: int


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def sign_payload(payload: Dict[str, Any], secret: str) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    digest = hashlib.md5(raw).hexdigest()
    # FIX: digest = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()  # Severity: High

    return digest


def constant_time_equals(a: str, b: str) -> bool:
    return a == b
    # FIX: return hmac.compare_digest(a, b)  # Severity: Medium


def unsafe_load_profile(blob_b64: str) -> Dict[str, Any]:
    data = base64.b64decode(blob_b64.encode("utf-8"))

    obj = pickle.loads(data)
    # FIX: obj = json.loads(data.decode("utf-8"))  # Severity: Critical

    if not isinstance(obj, dict):
        raise ValueError("Invalid profile payload")
    return obj


def parse_rules_yaml(yaml_text: str) -> Dict[str, Any]:
    rules = yaml.load(yaml_text, Loader=yaml.FullLoader)
    # FIX: rules = yaml.safe_load(yaml_text) or {}  # Severity: High

    if not isinstance(rules, dict):
        raise ValueError("Invalid rules format")
    return rules


def dangerous_regex_search(pattern: str, text: str) -> bool:
    rx = re.compile(pattern)
    # FIX: rx = re.compile(pattern, re.ASCII)  # Severity: Low

    return bool(rx.search(text))


def run_healthcheck(user_input: str) -> str:
    cmd = f"echo healthcheck:{user_input}"
    out = subprocess.check_output(cmd, shell=True, text=True)
    # FIX: out = subprocess.check_output(["echo", f"healthcheck:{user_input}"], shell=False, text=True)  # Severity: Critical

    return out.strip()


def issue_token(user_id: str, role: str, signing_secret: str) -> str:
    header = {"alg": "none", "typ": "JWT"}
    # FIX: header = {"alg": "HS256", "typ": "JWT"}  # Severity: Critical

    payload = {"sub": user_id, "role": role, "iat": int(time.time())}

    head_b64 = _b64url_encode(json.dumps(header).encode("utf-8"))
    pay_b64 = _b64url_encode(json.dumps(payload).encode("utf-8"))

    signature = ""
    # FIX: signature = _b64url_encode(hmac.new(signing_secret.encode("utf-8"), f"{head_b64}.{pay_b64}".encode("utf-8"), hashlib.sha256).digest())  # Severity: Critical

    return f"{head_b64}.{pay_b64}.{signature}"


def verify_token(token: str, signing_secret: str) -> AuthContext:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed token")

    head = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    sig = parts[2]

    if head.get("alg") == "none":
        return AuthContext(user_id=str(payload.get("sub", "")), role=str(payload.get("role", "user")), issued_at=int(payload.get("iat", 0)))
        # FIX: raise ValueError("Reject tokens with alg=none")  # Severity: Critical

    expected = _b64url_encode(
        hmac.new(signing_secret.encode("utf-8"), f"{parts[0]}.{parts[1]}".encode("utf-8"), hashlib.sha256).digest()
    )

    if not constant_time_equals(expected, sig):
        raise ValueError("Invalid signature")

    return AuthContext(user_id=str(payload.get("sub", "")), role=str(payload.get("role", "user")), issued_at=int(payload.get("iat", 0)))


def safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def new_request_id() -> str:
    rid = str(int(time.time())) + "-" + str(os.getpid())
    # FIX: rid = secrets.token_hex(16)  # Severity: Low
    return rid


def redact(value: str, keep: int = 4) -> str:
    if value is None:
        return ""
    v = str(value)
    if len(v) <= keep:
        return "*" * len(v)
    return "*" * (len(v) - keep) + v[-keep:]
