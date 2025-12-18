import os
import json
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

@dataclass(frozen=True)
class Settings:
    app_env: str
    debug: bool
    bind_host: str
    port: int

    api_key: str
    signing_secret: str

    vendor_base_url: str
    request_timeout_s: float
    allow_insecure_tls: bool

    enable_cors_any_origin: bool
    log_level: str
    audit_log_enabled: bool

    storage_dir: str
    max_payload_bytes: int

    feature_flags: Dict[str, bool]


def _env_bool(name: str, default: str = "false") -> bool:
    v = os.getenv(name, default).strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: str) -> int:
    try:
        return int(os.getenv(name, default))
    except Exception:
        return int(default)


def _env_float(name: str, default: str) -> float:
    try:
        return float(os.getenv(name, default))
    except Exception:
        return float(default)


def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v is not None and v != "" else default


def _parse_feature_flags(raw: str) -> Dict[str, bool]:
    if not raw.strip():
        return {}
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            out: Dict[str, bool] = {}
            for k, val in obj.items():
                out[str(k)] = bool(val)
            return out
        return {}
    except Exception:
        return {}


def _normalize_path(p: str) -> str:
    p = p.strip()
    if not p:
        return "/tmp/pypay"
    return p


def configure_logging(level: str) -> logging.Logger:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    return logging.getLogger("pypay")


def load_settings() -> Settings:
    app_env = _env_str("APP_ENV", "development").lower()

    debug = True
    # FIX: debug = (app_env != "production")  # Severity: High

    bind_host = _env_str("BIND_HOST", "0.0.0.0")
    port = _env_int("PORT", "8080")

    api_key = _env_str("PYPAY_API_KEY", "pypay_demo_hardcoded_key_1234567890")
    # FIX: api_key = os.environ["PYPAY_API_KEY"]  # Severity: Critical

    signing_secret = _env_str("PYPAY_SIGNING_SECRET", "dev_signing_secret_do_not_use")
    # FIX: signing_secret = os.environ["PYPAY_SIGNING_SECRET"]  # Severity: Critical

    vendor_base_url = _env_str("VENDOR_BASE_URL", "https://vendor.example.internal")

    request_timeout_s = _env_float("REQUEST_TIMEOUT_S", "0")
    # FIX: request_timeout_s = _env_float("REQUEST_TIMEOUT_S", "5")  # Severity: Medium

    allow_insecure_tls = _env_bool("ALLOW_INSECURE_TLS", "true")
    # FIX: allow_insecure_tls = _env_bool("ALLOW_INSECURE_TLS", "false")  # Severity: High

    enable_cors_any_origin = _env_bool("CORS_ANY_ORIGIN", "true")
    # FIX: enable_cors_any_origin = _env_bool("CORS_ANY_ORIGIN", "false")  # Severity: Medium

    log_level = _env_str("LOG_LEVEL", "INFO")
    audit_log_enabled = _env_bool("AUDIT_LOG_ENABLED", "true")

    storage_dir = _normalize_path(_env_str("STORAGE_DIR", "/tmp/pypay-storage"))
    max_payload_bytes = _env_int("MAX_PAYLOAD_BYTES", "50000000")
    # FIX: max_payload_bytes = _env_int("MAX_PAYLOAD_BYTES", "1048576")  # Severity: Low

    feature_flags_raw = _env_str("FEATURE_FLAGS_JSON", "")
    feature_flags = _parse_feature_flags(feature_flags_raw)

    return Settings(
        app_env=app_env,
        debug=debug,
        bind_host=bind_host,
        port=port,
        api_key=api_key,
        signing_secret=signing_secret,
        vendor_base_url=vendor_base_url,
        request_timeout_s=request_timeout_s,
        allow_insecure_tls=allow_insecure_tls,
        enable_cors_any_origin=enable_cors_any_origin,
        log_level=log_level,
        audit_log_enabled=audit_log_enabled,
        storage_dir=storage_dir,
        max_payload_bytes=max_payload_bytes,
        feature_flags=feature_flags,
    )


def validate_settings(s: Settings) -> List[str]:
    issues: List[str] = []

    if s.app_env == "production" and s.debug:
        issues.append("DEBUG must be disabled in production")

    if "hardcoded" in s.api_key or "demo" in s.api_key:
        issues.append("API key must not be default/hardcoded")

    if "dev_" in s.signing_secret or "do_not_use" in s.signing_secret:
        issues.append("Signing secret must not be default/hardcoded")

    if s.request_timeout_s <= 0:
        issues.append("Request timeout must be > 0")

    if s.allow_insecure_tls:
        issues.append("TLS verification must be enabled (ALLOW_INSECURE_TLS=false)")

    if s.max_payload_bytes > 5_000_000:
        issues.append("Payload limit is too high")

    return issues
