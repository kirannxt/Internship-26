"""
PhishGuard — ML Model Module
============================
Provides:
  - extract_feature_vector(url)  →  numpy array of 23 numeric features
  - FEATURE_NAMES                →  list of feature names (same order)
  - load_model()                 →  loads model.pkl from models/ directory
  - predict(url)                 →  returns dict with prediction, probability,
                                    risk_level, feature_vector, model_version

The feature set is intentionally identical to what the rule-based pipeline
already computes so the two approaches are directly comparable.

Model file location:  d:/Internship-26/models/phishguard_model.pkl
"""

import os
import re
import math
import ipaddress
import warnings
from urllib.parse import urlparse, parse_qs

import numpy as np

# ---------------------------------------------------------------------------
# Feature definitions  (must stay in sync with train_model.py)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    # --- URL structure ---
    "url_length",               # 0
    "hostname_length",          # 1
    "path_length",              # 2
    "num_dots_in_host",         # 3
    "num_hyphens_in_domain",    # 4
    "num_subdomains",           # 5
    "num_query_params",         # 6
    "num_subdirectories",       # 7
    "domain_entropy",           # 8
    # --- Boolean flags ---
    "is_ip_address",            # 9
    "is_shortener",             # 10
    "is_https",                 # 11
    "has_suspicious_tld",       # 12
    "has_brand_in_subdomain",   # 13
    "has_at_symbol",            # 14
    "has_double_slash_path",    # 15
    "has_hex_encoding",         # 16
    "has_redirect_in_path",     # 17
    "has_executable_ext",       # 18
    "is_punycode",              # 19
    # --- Keyword / context ---
    "num_suspicious_keywords",  # 20
    "brand_mismatch",           # 21
    "credential_path",          # 22
]

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
    ".work", ".party", ".download", ".racing", ".win", ".bid",
    ".loan", ".review", ".science", ".date", ".faith", ".accountant",
}

_HIGH_RISK_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "account",
    "update", "bank", "paypal", "ebay", "amazon", "apple", "microsoft",
    "password", "credential", "confirm", "free", "prize", "win",
    "click", "urgent", "suspended", "validate", "webscr", "cmd=",
    "alert", "warning", "limited", "expire", "billing", "invoice",
    "support", "helpdesk", "recovery", "unusual", "activity",
]

_KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "rb.gy", "cutt.ly", "short.io", "shorte.st", "adf.ly",
    "bc.vc", "za.gl", "clck.ru", "x.co", "tiny.cc",
}

_BRAND_KEYWORDS = [
    "paypal", "apple", "amazon", "microsoft", "google",
    "facebook", "instagram", "netflix", "bank", "hsbc",
    "chase", "wellsfargo", "citibank", "dropbox", "docusign",
]

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def extract_feature_vector(url: str) -> np.ndarray:
    """
    Convert a URL string into a fixed-length numeric feature vector.
    Returns a 1-D numpy array of shape (23,) matching FEATURE_NAMES.
    """
    # Ensure scheme present for urlparse
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed       = urlparse(url)
    host         = parsed.hostname or ""
    path         = parsed.path or ""
    query        = parsed.query or ""
    domain_parts = host.split(".")
    domain_name  = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else host
    subdomain    = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""
    tld          = ("." + domain_parts[-1]) if domain_parts else ""

    # IP host?
    is_ip = 0
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        pass

    # Brand mismatch
    brand_mismatch = 0
    for brand in _BRAND_KEYWORDS:
        if brand in url.lower() and brand not in domain_name.lower():
            brand_mismatch = 1
            break

    # Credential-harvesting path
    path_query_lower = (path + "?" + query).lower()
    credential_path  = int(bool(re.search(
        r"(login|signin|sign-in|account|password|credential|verify|auth|wp-admin|admin)",
        path_query_lower
    )))

    features = [
        len(url),                                                          # url_length
        len(host),                                                         # hostname_length
        len(path),                                                         # path_length
        host.count("."),                                                   # num_dots_in_host
        domain_name.count("-"),                                            # num_hyphens_in_domain
        len(domain_parts) - 2 if len(domain_parts) > 2 else 0,           # num_subdomains
        len(parse_qs(query)),                                              # num_query_params
        path.count("/"),                                                   # num_subdirectories
        round(_entropy(domain_name.replace(".", "")), 4),                 # domain_entropy
        is_ip,                                                             # is_ip_address
        int(domain_name in _KNOWN_SHORTENERS),                            # is_shortener
        int(parsed.scheme.lower() == "https"),                            # is_https
        int(tld.lower() in _SUSPICIOUS_TLDS),                             # has_suspicious_tld
        int(any(b in subdomain.lower() for b in _BRAND_KEYWORDS)),        # has_brand_in_subdomain
        int("@" in url),                                                   # has_at_symbol
        int("//" in path),                                                 # has_double_slash_path
        int(bool(re.search(r"%[0-9a-fA-F]{2}", url))),                   # has_hex_encoding
        int(bool(re.search(r"redirect|redir|url=http|link=http",          # has_redirect_in_path
                            path_query_lower))),
        int(bool(re.search(r"\.(exe|bat|cmd|vbs|ps1|jar|apk|dmg)(\?|$)", # has_executable_ext
                            path.lower()))),
        int("xn--" in host.lower()),                                      # is_punycode
        sum(1 for kw in _HIGH_RISK_KEYWORDS if kw in url.lower()),        # num_suspicious_keywords
        brand_mismatch,                                                    # brand_mismatch
        credential_path,                                                   # credential_path
    ]

    return np.array(features, dtype=np.float32)


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),   # project root
    "models", "phishguard_model.pkl"
)

_cached_model = None   # module-level cache — loaded once per process


def load_model():
    """
    Load the trained model bundle from disk.
    Returns the bundle dict or None if the model file does not exist.
    Caches the result after the first load.
    """
    global _cached_model
    if _cached_model is not None:
        return _cached_model

    if not os.path.exists(_MODEL_PATH):
        return None

    try:
        import joblib
        _cached_model = joblib.load(_MODEL_PATH)
        return _cached_model
    except Exception as exc:
        warnings.warn(f"PhishGuard: failed to load ML model — {exc}")
        return None


def is_model_available() -> bool:
    """Return True if the model file exists and can be loaded."""
    return load_model() is not None


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

_LABEL_MAP = {0: "safe", 1: "suspicious", 2: "malicious"}
_RISK_MAP   = {0: "LOW",  1: "MEDIUM",    2: "HIGH"}


def predict(url: str) -> dict | None:
    """
    Run the trained ML model on a URL.

    Returns a dict:
      {
        "prediction":     "safe" | "suspicious" | "malicious",
        "probability":    float  (0.0 – 1.0, confidence in the predicted class),
        "risk_level":     "LOW"  | "MEDIUM"     | "HIGH",
        "model_version":  str,
        "feature_vector": list[float],   # 23 values, same order as FEATURE_NAMES
        "probabilities":  {              # per-class probabilities
            "safe": float,
            "suspicious": float,
            "malicious": float,
        }
      }

    Returns None if the model is not loaded (app falls back to rule-based pipeline).
    """
    bundle = load_model()
    if bundle is None:
        return None

    try:
        model         = bundle["model"]
        label_encoder = bundle.get("label_encoder")   # optional
        version       = bundle.get("version", "ml-v1")
        model_name    = bundle.get("model_name", "ensemble")

        fv    = extract_feature_vector(url)
        fv_2d = fv.reshape(1, -1)

        # Raw label prediction
        raw_label = model.predict(fv_2d)[0]

        # Map label → standard string
        if isinstance(raw_label, (int, np.integer)):
            prediction = _LABEL_MAP.get(int(raw_label), "unknown")
        else:
            prediction = str(raw_label).lower()

        # Per-class probabilities
        proba_arr  = model.predict_proba(fv_2d)[0]          # shape (n_classes,)
        classes    = list(model.classes_)

        proba_dict: dict[str, float] = {}
        for cls, p in zip(classes, proba_arr):
            label = _LABEL_MAP.get(int(cls), str(cls))
            proba_dict[label] = round(float(p), 4)

        # Confidence = probability assigned to the winning class
        confidence = proba_dict.get(prediction, float(proba_arr.max()))

        # Risk level
        risk_level = _RISK_MAP.get(
            {v: k for k, v in _LABEL_MAP.items()}.get(prediction, 0), "LOW"
        )

        return {
            "prediction":     prediction,
            "probability":    round(confidence, 4),
            "risk_level":     risk_level,
            "model_version":  f"{model_name}-{version}",
            "feature_vector": fv.tolist(),
            "probabilities":  proba_dict,
        }

    except Exception as exc:
        warnings.warn(f"PhishGuard ML predict error: {exc}")
        return None
