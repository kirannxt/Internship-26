"""
PhishGuard — URL Risk Analysis System
Implements the full pipeline from the flowchart:

  Input (URL / QR) → Validate → Normalize → Resolve Redirects
  → Extract URL Features → Analyze Contextual Info
  → Feature Fusion → Risk Scoring / Classification
  → Display Result + Safety Recommendation
"""

import re
import json
import math
import hashlib
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin
from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, jsonify, current_app
)
from flask_login import login_required, current_user
from app import db
from app.models import ScanHistory, User

scanner = Blueprint("scanner", __name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
    ".work", ".party", ".download", ".racing", ".win", ".bid",
    ".loan", ".review", ".science", ".date", ".faith", ".accountant",
}

HIGH_RISK_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "account",
    "update", "bank", "paypal", "ebay", "amazon", "apple", "microsoft",
    "password", "credential", "confirm", "free", "prize", "win",
    "click", "urgent", "suspended", "validate", "webscr", "cmd=",
    "alert", "warning", "limited", "expire", "billing", "invoice",
    "support", "helpdesk", "recovery", "unusual", "activity",
]

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "rb.gy", "cutt.ly", "short.io", "shorte.st", "adf.ly",
    "bc.vc", "za.gl", "clck.ru", "x.co", "tiny.cc",
}

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "reddit.com",
    "stackoverflow.com", "mozilla.org", "cloudflare.com",
}

# ---------------------------------------------------------------------------
# Stage 1: Input Validation & URL Normalisation
# ---------------------------------------------------------------------------

URL_RE = re.compile(
    r"^(https?://)?"                           # optional scheme
    r"(([a-zA-Z0-9\u00C0-\u024F\-]+\.)+[a-zA-Z]{2,})"  # domain (supports IDN)
    r"(:\d{1,5})?"                             # optional port
    r"(/[^\s]*)?$",                            # optional path/query
    re.IGNORECASE,
)


def _is_valid_url(url: str) -> bool:
    """Check that a string looks like a URL."""
    return bool(url and URL_RE.match(url.strip()))


def _normalize_url(url: str) -> str:
    """
    URL Normalisation stage (flowchart):
    - Add missing scheme
    - Lowercase scheme + host
    - Strip tracking parameters (utm_*, fbclid, gclid, etc.)
    - Remove default ports
    """
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host   = parsed.hostname or ""
    port   = parsed.port

    # Strip default ports
    netloc = host
    if port and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        netloc = f"{host}:{port}"

    # Strip common tracking params
    _STRIP_PARAMS = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "msclkid", "ref", "_ga", "mc_cid", "mc_eid",
    }
    if parsed.query:
        qs_pairs = [
            p for p in parsed.query.split("&")
            if p.split("=")[0].lower() not in _STRIP_PARAMS
        ]
        clean_query = "&".join(qs_pairs)
    else:
        clean_query = ""

    from urllib.parse import urlunparse
    normalized = urlunparse((scheme, netloc, parsed.path, parsed.params, clean_query, ""))
    return normalized


def _resolve_redirects(url: str, max_hops: int = 5) -> tuple[str, list[str]]:
    """
    Redirect Resolution stage (flowchart):
    Follow redirects to obtain the final destination URL.
    Returns (final_url, redirect_chain).
    Does NOT raise on failure — returns original URL.
    """
    chain: list[str] = []
    current = url
    try:
        import requests as req
        resp = req.head(
            current, allow_redirects=True, timeout=6,
            headers={"User-Agent": "Mozilla/5.0 (PhishGuard/1.0)"},
            stream=True,
        )
        final = resp.url
        # Build hop list from response history
        chain = [r.url for r in resp.history] + ([final] if resp.history else [])
        return final, chain
    except Exception:
        return current, chain


# ---------------------------------------------------------------------------
# Stage 2: Extract URL Features  (flowchart box)
# ---------------------------------------------------------------------------

def _extract_url_features(url: str) -> dict:
    """
    Extract structural / syntactic features from the URL itself.
    Returns a dict of named feature values + a partial risk score contribution.
    """
    parsed  = urlparse(url)
    host    = parsed.hostname or ""
    path    = parsed.path or ""
    query   = parsed.query or ""
    tld     = "." + host.split(".")[-1] if "." in host else ""
    domain_parts = host.split(".")

    # --- Domain name analysis ---
    domain_name = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else host
    subdomain   = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

    # IP address as host
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    # Entropy of the domain (high entropy → random / DGA domain)
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

    domain_entropy = _entropy(domain_name.replace(".", ""))

    # Suspicious patterns
    has_suspicious_tld      = tld.lower() in SUSPICIOUS_TLDS
    has_brand_in_subdomain  = any(b in subdomain.lower() for b in
                                  ["paypal", "amazon", "apple", "microsoft", "google",
                                   "facebook", "bank", "secure", "verify"])
    has_at_symbol           = "@" in url
    has_double_slash_path   = "//" in path
    num_dots_in_host        = host.count(".")
    num_hyphens_in_domain   = domain_name.count("-")
    url_length              = len(url)
    path_length             = len(path)
    num_subdirectories      = path.count("/")
    num_query_params        = len(parse_qs(query))
    has_hex_encoding        = bool(re.search(r"%[0-9a-fA-F]{2}", url))
    suspicious_keywords_hit = [kw for kw in HIGH_RISK_KEYWORDS if kw in url.lower()]
    is_shortener            = domain_name in KNOWN_SHORTENERS
    is_trusted              = domain_name in TRUSTED_DOMAINS

    # Suspicious paths
    has_redirect_in_path    = bool(re.search(r"redirect|redir|url=http|link=http", path.lower() + query.lower()))
    has_executable_ext      = bool(re.search(r"\.(exe|bat|cmd|vbs|ps1|jar|apk|dmg)(\?|$)", path.lower()))

    # Punycode / IDN homograph
    is_punycode = "xn--" in host.lower()

    # --- Score contribution from URL features ---
    score = 0.0

    if is_ip:                       score += 0.35
    if has_suspicious_tld:          score += 0.20
    if has_brand_in_subdomain:      score += 0.30
    if has_at_symbol:               score += 0.20
    if has_double_slash_path:       score += 0.10
    if is_shortener:                score += 0.10
    if is_punycode:                 score += 0.20
    if has_redirect_in_path:        score += 0.20
    if has_executable_ext:          score += 0.30
    if domain_entropy > 3.8:        score += 0.15
    if num_dots_in_host > 4:        score += 0.10
    if num_hyphens_in_domain > 3:   score += 0.10
    if url_length > 100:            score += 0.08
    if url_length > 200:            score += 0.08
    if num_query_params > 8:        score += 0.08
    score += min(len(suspicious_keywords_hit) * 0.08, 0.40)
    if is_trusted and not has_brand_in_subdomain:
        score = score * 0.3          # strong discount for known-good domains

    return {
        # meta
        "domain":                   domain_name,
        "subdomain":                subdomain,
        "tld":                      tld,
        "scheme":                   parsed.scheme,
        # flags
        "is_ip_address":            is_ip,
        "is_shortener":             is_shortener,
        "is_trusted_domain":        is_trusted,
        "is_punycode":              is_punycode,
        "has_suspicious_tld":       has_suspicious_tld,
        "has_brand_in_subdomain":   has_brand_in_subdomain,
        "has_at_symbol":            has_at_symbol,
        "has_hex_encoding":         has_hex_encoding,
        "has_redirect_in_path":     has_redirect_in_path,
        "has_executable_ext":       has_executable_ext,
        # metrics
        "url_length":               url_length,
        "path_length":              path_length,
        "num_dots_in_host":         num_dots_in_host,
        "num_hyphens_in_domain":    num_hyphens_in_domain,
        "num_subdirectories":       num_subdirectories,
        "num_query_params":         num_query_params,
        "domain_entropy":           round(domain_entropy, 3),
        "suspicious_keywords":      suspicious_keywords_hit,
        # partial score
        "url_feature_score":        round(min(score, 1.0), 4),
    }


# ---------------------------------------------------------------------------
# Stage 3: Analyze Contextual Information  (flowchart box)
# ---------------------------------------------------------------------------

def _analyze_context(url: str, redirect_chain: list[str]) -> dict:
    """
    Contextual analysis stage (flowchart):
    - Source/medium analysis (email link, social link, direct)
    - Claimed service vs. actual destination
    - Content-based signals
    - Risk context (business, user behaviour)
    """
    parsed       = urlparse(url)
    host         = parsed.hostname or ""
    domain_parts = host.split(".")
    domain_name  = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else host

    # Redirect chain analysis
    num_redirects      = len(redirect_chain)
    crosses_domains    = False
    redirect_domains   = set()
    if redirect_chain:
        for rurl in redirect_chain:
            rh = urlparse(rurl).hostname or ""
            rd = ".".join(rh.split(".")[-2:]) if "." in rh else rh
            redirect_domains.add(rd)
        crosses_domains = len(redirect_domains) > 1

    # Claimed service vs actual destination
    # e.g., URL says "paypal" but domain is not paypal.com
    brand_keywords = ["paypal", "apple", "amazon", "microsoft", "google",
                      "facebook", "instagram", "netflix", "bank", "hsbc",
                      "chase", "wellsfargo", "citibank", "dropbox", "docusign"]
    claimed_brand   = None
    brand_mismatch  = False
    for brand in brand_keywords:
        if brand in url.lower():
            claimed_brand = brand
            if brand not in domain_name.lower():
                brand_mismatch = True
            break

    # Scheme downgrade (http for a known financial/sensitive site)
    uses_http = parsed.scheme == "http"
    sensitive_domain = any(kw in domain_name.lower() for kw in
                           ["bank", "paypal", "secure", "account", "login"])
    scheme_risk = uses_http and sensitive_domain

    # Path looks like login / credential harvest
    path_lower = (parsed.path + "?" + parsed.query).lower()
    credential_path = bool(re.search(
        r"(login|signin|sign-in|account|password|credential|verify|auth|wp-admin|admin)",
        path_lower
    ))

    # Score contribution
    score = 0.0
    if num_redirects > 2:       score += 0.10 * min(num_redirects - 2, 3)
    if crosses_domains:          score += 0.15
    if brand_mismatch:           score += 0.40
    if scheme_risk:              score += 0.15
    if credential_path:          score += 0.10
    if uses_http:                score += 0.05

    return {
        "num_redirects":        num_redirects,
        "crosses_domains":      crosses_domains,
        "redirect_domains":     sorted(redirect_domains),
        "claimed_brand":        claimed_brand,
        "brand_mismatch":       brand_mismatch,
        "uses_http":            uses_http,
        "scheme_risk":          scheme_risk,
        "credential_path":      credential_path,
        "context_score":        round(min(score, 1.0), 4),
    }


# ---------------------------------------------------------------------------
# Stage 4: Feature Fusion  (flowchart box)
# ---------------------------------------------------------------------------

_FEATURE_WEIGHTS = {
    "url_feature_score": 0.55,
    "context_score":     0.45,
}


def _fuse_features(url_features: dict, context: dict) -> dict:
    """
    Combine URL structural features and contextual signals into a
    single fused risk score using weighted averaging.
    """
    url_score  = url_features.get("url_feature_score", 0.0)
    ctx_score  = context.get("context_score", 0.0)

    # Weighted sum
    fused = (
        _FEATURE_WEIGHTS["url_feature_score"] * url_score +
        _FEATURE_WEIGHTS["context_score"]     * ctx_score
    )

    # Hard boosts for definitive signals
    if url_features.get("is_ip_address"):         fused = max(fused, 0.60)
    if url_features.get("has_brand_in_subdomain"): fused = max(fused, 0.65)
    if context.get("brand_mismatch"):              fused = max(fused, 0.72)
    if url_features.get("has_executable_ext"):     fused = max(fused, 0.78)
    if url_features.get("is_trusted_domain") and not context.get("brand_mismatch"):
        fused = min(fused, 0.25)   # cap at low risk for trusted domains

    fused = round(min(max(fused, 0.0), 0.99), 4)

    return {
        "fused_score":      fused,
        "url_weight":       _FEATURE_WEIGHTS["url_feature_score"],
        "context_weight":   _FEATURE_WEIGHTS["context_score"],
        "url_score":        round(url_score, 4),
        "context_score":    round(ctx_score, 4),
    }


# ---------------------------------------------------------------------------
# Stage 5: Risk Scoring / Classification  (flowchart — Rule-based + ML-like)
# ---------------------------------------------------------------------------

def _classify_risk(fused_score: float) -> tuple[str, str]:
    """
    Map the fused numeric score to a categorical prediction and risk level.
    Thresholds mirror the flowchart: Safe / Suspicious / Malicious.
    """
    if fused_score < 0.35:
        return "safe",       "LOW"
    elif fused_score < 0.65:
        return "suspicious", "MEDIUM"
    else:
        return "malicious",  "HIGH"


# ---------------------------------------------------------------------------
# Stage 6: Safety Recommendation  (flowchart — Display Result)
# ---------------------------------------------------------------------------

_SAFETY_RECOMMENDATIONS = {
    "safe": (
        "This URL appears safe to visit. "
        "Proceed with normal caution — always verify the site is what you expect "
        "before entering any personal information."
    ),
    "suspicious": (
        "This URL has characteristics associated with phishing or deceptive content. "
        "Do NOT enter passwords, payment details, or personal data. "
        "Verify the destination independently before proceeding."
    ),
    "malicious": (
        "This URL shows strong indicators of malicious intent. "
        "Avoid opening it entirely. Do not click, share, or interact with this link. "
        "If received via email or message, mark it as phishing and report to your provider."
    ),
}


def _build_safety_recommendation(prediction: str, url_features: dict, context: dict) -> str:
    base = _SAFETY_RECOMMENDATIONS.get(prediction, "Unable to determine safety. Treat with caution.")
    extras = []
    if url_features.get("is_shortener"):
        extras.append("The URL uses a link shortener — the true destination was hidden.")
    if url_features.get("is_ip_address"):
        extras.append("The domain is a raw IP address, which is unusual for legitimate sites.")
    if context.get("brand_mismatch"):
        brand = context.get("claimed_brand", "a known brand")
        extras.append(f"The URL mentions '{brand}' but the domain does not match — a common phishing trick.")
    if url_features.get("has_executable_ext"):
        extras.append("The link leads to an executable file that could install malware.")
    if context.get("num_redirects", 0) > 2:
        extras.append(f"The URL redirects {context['num_redirects']} times, which is suspicious.")
    if extras:
        return base + " Additional notes: " + " ".join(extras)
    return base


# ---------------------------------------------------------------------------
# Full Pipeline
# ---------------------------------------------------------------------------

def _full_scan_pipeline(raw_url: str) -> dict:
    """
    Execute all flowchart stages in order:
      1. Normalize URL
      2. Resolve redirects
      3. Extract URL features
      4. Analyze contextual info
      5. Fuse features
      6. Classify risk
      7. Build safety recommendation
    """
    # Stage 1 — normalize
    url = _normalize_url(raw_url)

    # Stage 2 — redirect resolution (best-effort; never blocks the scan)
    final_url, redirect_chain = _resolve_redirects(url)
    analysis_url = final_url if final_url else url

    # Stage 3 — URL feature extraction
    url_features = _extract_url_features(analysis_url)

    # Stage 4 — contextual analysis
    context = _analyze_context(analysis_url, redirect_chain)

    # Stage 5 — feature fusion
    fusion = _fuse_features(url_features, context)

    # Stage 6 — classification
    prediction, risk_level = _classify_risk(fusion["fused_score"])

    # Stage 7 — safety recommendation
    recommendation = _build_safety_recommendation(prediction, url_features, context)

    return {
        # Core result
        "url":              analysis_url,
        "original_url":     raw_url,
        "prediction":       prediction,
        "probability":      fusion["fused_score"],
        "risk_level":       risk_level,
        "model_version":    "pipeline-v2",
        # Detailed breakdown for result page
        "url_features":     url_features,
        "context":          context,
        "fusion":           fusion,
        "recommendation":   recommendation,
        "redirect_chain":   redirect_chain,
    }


def _call_external_api(url: str, api_url: str) -> dict | None:
    """Call an external scan API. Returns parsed JSON or None on failure."""
    try:
        import requests as req
        resp = req.post(api_url, json={"url": url}, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def _perform_scan(url: str) -> tuple[dict | None, str | None]:
    """
    Run the scan. Returns (result_dict, error_message).
    Tries external API first; falls back to the full built-in pipeline.
    """
    api_url = current_app.config.get("SCAN_API_URL", "").strip()
    if api_url:
        result = _call_external_api(url, api_url)
        if result is None:
            return None, "The detection service is unavailable. Please try again later."
        return result, None
    else:
        result = _full_scan_pipeline(url)
        return result, None


# ---------------------------------------------------------------------------
# QR Code Decoding
# ---------------------------------------------------------------------------

def _decode_qr_image(file_storage) -> tuple[str | None, str | None]:
    """
    Decode a QR code from an uploaded image file.
    Returns (url_string, error_message).
    Requires Pillow and pyzbar (optional).
    """
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as qr_decode
        img  = Image.open(file_storage.stream)
        data = qr_decode(img)
        if not data:
            return None, "No QR code detected in the uploaded image. Please ensure the image is clear and contains a QR code."
        raw = data[0].data.decode("utf-8", errors="replace").strip()
        return raw, None
    except ImportError:
        return None, "QR code decoding is not available. Install 'pyzbar' and 'Pillow' to enable this feature."
    except Exception as exc:
        return None, f"Failed to decode the QR image: {exc}"


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------

@scanner.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("scanner.dashboard"))
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@scanner.route("/dashboard")
@login_required
def dashboard():
    scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scanned_at.desc())
        .all()
    )

    total      = len(scans)
    safe       = sum(1 for s in scans if s.prediction == "safe")
    suspicious = sum(1 for s in scans if s.prediction == "suspicious")
    malicious  = sum(1 for s in scans if s.prediction == "malicious")
    recent     = scans[:5]

    return render_template(
        "scanner/dashboard.html",
        title="Dashboard",
        stats={
            "total":      total,
            "safe":       safe,
            "suspicious": suspicious,
            "malicious":  malicious,
        },
        recent_scans=recent,
    )


# ---------------------------------------------------------------------------
# URL Scanner (supports URL text + QR image upload)
# ---------------------------------------------------------------------------

@scanner.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    error   = None
    url_val = ""
    input_type = "url"   # "url" | "qr"

    if request.method == "POST":
        input_type = request.form.get("input_type", "url")

        if input_type == "qr":
            # --- QR Code path ---
            qr_file = request.files.get("qr_image")
            if not qr_file or qr_file.filename == "":
                error = "Please upload a QR code image."
            else:
                decoded_url, decode_err = _decode_qr_image(qr_file)
                if decode_err:
                    error = decode_err
                else:
                    url_val = decoded_url
        else:
            # --- Direct URL path ---
            url_val = request.form.get("url", "").strip()
            if not url_val:
                error = "Please enter a URL before scanning."

        if not error and url_val:
            if not _is_valid_url(url_val):
                error = "That doesn't look like a valid URL. Include http:// or https://."
            else:
                result, api_error = _perform_scan(url_val)

                if api_error:
                    error = api_error
                elif result:
                    # Persist to history
                    scan_record = ScanHistory(
                        user_id         = current_user.id,
                        url             = result.get("url", url_val),
                        original_url    = result.get("original_url", url_val),
                        input_type      = input_type,
                        prediction      = result.get("prediction", "unknown"),
                        probability     = result.get("probability"),
                        risk_level      = result.get("risk_level"),
                        model_version   = result.get("model_version"),
                        recommendation  = result.get("recommendation", ""),
                        details_json    = json.dumps({
                            "url_features":   result.get("url_features", {}),
                            "context":        result.get("context", {}),
                            "fusion":         result.get("fusion", {}),
                            "redirect_chain": result.get("redirect_chain", []),
                        }),
                    )
                    db.session.add(scan_record)
                    db.session.commit()
                    return redirect(url_for("scanner.result", scan_id=scan_record.id))
                else:
                    error = "An unexpected error occurred. Please try again."

    return render_template("scanner/scan.html",
                           title="Scan URL",
                           error=error,
                           url_val=url_val,
                           input_type=input_type)


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------

@scanner.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan_record = ScanHistory.query.filter_by(
        id=scan_id, user_id=current_user.id
    ).first_or_404()

    # Parse stored JSON details
    details = {}
    if scan_record.details_json:
        try:
            details = json.loads(scan_record.details_json)
        except (ValueError, TypeError):
            details = {}

    return render_template("scanner/result.html",
                           title="Scan Result",
                           scan=scan_record,
                           details=details)


# ---------------------------------------------------------------------------
# Internal JSON API endpoint  (POST /api/scan)
# CSRF exempted — JSON-only, no session cookie needed.
# ---------------------------------------------------------------------------

from app import csrf as _csrf_ext

@scanner.route("/api/scan", methods=["POST"])
@_csrf_ext.exempt
def api_scan():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url field is required"}), 400
    if not _is_valid_url(url):
        return jsonify({"error": "invalid url"}), 422

    result = _full_scan_pipeline(url)
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# Scan History (full list)
# ---------------------------------------------------------------------------

@scanner.route("/history")
@login_required
def history():
    scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.scanned_at.desc())
        .all()
    )
    return render_template("scanner/history.html",
                           title="Scan History",
                           scans=scans)
