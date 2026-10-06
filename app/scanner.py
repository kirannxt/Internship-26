import re
import json
import random
from datetime import datetime
from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, jsonify, current_app
)
from flask_login import login_required, current_user
from app import db
from app.models import ScanHistory, User

scanner = Blueprint("scanner", __name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

URL_RE = re.compile(
    r"^(https?://)?"                          # optional scheme
    r"(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})"     # domain
    r"(:\d+)?"                                # optional port
    r"(/[^\s]*)?$",                           # optional path
    re.IGNORECASE,
)


def _is_valid_url(url: str) -> bool:
    return bool(url and URL_RE.match(url.strip()))


def _mock_scan(url: str) -> dict:
    """
    Built-in mock detection used when no external SCAN_API_URL is configured.
    Deterministic-ish: suspicious keywords push the score up.
    """
    url_lower = url.lower()
    score = random.uniform(0.03, 0.15)   # baseline: low risk

    high_risk_keywords = [
        "login", "signin", "verify", "secure", "account", "update",
        "bank", "paypal", "ebay", "amazon", "apple", "microsoft",
        "password", "credential", "confirm", "free", "prize", "win",
        "click", "urgent", "suspended", "verify", "validate",
    ]
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click"]

    for kw in high_risk_keywords:
        if kw in url_lower:
            score += random.uniform(0.08, 0.15)

    for tld in suspicious_tlds:
        if tld in url_lower:
            score += random.uniform(0.15, 0.25)

    # IP address as host is suspicious
    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url_lower):
        score += 0.35

    # very long URLs are suspicious
    if len(url) > 100:
        score += random.uniform(0.05, 0.12)

    score = min(score, 0.99)

    if score < 0.35:
        prediction, risk_level = "safe",       "LOW"
    elif score < 0.70:
        prediction, risk_level = "suspicious", "MEDIUM"
    else:
        prediction, risk_level = "malicious",  "HIGH"

    return {
        "url":           url,
        "prediction":    prediction,
        "probability":   round(score, 4),
        "risk_level":    risk_level,
        "model_version": "mock-v1",
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
    Tries external API first; falls back to mock.
    """
    api_url = current_app.config.get("SCAN_API_URL", "").strip()
    if api_url:
        result = _call_external_api(url, api_url)
        if result is None:
            return None, "The detection service is unavailable. Please try again later."
    else:
        result = _mock_scan(url)
    return result, None


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
# URL Scanner
# ---------------------------------------------------------------------------

@scanner.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    error    = None
    url_val  = ""

    if request.method == "POST":
        url_val = request.form.get("url", "").strip()

        if not url_val:
            error = "Please enter a URL before scanning."
        elif not _is_valid_url(url_val):
            error = "That doesn't look like a valid URL. Include http:// or https://."
        else:
            result, api_error = _perform_scan(url_val)

            if api_error:
                error = api_error
            elif result:
                # persist to history
                scan_record = ScanHistory(
                    user_id       = current_user.id,
                    url           = result.get("url", url_val),
                    prediction    = result.get("prediction", "unknown"),
                    probability   = result.get("probability"),
                    risk_level    = result.get("risk_level"),
                    model_version = result.get("model_version"),
                )
                db.session.add(scan_record)
                db.session.commit()
                return redirect(url_for("scanner.result", scan_id=scan_record.id))
            else:
                error = "An unexpected error occurred. Please try again."

    return render_template("scanner/scan.html",
                           title="Scan URL",
                           error=error,
                           url_val=url_val)


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------

@scanner.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan_record = ScanHistory.query.filter_by(
        id=scan_id, user_id=current_user.id
    ).first_or_404()

    return render_template("scanner/result.html",
                           title="Scan Result",
                           scan=scan_record)


# ---------------------------------------------------------------------------
# Internal mock API endpoint  (POST /api/scan)
# Useful for testing; real deployments replace this with an ML service.
# ---------------------------------------------------------------------------

@scanner.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url field is required"}), 400
    if not _is_valid_url(url):
        return jsonify({"error": "invalid url"}), 422

    result = _mock_scan(url)
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
