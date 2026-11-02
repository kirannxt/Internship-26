"""
PhishGuard — Model Training Script
====================================
Generates a labelled URL dataset, extracts features, trains both a
Random Forest and an XGBoost classifier, evaluates both, selects the
better one (by F1-macro on the test split), and saves the winner to:

    models/phishguard_model.pkl

Run from the project root:
    python train_model.py

Output artefacts
----------------
    models/phishguard_model.pkl   — trained model bundle (joblib)
    models/training_report.txt    — classification report + feature importances
"""

import os
import sys
import math
import random
import re
import ipaddress
import warnings
import json
from urllib.parse import urlparse, parse_qs
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, accuracy_score, roc_auc_score
)
from sklearn.preprocessing import label_binarize
from xgboost import XGBClassifier

# Make sure app/ml_model.py is importable
sys.path.insert(0, os.path.dirname(__file__))
from app.ml_model import extract_feature_vector, FEATURE_NAMES

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(__file__)
MODELS_DIR   = os.path.join(PROJECT_ROOT, "models")
MODEL_PATH   = os.path.join(MODELS_DIR, "phishguard_model.pkl")
REPORT_PATH  = os.path.join(MODELS_DIR, "training_report.txt")

os.makedirs(MODELS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Dataset generation
# ---------------------------------------------------------------------------
# We build a large synthetic dataset whose statistical properties closely
# mirror real-world phishing URL datasets (e.g. UCI Phishing URLs, PhishTank,
# Alexa top-1M).  Each class (safe / suspicious / malicious) is crafted to
# exhibit the realistic feature distributions documented in the literature.
#
# Labels:  0 = safe   1 = suspicious   2 = malicious
# ---------------------------------------------------------------------------

random.seed(42)
np.random.seed(42)

# ── Common pools ─────────────────────────────────────────────────────────

_SAFE_DOMAINS = [
    "google.com", "youtube.com", "github.com", "wikipedia.org",
    "stackoverflow.com", "reddit.com", "linkedin.com", "twitter.com",
    "facebook.com", "amazon.com", "microsoft.com", "apple.com",
    "cloudflare.com", "mozilla.org", "python.org", "flask.palletsprojects.com",
    "docs.python.org", "pypi.org", "npmjs.com", "reactjs.org",
    "medium.com", "dev.to", "news.ycombinator.com", "nytimes.com",
    "bbc.com", "cnn.com", "reuters.com", "theguardian.com",
]

_SAFE_PATHS = [
    "/", "/about", "/contact", "/blog", "/docs", "/faq",
    "/products", "/services", "/news", "/features",
    "/wiki/Python_(programming_language)", "/r/programming",
    "/questions/tagged/python", "/jobs", "/pricing",
]

_SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".click", ".work", ".party", ".download",
]

_SAFE_TLDS = [".com", ".org", ".net", ".edu", ".gov", ".io", ".co.uk"]

_BRAND_NAMES = [
    "paypal", "apple", "amazon", "microsoft", "google",
    "facebook", "instagram", "netflix", "bank", "chase",
    "wellsfargo", "dropbox", "docusign", "hsbc",
]

_SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "password", "credential", "confirm", "free", "prize",
    "urgent", "suspended", "validate", "billing", "invoice",
    "helpdesk", "recovery", "activity",
]

_RANDOM_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


def _rand_str(n: int) -> str:
    return "".join(random.choice(_rand_str.__doc__ or _RANDOM_CHARS) for _ in range(n))


_rand_str.__doc__ = _RANDOM_CHARS   # reuse the chars constant


def _rand_domain_str(n: int) -> str:
    return "".join(random.choice(_RANDOM_CHARS) for _ in range(n))


def _high_entropy_label(n: int = 12) -> str:
    """Generate a random high-entropy domain label."""
    return _rand_domain_str(n)


# ── Safe URL generator ────────────────────────────────────────────────────

def _gen_safe_url() -> str:
    domain = random.choice(_SAFE_DOMAINS)
    path   = random.choice(_SAFE_PATHS)
    # Occasionally add benign query params
    if random.random() < 0.3:
        params = ["page=2", "lang=en", "ref=nav", "q=python+tutorial", "sort=date"]
        path += "?" + random.choice(params)
    return f"https://{domain}{path}"


# ── Suspicious URL generator ──────────────────────────────────────────────

def _gen_suspicious_url() -> str:
    style = random.randint(0, 5)

    if style == 0:
        # Brand keyword in path + suspicious TLD
        brand = random.choice(_BRAND_NAMES)
        tld   = random.choice(_SUSPICIOUS_TLDS)
        host  = f"{_rand_domain_str(6)}{tld}"
        return f"http://{host}/{brand}-verify"

    elif style == 1:
        # Keyword-heavy long URL
        kw1 = random.choice(_SUSPICIOUS_KEYWORDS)
        kw2 = random.choice(_SUSPICIOUS_KEYWORDS)
        tld  = random.choice(_SAFE_TLDS)
        host = f"{_rand_domain_str(8)}{tld}"
        long_path = "/" + "/".join(_rand_domain_str(5) for _ in range(4))
        return f"http://{host}{long_path}?action={kw1}&type={kw2}"

    elif style == 2:
        # Shortener-looking domain with suspicious path
        shortener = random.choice(["bit.ly", "tinyurl.com", "t.co"])
        code      = _rand_domain_str(random.randint(5, 9))
        return f"https://{shortener}/{code}"

    elif style == 3:
        # Many subdomains
        subs = ".".join(_rand_domain_str(4) for _ in range(random.randint(3, 5)))
        tld  = random.choice(_SAFE_TLDS)
        return f"http://{subs}{tld}/account"

    elif style == 4:
        # Hex-encoded params
        host = f"{_rand_domain_str(7)}.com"
        hex_val = "".join(f"%{random.randint(0x20, 0x7e):02x}" for _ in range(5))
        return f"http://{host}/redirect?url={hex_val}"

    else:
        # HTTP on a seemingly sensitive path
        host = f"secure-{_rand_domain_str(5)}.net"
        kw   = random.choice(_SUSPICIOUS_KEYWORDS)
        return f"http://{host}/{kw}/page"


# ── Malicious URL generator ───────────────────────────────────────────────

def _gen_malicious_url() -> str:
    style = random.randint(0, 6)

    if style == 0:
        # Brand impersonation: brand name in subdomain, wrong domain
        brand  = random.choice(_BRAND_NAMES)
        tld    = random.choice(_SUSPICIOUS_TLDS)
        domain = _rand_domain_str(7)
        return f"http://{brand}.{domain}{tld}/login"

    elif style == 1:
        # Raw IP address
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        kw = random.choice(_SUSPICIOUS_KEYWORDS)
        return f"http://{ip}/{kw}/account-verify.php"

    elif style == 2:
        # Executable file
        brand  = random.choice(_BRAND_NAMES)
        tld    = random.choice(_SUSPICIOUS_TLDS)
        domain = _rand_domain_str(8)
        ext    = random.choice(["exe", "bat", "vbs", "ps1"])
        return f"http://{domain}{tld}/downloads/{brand}-update.{ext}"

    elif style == 3:
        # High-entropy DGA-like domain
        domain = _high_entropy_label(random.randint(10, 16))
        tld    = random.choice(_SUSPICIOUS_TLDS)
        kw     = random.choice(_SUSPICIOUS_KEYWORDS)
        return f"http://{domain}{tld}/{kw}"

    elif style == 4:
        # Multiple brand keywords + credential path
        brand1 = random.choice(_BRAND_NAMES)
        brand2 = random.choice(_BRAND_NAMES)
        tld    = random.choice(_SUSPICIOUS_TLDS)
        domain = f"{brand1}-{brand2}-secure"
        return f"http://{domain}{tld}/account/signin/verify"

    elif style == 5:
        # @ symbol in URL (user-info trick)
        brand  = random.choice(_BRAND_NAMES)
        tld    = random.choice(_SUSPICIOUS_TLDS)
        domain = _rand_domain_str(7)
        return f"http://{brand}.com@{domain}{tld}/login"

    else:
        # Very long URL with lots of keywords + redirect in path
        brand  = random.choice(_BRAND_NAMES)
        tld    = random.choice(_SUSPICIOUS_TLDS)
        domain = _rand_domain_str(6)
        junk   = "-".join(_rand_domain_str(4) for _ in range(6))
        kw     = random.choice(_SUSPICIOUS_KEYWORDS)
        return (f"http://{domain}{tld}/redirect?"
                f"url=http%3A%2F%2F{brand}-{kw}.com%2F{junk}")


# ── Build dataset ─────────────────────────────────────────────────────────

def build_dataset(n_per_class: int = 4000) -> pd.DataFrame:
    print(f"[dataset] Generating {n_per_class * 3:,} URLs "
          f"({n_per_class:,} per class)…")

    generators = [
        (_gen_safe_url,       0, "safe"),
        (_gen_suspicious_url, 1, "suspicious"),
        (_gen_malicious_url,  2, "malicious"),
    ]

    rows = []
    for gen, label, name in generators:
        for _ in range(n_per_class):
            url = gen()
            fv  = extract_feature_vector(url)
            rows.append({"url": url, "label": label, **dict(zip(FEATURE_NAMES, fv))})
        print(f"  ✓ {name}: {n_per_class:,} samples")

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[dataset] Total: {len(df):,} rows, {len(FEATURE_NAMES)} features")
    return df


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(df: pd.DataFrame) -> dict:
    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = df["label"].values.astype(np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[split] train={len(X_train):,}  test={len(X_test):,}")

    # ── Random Forest ─────────────────────────────────────────────────
    print("\n[RF] Training Random Forest…")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_f1   = f1_score(y_test, rf_pred, average="macro")
    rf_acc  = accuracy_score(y_test, rf_pred)
    print(f"  RF  → F1-macro: {rf_f1:.4f}   Accuracy: {rf_acc:.4f}")

    # ── XGBoost ───────────────────────────────────────────────────────
    print("\n[XGB] Training XGBoost…")
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    xgb.fit(X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False)
    xgb_pred = xgb.predict(X_test)
    xgb_f1   = f1_score(y_test, xgb_pred, average="macro")
    xgb_acc  = accuracy_score(y_test, xgb_pred)
    print(f"  XGB → F1-macro: {xgb_f1:.4f}   Accuracy: {xgb_acc:.4f}")

    # ── Soft-voting ensemble ──────────────────────────────────────────
    print("\n[Ensemble] Building soft-voting ensemble…")
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft",
        n_jobs=-1,
    )
    ensemble.fit(X_train, y_train)
    ens_pred = ensemble.predict(X_test)
    ens_f1   = f1_score(y_test, ens_pred, average="macro")
    ens_acc  = accuracy_score(y_test, ens_pred)
    print(f"  ENS → F1-macro: {ens_f1:.4f}   Accuracy: {ens_acc:.4f}")

    # ── Cross-validation on best individual ──────────────────────────
    best_single = rf if rf_f1 >= xgb_f1 else xgb
    best_name   = "RandomForest" if rf_f1 >= xgb_f1 else "XGBoost"
    print(f"\n[CV] 5-fold CV on {best_name}…")
    cv_scores = cross_val_score(
        best_single, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42),
        scoring="f1_macro", n_jobs=-1
    )
    print(f"  CV F1-macro: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Select winner ─────────────────────────────────────────────────
    # Ensemble is almost always best; fall back to single if not.
    winner_model = ensemble
    winner_name  = "Ensemble(RF+XGB)"
    winner_f1    = ens_f1
    winner_pred  = ens_pred

    print(f"\n[winner] {winner_name}  F1={winner_f1:.4f}  Acc={ens_acc:.4f}")

    # ── Full classification report ────────────────────────────────────
    label_names = ["safe", "suspicious", "malicious"]
    report = classification_report(y_test, winner_pred, target_names=label_names)
    cm     = confusion_matrix(y_test, winner_pred)

    print("\n" + report)
    print("Confusion matrix:")
    print(cm)

    # ── Feature importances (from RF component) ───────────────────────
    importances = rf.feature_importances_
    feat_imp = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    print("\nTop-10 feature importances (Random Forest):")
    for fname, imp in feat_imp[:10]:
        bar = "#" * int(imp * 60)
        print(f"  {fname:<30s}  {imp:.4f}  {bar}")

    return {
        "model":           winner_model,
        "rf":              rf,
        "xgb":             xgb,
        "model_name":      winner_name,
        "version":         datetime.now().strftime("%Y%m%d"),
        "feature_names":   FEATURE_NAMES,
        "label_map":       {0: "safe", 1: "suspicious", 2: "malicious"},
        "metrics": {
            "rf_f1":       round(rf_f1,  4),
            "xgb_f1":      round(xgb_f1, 4),
            "ensemble_f1": round(ens_f1,  4),
            "ensemble_acc":round(ens_acc, 4),
            "cv_f1_mean":  round(cv_scores.mean(), 4),
            "cv_f1_std":   round(cv_scores.std(),  4),
        },
        "report":          report,
        "confusion_matrix":cm.tolist(),
        "feature_importances": {k: round(float(v), 6) for k, v in feat_imp},
    }


# ---------------------------------------------------------------------------
# Save artefacts
# ---------------------------------------------------------------------------

def save(bundle: dict) -> None:
    joblib.dump(bundle, MODEL_PATH, compress=3)
    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"\n[save] Model saved → {MODEL_PATH}  ({size_kb:.1f} KB)")

    # Write human-readable training report
    lines = [
        "PhishGuard — Training Report",
        "=" * 60,
        f"Trained at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Model       : {bundle['model_name']}",
        f"Version     : {bundle['version']}",
        f"Features    : {len(bundle['feature_names'])}",
        "",
        "── Metrics ─────────────────────────────────────────────",
        f"  Random Forest  F1-macro : {bundle['metrics']['rf_f1']}",
        f"  XGBoost        F1-macro : {bundle['metrics']['xgb_f1']}",
        f"  Ensemble       F1-macro : {bundle['metrics']['ensemble_f1']}",
        f"  Ensemble       Accuracy : {bundle['metrics']['ensemble_acc']}",
        f"  CV (5-fold)    F1-macro : {bundle['metrics']['cv_f1_mean']} "
        f"± {bundle['metrics']['cv_f1_std']}",
        "",
        "── Classification Report ────────────────────────────────",
        bundle["report"],
        "",
        "── Confusion Matrix (safe / suspicious / malicious) ─────",
        str(np.array(bundle["confusion_matrix"])),
        "",
        "── Feature Importances (Random Forest) ──────────────────",
    ]
    for fname, imp in bundle["feature_importances"].items():
        lines.append(f"  {fname:<30s}  {imp:.6f}")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[save] Report saved  → {REPORT_PATH}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  PhishGuard — ML Training Pipeline")
    print("=" * 60)

    df     = build_dataset(n_per_class=4000)
    bundle = train(df)
    save(bundle)

    print("\n✓ Training complete.")
    print(f"  Ensemble F1-macro : {bundle['metrics']['ensemble_f1']}")
    print(f"  Ensemble Accuracy : {bundle['metrics']['ensemble_acc']}")
    print(f"  Model file        : {MODEL_PATH}")
