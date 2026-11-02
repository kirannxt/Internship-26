"""
PhishGuard — CSV-Upload Model Trainer
======================================
Provides a web interface to:
  1. Upload a CSV file containing URLs + labels
  2. Map which column is the URL and which is the label
  3. Preview the data (first 5 rows)
  4. Run training (RF + XGBoost ensemble)
  5. View full evaluation report in the browser

Routes
------
  GET  /train            — upload + column-map form
  POST /train/preview    — parse CSV, return column names + preview rows (JSON)
  POST /train/run        — run training, return results (JSON)
  GET  /train/report     — view the last training report
"""

import os
import io
import json
import tempfile
import traceback
from datetime import datetime

from flask import (
    Blueprint, render_template, request, jsonify,
    current_app, redirect, url_for
)
from flask_login import login_required, current_user

trainer = Blueprint("trainer", __name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_DIR   = os.path.join(PROJECT_ROOT, "models")
MODEL_PATH   = os.path.join(MODELS_DIR, "phishguard_model.pkl")
REPORT_PATH  = os.path.join(MODELS_DIR, "training_report.txt")

# Max CSV upload size: 50 MB
MAX_CSV_BYTES = 50 * 1024 * 1024

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _allowed_file(filename: str) -> bool:
    return filename.lower().endswith(".csv")


def _normalise_label(raw: str) -> int | None:
    """
    Map a raw label string to 0 / 1 / 2.

    Accepted values
    ---------------
    0 / safe / legitimate / benign / good  →  0  (safe)
    1 / suspicious / phishing / bad / spam →  1  (suspicious)
    2 / malicious / malware / dangerous    →  2  (malicious)

    Numeric 0/1 (binary datasets) — 0=safe, 1=malicious (common in
    UCI phishing datasets) are also handled.
    """
    v = str(raw).strip().lower()

    # Numeric
    if v in ("0", "0.0"):
        return 0
    if v in ("1", "1.0"):
        return 2        # Binary: 1 = phishing → malicious
    if v in ("2", "2.0"):
        return 2

    # Text
    if v in ("safe", "legitimate", "benign", "good", "ham"):
        return 0
    if v in ("suspicious", "phishing", "phish", "bad", "spam"):
        return 1
    if v in ("malicious", "malware", "dangerous", "defacement", "fraud"):
        return 2

    return None


def _parse_csv(file_bytes: bytes, url_col: str, label_col: str) -> tuple[list, list, list, str | None]:
    """
    Parse CSV bytes. Returns (urls, labels, skipped_rows, error).
    skipped_rows is a list of dicts describing rows that couldn't be parsed.
    """
    import pandas as pd

    try:
        df = pd.read_csv(io.BytesIO(file_bytes), dtype=str, on_bad_lines="skip")
    except Exception as exc:
        return [], [], [], f"Could not parse CSV: {exc}"

    if url_col not in df.columns:
        return [], [], [], f"Column '{url_col}' not found. Available: {list(df.columns)}"
    if label_col not in df.columns:
        return [], [], [], f"Column '{label_col}' not found. Available: {list(df.columns)}"

    urls, labels, skipped = [], [], []
    for i, row in df.iterrows():
        url   = str(row[url_col]).strip()
        raw_l = str(row[label_col]).strip()
        label = _normalise_label(raw_l)

        if not url or url == "nan":
            skipped.append({"row": i + 2, "reason": "empty URL"})
            continue
        if label is None:
            skipped.append({"row": i + 2, "reason": f"unknown label '{raw_l}'"})
            continue

        urls.append(url)
        labels.append(label)

    return urls, labels, skipped, None


def _run_training(urls: list[str], labels: list[int]) -> dict:
    """
    Extract features, train RF + XGBoost ensemble, save model.
    Returns a results dict consumed by the front-end.
    """
    import numpy as np
    import joblib
    from sklearn.ensemble import RandomForestClassifier, VotingClassifier
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
    from xgboost import XGBClassifier
    from app.ml_model import extract_feature_vector, FEATURE_NAMES

    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── Feature extraction ───────────────────────────────────────────
    X, y, bad = [], [], []
    for i, (url, label) in enumerate(zip(urls, labels)):
        try:
            fv = extract_feature_vector(url)
            X.append(fv)
            y.append(label)
        except Exception:
            bad.append(i)

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)

    n_classes = len(set(y))
    if len(X) < 20:
        return {"error": f"Not enough valid rows after feature extraction ({len(X)}). Need at least 20."}
    if n_classes < 2:
        return {"error": "Dataset must contain at least 2 distinct label classes."}

    # ── Train / test split ───────────────────────────────────────────
    test_size = min(0.2, max(0.1, 50 / len(X)))
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42,
        stratify=y if len(X) > 50 else None
    )

    # ── Random Forest ─────────────────────────────────────────────────
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        max_features="sqrt", class_weight="balanced",
        random_state=42, n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_f1   = round(f1_score(y_test, rf_pred, average="macro", zero_division=0), 4)
    rf_acc  = round(accuracy_score(y_test, rf_pred), 4)

    # ── XGBoost ───────────────────────────────────────────────────────
    xgb = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        use_label_encoder=False, eval_metric="mlogloss",
        random_state=42, n_jobs=-1, verbosity=0,
    )
    xgb.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
    xgb_pred = xgb.predict(X_test)
    xgb_f1   = round(f1_score(y_test, xgb_pred, average="macro", zero_division=0), 4)
    xgb_acc  = round(accuracy_score(y_test, xgb_pred), 4)

    # ── Ensemble ──────────────────────────────────────────────────────
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft", n_jobs=-1,
    )
    ensemble.fit(X_train, y_train)
    ens_pred = ensemble.predict(X_test)
    ens_f1   = round(f1_score(y_test, ens_pred, average="macro", zero_division=0), 4)
    ens_acc  = round(accuracy_score(y_test, ens_pred), 4)

    # ── Cross-validation ──────────────────────────────────────────────
    n_splits = min(5, min(len(y[y == c]) for c in set(y)) if n_classes > 1 else 5)
    n_splits = max(2, n_splits)
    cv_scores = cross_val_score(
        rf, X, y,
        cv=StratifiedKFold(n_splits, shuffle=True, random_state=42),
        scoring="f1_macro", n_jobs=-1
    )

    # ── Classification report ─────────────────────────────────────────
    label_names_map = {0: "safe", 1: "suspicious", 2: "malicious"}
    present_labels  = sorted(set(y_test))
    label_names     = [label_names_map.get(l, str(l)) for l in present_labels]
    report_str = classification_report(
        y_test, ens_pred,
        labels=present_labels,
        target_names=label_names,
        zero_division=0
    )
    cm = confusion_matrix(y_test, ens_pred, labels=present_labels).tolist()

    # ── Feature importances ───────────────────────────────────────────
    feat_imp = sorted(
        zip(FEATURE_NAMES, rf.feature_importances_.tolist()),
        key=lambda x: x[1], reverse=True
    )

    # ── Save model ────────────────────────────────────────────────────
    version = datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle = {
        "model":               ensemble,
        "rf":                  rf,
        "xgb":                 xgb,
        "model_name":          "Ensemble(RF+XGB)",
        "version":             version,
        "feature_names":       FEATURE_NAMES,
        "label_map":           {0: "safe", 1: "suspicious", 2: "malicious"},
        "metrics": {
            "rf_f1":           rf_f1,  "rf_acc":  rf_acc,
            "xgb_f1":          xgb_f1, "xgb_acc": xgb_acc,
            "ensemble_f1":     ens_f1, "ensemble_acc": ens_acc,
            "cv_f1_mean":      round(cv_scores.mean(), 4),
            "cv_f1_std":       round(cv_scores.std(),  4),
        },
        "report":              report_str,
        "confusion_matrix":    cm,
        "feature_importances": {k: round(float(v), 6) for k, v in feat_imp},
        "trained_on":          len(X),
        "trained_at":          version,
    }
    joblib.dump(bundle, MODEL_PATH, compress=3)

    # Invalidate the in-memory model cache so next prediction uses new model
    import app.ml_model as _ml
    _ml._cached_model = None

    # ── Write plain-text report ───────────────────────────────────────
    report_lines = [
        "PhishGuard — Training Report (CSV Upload)",
        "=" * 60,
        f"Trained at   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Source       : CSV upload",
        f"Total rows   : {len(X)}",
        f"Train / Test : {len(X_train)} / {len(X_test)}",
        f"Classes      : {label_names}",
        "",
        "Metrics",
        "-------",
        f"  Random Forest  F1   : {rf_f1}    Acc: {rf_acc}",
        f"  XGBoost        F1   : {xgb_f1}   Acc: {xgb_acc}",
        f"  Ensemble       F1   : {ens_f1}   Acc: {ens_acc}",
        f"  CV ({n_splits}-fold) F1 mean : {round(cv_scores.mean(), 4)} +/- {round(cv_scores.std(), 4)}",
        "",
        "Classification Report",
        "---------------------",
        report_str,
        "",
        "Confusion Matrix",
        "----------------",
        str(cm),
        "",
        "Feature Importances (Random Forest)",
        "------------------------------------",
    ]
    for fname, imp in feat_imp:
        report_lines.append(f"  {fname:<30s}  {imp:.6f}")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    # ── Write JSON report (used by the HTML report page) ─────────────
    # Convert all numpy scalar types to plain Python before json.dump
    cm_python = [[int(cell) for cell in row] for row in cm]
    fi_python  = [{"feature": k, "importance": round(float(v), 6)} for k, v in feat_imp]

    report_data = {
        "trained_at":            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version":               str(version),
        "model_name":            "Ensemble (Random Forest + XGBoost)",
        "total_rows":            int(len(X)),
        "train_size":            int(len(X_train)),
        "test_size":             int(len(X_test)),
        "classes":               [str(c) for c in label_names],
        "n_splits":              int(n_splits),
        "metrics": {
            "rf_f1":   float(rf_f1),    "rf_acc":  float(rf_acc),
            "xgb_f1":  float(xgb_f1),   "xgb_acc": float(xgb_acc),
            "ens_f1":  float(ens_f1),   "ens_acc": float(ens_acc),
            "cv_mean": float(round(cv_scores.mean(), 4)),
            "cv_std":  float(round(cv_scores.std(),  4)),
        },
        "classification_report": str(report_str),
        "confusion_matrix":      cm_python,
        "confusion_labels":      [str(c) for c in label_names],
        "feature_importances":   fi_python,
    }
    report_json_path = os.path.join(MODELS_DIR, "training_report.json")
    try:
        with open(report_json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
    except Exception as json_exc:
        import traceback as _tb
        print(f"[PhishGuard] JSON report write failed: {json_exc}")
        print(_tb.format_exc())

    return {
        "success":        True,
        "trained_rows":   len(X),
        "skipped_extract":len(bad),
        "train_size":     len(X_train),
        "test_size":      len(X_test),
        "classes":        label_names,
        "version":        version,
        "metrics": {
            "rf_f1":      rf_f1,   "rf_acc":      rf_acc,
            "xgb_f1":     xgb_f1,  "xgb_acc":     xgb_acc,
            "ens_f1":     ens_f1,  "ens_acc":     ens_acc,
            "cv_mean":    round(cv_scores.mean(), 4),
            "cv_std":     round(cv_scores.std(),  4),
        },
        "report":         report_str,
        "confusion_matrix":cm,
        "confusion_labels":label_names,
        "feature_importances": [
            {"feature": k, "importance": v} for k, v in feat_imp[:15]
        ],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@trainer.route("/train")
@login_required
def train_page():
    """Render the CSV upload + column map form."""
    report_json_path = os.path.join(MODELS_DIR, "training_report.json")
    has_report = os.path.exists(report_json_path)
    return render_template("scanner/train.html",
                           title="Train Model",
                           last_report=has_report)


@trainer.route("/train/preview", methods=["POST"])
@login_required
def train_preview():
    """
    Accepts a CSV file upload.
    Returns JSON: { columns: [...], preview: [{...}, ...], total_rows: int }
    """
    if "csv_file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    f = request.files["csv_file"]
    if not f or not _allowed_file(f.filename):
        return jsonify({"error": "Please upload a .csv file."}), 400

    file_bytes = f.read(MAX_CSV_BYTES + 1)
    if len(file_bytes) > MAX_CSV_BYTES:
        return jsonify({"error": "File exceeds 50 MB limit."}), 400

    try:
        import pandas as pd
        df = pd.read_csv(io.BytesIO(file_bytes), dtype=str, on_bad_lines="skip", nrows=6)
        all_df = pd.read_csv(io.BytesIO(file_bytes), dtype=str, on_bad_lines="skip")
    except Exception as exc:
        return jsonify({"error": f"Could not parse CSV: {exc}"}), 400

    # Store file bytes in server-side session via a temp file
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv",
                                      dir=tempfile.gettempdir(), prefix="phishguard_")
    tmp.write(file_bytes)
    tmp.close()

    columns  = list(df.columns)
    preview  = df.head(5).fillna("").to_dict(orient="records")
    total    = len(all_df)

    # Auto-detect common column names
    url_guess   = next((c for c in columns if c.lower() in
                        ("url", "urls", "link", "address", "domain")), columns[0])
    label_guess = next((c for c in columns if c.lower() in
                        ("label", "labels", "class", "type", "category",
                         "result", "status", "target", "phishing")),
                       columns[-1] if len(columns) > 1 else columns[0])

    return jsonify({
        "columns":     columns,
        "preview":     preview,
        "total_rows":  total,
        "tmp_path":    tmp.name,
        "url_guess":   url_guess,
        "label_guess": label_guess,
    })


@trainer.route("/train/run", methods=["POST"])
@login_required
def train_run():
    """
    Accepts JSON: { tmp_path, url_col, label_col }
    Runs full training pipeline, returns results JSON.
    """
    data      = request.get_json(silent=True) or {}
    tmp_path  = data.get("tmp_path", "").strip()
    url_col   = data.get("url_col", "").strip()
    label_col = data.get("label_col", "").strip()

    # ── Basic validation ──────────────────────────────────────────────
    if not tmp_path or not os.path.exists(tmp_path):
        return jsonify({"error": "Upload session expired. Please re-upload the CSV."}), 400
    if not url_col or not label_col:
        return jsonify({"error": "Both URL column and Label column must be selected."}), 400

    # Prevent path traversal
    if not tmp_path.startswith(tempfile.gettempdir()):
        return jsonify({"error": "Invalid file path."}), 400

    try:
        with open(tmp_path, "rb") as fh:
            file_bytes = fh.read()
    except Exception as exc:
        return jsonify({"error": f"Could not read uploaded file: {exc}"}), 400
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # ── Parse CSV ─────────────────────────────────────────────────────
    urls, labels, skipped, parse_err = _parse_csv(file_bytes, url_col, label_col)
    if parse_err:
        return jsonify({"error": parse_err}), 400
    if len(urls) < 20:
        return jsonify({"error": (
            f"Only {len(urls)} valid rows found after parsing "
            f"({len(skipped)} skipped). Need at least 20."
        )}), 400

    # ── Train ─────────────────────────────────────────────────────────
    try:
        results = _run_training(urls, labels)
    except Exception:
        tb = traceback.format_exc()
        return jsonify({"error": f"Training failed:\n{tb}"}), 500

    if "error" in results:
        return jsonify(results), 400

    results["skipped_rows"]  = len(skipped)
    results["skipped_sample"]= skipped[:5]   # show at most 5 examples
    return jsonify(results), 200


@trainer.route("/train/report")
@login_required
def train_report():
    """Render the last training report as a styled HTML page."""
    report_json_path = os.path.join(MODELS_DIR, "training_report.json")

    if not os.path.exists(report_json_path):
        # Fall back gracefully if no JSON report yet
        return render_template("scanner/report.html",
                               title="Training Report",
                               report=None), 200

    try:
        with open(report_json_path, encoding="utf-8") as f:
            report = json.load(f)
    except Exception as exc:
        report = {"error": str(exc)}

    return render_template("scanner/report.html",
                           title="Training Report",
                           report=report)
