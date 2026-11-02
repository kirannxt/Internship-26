# 🛡️ PhishGuard — URL Risk Analysis System

A Flask-based web application that analyses URLs through a **seven-stage detection pipeline** to classify them as Safe, Suspicious, or Malicious — and explains exactly why.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Pipeline Architecture](#pipeline-architecture)
- [Risk Classification](#risk-classification)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Running the App](#running-the-app)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Screenshots](#screenshots)

---

## Overview

PhishGuard analyses every URL through a multi-stage pipeline — from raw input all the way to a human-readable safety recommendation — so you know exactly **why** a link is flagged, not just *that* it was flagged.

It accepts input as:
- A **URL typed directly**
- A **QR code image** (PNG / JPG / GIF) — decoded automatically to extract the embedded URL

Results include a full breakdown of URL structural features, contextual signals, weighted feature fusion scores, redirect chains, and a plain-English safety recommendation.

---

## Features

- 🔗 **Direct URL scanning** with normalisation and redirect resolution
- 📷 **QR code image upload** with drag-and-drop support
- 🔍 **15+ URL structural features** extracted per scan
- 🌐 **Contextual analysis** — brand impersonation, redirect chains, credential-harvesting paths
- ⚖️ **Weighted feature fusion** (55% URL features + 45% context)
- 🚦 **Three-tier classification** — Safe / Suspicious / Malicious
- 📋 **Per-scan result page** with full analysis breakdown and safety recommendation
- 📊 **Dashboard** with scan statistics and recent activity
- 🕓 **Scan history** per user
- 🔐 **Authentication** — register, login (email or username), logout
- 🛡️ **CSRF protection** on all forms

---

## Pipeline Architecture

The flowchart below describes the full processing pipeline:

```
User Input (URL or QR Code)
        │
        ▼
┌─────────────────────┐
│  Stage 1            │
│  Input Detection    │  ── URL text  OR  QR image → decoded URL
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Stage 2            │
│  Validate &         │  ── Structural check, add scheme, lowercase host,
│  Normalise          │     strip tracking params (utm_*, fbclid, gclid…)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Stage 3            │
│  Redirect           │  ── Follow up to 5 HTTP hops to find final destination
│  Resolution         │     Records full redirect chain
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Stage 4            │  ── Domain entropy, suspicious TLDs, IP-address hosts,
│  URL Feature        │     brand in subdomain, Punycode/IDN, URL length,
│  Extraction         │     query param count, executable extensions, keywords…
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Stage 5            │  ── Cross-domain redirect chains, brand impersonation
│  Contextual         │     (e.g. "paypal" in URL but domain ≠ paypal.com),
│  Analysis           │     credential-harvest paths, HTTP on sensitive domains
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Stage 6            │  ── Weighted combination:
│  Feature Fusion     │     55% URL features + 45% contextual signals
│  & Risk Scoring     │     Hard-boost rules for definitive signals
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Stage 7            │  ── Safe (<35%) / Suspicious (35–65%) / Malicious (>65%)
│  Classification &   │     Plain-English safety recommendation with per-signal
│  Recommendation     │     explanations
└─────────────────────┘
```

### Stage Details

| # | Stage | What it does |
|---|-------|-------------|
| 1 | **Input Detection** | Accepts a typed URL or a QR image. When an image is uploaded it is decoded via `pyzbar` to extract the embedded URL. |
| 2 | **Validate & Normalise** | Checks structural validity. Adds `https://` if missing, lowercases the host, removes default ports, strips common tracking parameters (`utm_*`, `fbclid`, `gclid`, `msclkid`, etc.). |
| 3 | **Redirect Resolution** | Follows HTTP redirects (up to 5 hops) using a `HEAD` request with a browser-like User-Agent to find the true destination. The full redirect chain is stored and displayed. |
| 4 | **URL Feature Extraction** | Extracts 15+ structural features: domain entropy, suspicious TLDs, raw-IP hosts, brand keywords in subdomain, Punycode/IDN homograph detection, URL length, query-parameter count, executable file extensions, hex-encoded characters, redirect patterns in path, and more. |
| 5 | **Contextual Analysis** | Layers contextual signals on top: cross-domain redirect chains, brand impersonation detection (claimed brand vs. actual domain), credential-harvesting path patterns (`/login`, `/verify`, `/account`, etc.), and unencrypted HTTP on sensitive domains. |
| 6 | **Feature Fusion & Risk Scoring** | Combines URL structural features (55% weight) and contextual signals (45% weight) into a single fused score. Hard-boost rules override the weighted score for definitive indicators (IP-based hosts, confirmed brand impersonation, executable links). |
| 7 | **Safety Recommendation** | Maps the fused score to a classification and generates a plain-English recommendation, augmented with specific notes for each triggered signal (shortener detected, IP host, brand mismatch, executable link, etc.). |

---

## Risk Classification

| Verdict | Score Range | Meaning |
|---------|-------------|---------|
| ✅ **Safe** | < 35% | No significant phishing indicators. Proceed with normal caution. |
| ⚠️ **Suspicious** | 35% – 65% | Risk signals present. Verify independently before entering credentials. |
| 🚨 **Malicious** | > 65% | Strong phishing / malware indicators. Avoid this link entirely. |

### Signals that trigger hard-boost rules

These bypass weighted scoring and force the fused score to a minimum threshold:

| Signal | Minimum fused score |
|--------|-------------------|
| Raw IP address as host | 60% |
| Brand name in subdomain | 65% |
| Confirmed brand impersonation | 72% |
| Executable file extension (`.exe`, `.bat`, etc.) | 78% |
| Trusted domain (no impersonation) | capped at 25% |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Web framework | Flask 3.0.3 |
| ORM / Database | Flask-SQLAlchemy 3.1.1 + SQLite |
| Authentication | Flask-Login 0.6.3 |
| CSRF protection | Flask-WTF 1.2.1 |
| Password hashing | Werkzeug 3.0.3 |
| HTTP / redirect resolver | requests 2.32.3 |
| QR decoding | pyzbar 0.1.9 + Pillow 10.4.0 |
| Environment config | python-dotenv 1.0.1 |
| Frontend | Vanilla JS + custom CSS design system |

---

## Project Structure

```
Internship-26/
├── app/
│   ├── __init__.py          # Application factory — extensions + blueprint registration
│   ├── auth.py              # Authentication blueprint (login / register / logout)
│   ├── models.py            # SQLAlchemy models: User, ScanHistory
│   ├── routes.py            # Main blueprint (about page)
│   ├── scanner.py           # Core pipeline — all 7 stages + Flask routes
│   ├── static/
│   │   ├── css/style.css    # Full design system + pipeline UI components
│   │   └── js/main.js       # Alerts, nav toggle, password show/hide, count-up
│   └── templates/
│       ├── base.html        # Master layout with navbar, flash messages, footer
│       ├── about.html       # Pipeline documentation page
│       ├── auth/
│       │   ├── login.html
│       │   └── register.html
│       └── scanner/
│           ├── dashboard.html   # Stats cards + recent scans
│           ├── scan.html        # Tabbed URL / QR input form
│           ├── result.html      # Full analysis breakdown
│           └── history.html     # Full scan history list
├── instance/
│   └── app.db               # SQLite database (auto-created)
├── config.py                # Config classes (Development / Testing / Production)
├── run.py                   # Entry point — creates tables, seeds demo user, starts server
├── requirements.txt
└── .env                     # Environment variables (not committed)
```

### Key models

**`User`**
```
id, username (unique), email (unique), password_hash,
created_at, is_active
→ relationship: scans (ScanHistory)
```

**`ScanHistory`**
```
id, user_id (FK), url, original_url, input_type (url|qr),
prediction (safe|suspicious|malicious), probability (0.0–1.0),
risk_level (LOW|MEDIUM|HIGH), model_version,
recommendation (text), details_json (JSON blob),
scanned_at
```

The `details_json` column stores the full pipeline breakdown:
```json
{
  "url_features":   { "domain": "...", "is_ip_address": false, ... },
  "context":        { "brand_mismatch": true, "num_redirects": 2, ... },
  "fusion":         { "fused_score": 0.74, "url_score": 0.68, ... },
  "redirect_chain": ["https://bit.ly/xxx", "https://evil.example.com"]
}
```

---

## Setup & Installation

### Prerequisites

- Python 3.10+
- pip

### 1. Clone the repository

```bash
git clone <repo-url>
cd Internship-26
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note — QR code support:** `pyzbar` requires the `zbar` shared library.
> - **Windows:** the `pyzbar` wheel bundles `libzbar` automatically — no extra step needed.
> - **macOS:** `brew install zbar`
> - **Linux (Debian/Ubuntu):** `sudo apt-get install libzbar0`

### 4. Configure environment variables

Copy `.env.example` to `.env` and set your values:

```env
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///app.db

# Optional: point at a real ML detection service
# SCAN_API_URL=https://your-model-service.example.com/predict
```

---

## Running the App

```bash
python run.py
```

On first run this will:
1. Create all database tables
2. Seed a demo user: `demo@phishguard.io` / `demo1234`
3. Start the server at `http://localhost:5000`

---

## Usage

### Scanning a URL

1. Log in at `http://localhost:5000`
2. Go to **Scan URL** in the navbar
3. Select the **Enter URL** tab, paste any URL, and click **Scan URL**
4. The result page shows:
   - Verdict badge (Safe / Suspicious / Malicious)
   - Safety recommendation with per-signal notes
   - Risk probability score + progress bar
   - **URL Feature Extraction** — table of structural signals + flag chips
   - **Contextual Analysis** — brand impersonation, redirects, credential paths
   - **Feature Fusion** — weighted bar chart of how the final score was computed
   - **Redirect Chain** — each hop from the original URL to the final destination

### Scanning a QR code

1. Go to **Scan URL** and select the **Upload QR Code** tab
2. Drag and drop a QR image onto the drop zone, or click to browse
3. Click **Decode & Scan QR** — the URL is extracted and run through the same pipeline

### Example URLs to test

| URL | Expected result |
|-----|----------------|
| `https://github.com` | ✅ Safe |
| `https://secure-paypal-verify.xyz/login` | 🚨 Malicious |
| `http://192.168.1.1/paypal-login-verify.exe` | 🚨 Malicious |
| `https://login-amazon-account-update.tk` | 🚨 Malicious |
| `https://en.wikipedia.org/wiki/Phishing` | ✅ Safe |

---

## API Reference

### `POST /api/scan`

Scan a URL via JSON. CSRF-exempt — suitable for programmatic use.

**Request**
```http
POST /api/scan
Content-Type: application/json

{ "url": "https://example.com/path" }
```

**Response `200 OK`**
```json
{
  "url": "https://example.com/path",
  "original_url": "https://example.com/path",
  "prediction": "safe",
  "probability": 0.08,
  "risk_level": "LOW",
  "model_version": "pipeline-v2",
  "recommendation": "This URL appears safe to visit...",
  "url_features": {
    "domain": "example.com",
    "tld": ".com",
    "is_ip_address": false,
    "is_trusted_domain": false,
    "has_suspicious_tld": false,
    "has_brand_in_subdomain": false,
    "url_length": 27,
    "domain_entropy": 2.807,
    "suspicious_keywords": [],
    "url_feature_score": 0.07
  },
  "context": {
    "num_redirects": 0,
    "crosses_domains": false,
    "brand_mismatch": false,
    "credential_path": false,
    "context_score": 0.0
  },
  "fusion": {
    "fused_score": 0.08,
    "url_weight": 0.55,
    "context_weight": 0.45,
    "url_score": 0.07,
    "context_score": 0.0
  },
  "redirect_chain": []
}
```

**Error responses**

| Status | Body | Reason |
|--------|------|--------|
| `400` | `{"error": "url field is required"}` | Missing `url` field |
| `422` | `{"error": "invalid url"}` | URL fails structural validation |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-in-production` | Flask session signing key |
| `DATABASE_URL` | `sqlite:///app.db` | SQLAlchemy database URI |
| `SCAN_API_URL` | *(empty)* | External ML model endpoint. When empty, the built-in pipeline is used. |
| `FLASK_ENV` | `development` | Enables debug mode when set to `development` |
| `PORT` | `5000` | Port the server listens on |

When `SCAN_API_URL` is set, the app POSTs `{"url": "<url>"}` to that endpoint and expects a JSON response with at minimum `prediction`, `probability`, and `risk_level` fields.

---

## Demo Credentials

| Field | Value |
|-------|-------|
| Email | `demo@phishguard.io` |
| Password | `demo1234` |

Created automatically on first run. Change or remove in `run.py → seed_demo_user()` before deploying.
