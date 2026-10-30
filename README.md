# WAFBench: A Reproducible Evaluation Framework for Web Application Firewalls

**WAFBench** is an automated, self-hosted, and reproducible laboratory for the empirical evaluation of Web Application Firewalls (**Nginx 1.26 + ModSecurity v3 + OWASP Core Rule Set v4.0.0**).

---

## Architectural Overview

- **`gateway/`**: Ingress Reverse Proxy powered by Nginx 1.26 + ModSecurity v3 + OWASP Core Rule Set (CRS v4.0.0). Serial JSON audit logging to `/var/log/modsec/audit.log`.
- **`app/`**: Vulnerable target web application (Node.js 20 / Express) exposing four deterministic test endpoints: SQLi (`/login`), Reflected XSS (`/search`), Path Traversal (`/file`), and SSRF (`/fetch`).
- **`mock-internal/`**: Private internal HTTP responder for SSRF testing (`/metadata` sensitive endpoint; `/public/avatar.png` benign asset).
- **`corpus/`**: Standardized test corpus (malicious probes strictly paired with benign/edge cases) and validation scripts.
- **`telemetry/`**: Asynchronous ingestion pipeline tailing ModSecurity audit logs, normalizing to ECS-lite format, and recording to PostgreSQL `event-db`.
- **`dashboard/`**: Streamlit Analytics Dashboard (:8501) visualizing Detection Rate (DR), Blocking Rate (BR), False Positive Rates (FPR), and 3-tier raw evidence.
- **`runner/`**: Automated CLI test harness orchestrating 3-state evaluation (`Direct-to-App`, `DetectionOnly`, `Blocking`) with independent application oracles.

---

## Quick-Start Deployment Guide

### 1. Prerequisites
- Docker Engine & Docker Compose plugin (`docker compose`).
- Recommended Environment: Linux (Ubuntu/Debian) or dedicated VM (2 vCPU, 4–6 GB RAM, 25+ GB SSD).

Create your environment configuration from the template:
```bash
cp .env.example .env
```

### 2. Launch the Entire Laboratory
```bash
make up
# or: docker compose up -d --build
```

### 3. Verify System & Health Status
```bash
make status
```
- **WAF Ingress Route**: `http://localhost:8080`
- **Direct Baseline (Loopback Bypass)**: `http://127.0.0.1:8001`
- **Streamlit Analytics Dashboard**: `http://localhost:8501`

### 4. Switch WAF Operating Profiles
```bash
make mode-detection   # Switches ModSecurity to DetectionOnly and reloads Nginx
make mode-blocking    # Switches ModSecurity to Blocking (On) and reloads Nginx
```

### 5. Trigger Fast Fixture Reset
```bash
make reset
# Truncates sessions/articles and re-seeds Fixture F1 in <= 5 seconds
```

### 6. Execute Test Runner Suite
```bash
make test
# Runs 3-state evaluation with 3 repetitions per case and exports CSV results
```
