# JWT Security Tool - Implementation Roadmap

## Tổng quan dự án
Tool phân tích và kiểm tra bảo mật JWT tokens, bao gồm parsing, verification, và brute-force weak secrets.

## Quick Start

### Installation

```bash
# Clone repository
cd /home/dathv2004/Documents/BKDN/Learning/Pentest/jwt-tool

# Install dependencies
pip install -r requirements.txt

# Optional: Install as package (recommended)
pip install -e .
```

### Usage

```bash
# Analyze a token
python -m src.cli analyze "eyJhbGc..."

# Verify signature
python -m src.cli verify "eyJhbGc..." "secret-key"

# Crack weak secret
python -m src.cli crack "eyJhbGc..." -w wordlists/common.txt

# Forge/manipulate tokens (NEW!)
python -m src.cli forge "eyJhbGc..." -m modify -c '{"role":"admin"}' -s "secret"

# Run all tests
python run_tests.py
```

## Implementation Roadmap

### Phase 1: Core JWT Parser & Analysis ✅ COMPLETED
**Mục tiêu**: Tạo foundation để parse và phân tích JWT tokens

**Tasks**:
- [x] Tạo cấu trúc project (`src/`, `tests/`, `requirements.txt`)
- [x] Implement JWT parser class (decode header.payload.signature)
- [x] Base64URL decoder/encoder utilities
- [x] JSON pretty-print cho header/payload
- [x] Timestamp humanization (exp/iat/nbf)
- [x] Weak pattern detection (`alg: none`, symmetric vs asymmetric)
- [x] Basic CLI interface để test

**Deliverable**: ✅ Working CLI tool có thể parse và analyze JWT token

**Usage**: See [README_PHASE1.md](README_PHASE1.md) for details

---

### Phase 2: Signature Verification ✅ COMPLETED
**Mục tiêu**: Verify JWT signatures với known keys

**Tasks**:
- [x] HS256/HS384/HS512 signature verification
- [x] RS256/RS384/RS512 public key verification
- [x] Key format handling (raw string, file, PEM)
- [x] Verification result reporting
- [x] Error handling cho invalid keys/formats
- [x] Batch verification (multiple secrets)

**Deliverable**: ✅ CLI tool có thể verify JWT signatures

**Usage**: See [README_PHASE2.md](README_PHASE2.md) for details

---

### Phase 3: Brute-force Engine ✅ COMPLETED
**Mục tiêu**: Crack weak HS256 secrets using wordlists

**Tasks**:
- [x] Wordlist loader (text files, built-in common secrets)
- [x] Multiprocessing brute-force implementation
- [x] Progress tracking và estimation
- [x] Configurable concurrency
- [x] Common weak secrets database (`secret`, `123456`, env var names)
- [x] Memory-efficient wordlist processing

**Deliverable**: ✅ CLI tool có thể crack weak JWT secrets

**Usage**: See [README_PHASE3.md](README_PHASE3.md) for details

---

### Phase 3.5: JWT Token Forging ✅ COMPLETED
**Mục tiêu**: Forge and manipulate JWT tokens for security testing

**Tasks**:
- [x] None algorithm attack
- [x] Modify claims (privilege escalation)
- [x] Algorithm confusion (RS256 → HS256)
- [x] Custom token creation
- [x] Pre-built escalation scenarios
- [x] Re-signing with known secrets
- [x] CLI forge command
- [x] Web UI Forge tab 🆕
- [x] Comprehensive documentation

**Deliverable**: ✅ CLI tool và Web UI có thể forge JWT tokens cho penetration testing

**Usage**: See [README_FORGE.md](README_FORGE.md) for detailed guide

---

### Phase 6: Web UI Frontend ✅ COMPLETED
**Mục tiêu**: Simple web interface

**Tasks**:
- [x] Single-page HTML interface
- [x] Token input textarea
- [x] Analysis results display (header/payload, timestamps)
- [x] Verification form (key input)
- [x] Crack interface (wordlist upload/selection)
- [x] Forge interface (5 attack modes) 🆕
- [x] Progress bar và real-time updates
- [x] JSON syntax highlighting
- [x] Color-coded security warnings
- [x] Responsive design
- [x] Beautiful gradient UI with animations

**Deliverable**: ✅ Complete web application với 4 tabs (Analyze, Verify, Crack, Forge)

**Usage**: See [WEB_APP_GUIDE.md](WEB_APP_GUIDE.md) for details

---

### Phase 7: Security & Production Ready 🛡️
**Mục tiêu**: Production-ready security features

**Tasks**:
- [ ] Input validation và sanitization
- [ ] Rate limiting
- [ ] HTTPS enforcement
- [ ] Security headers (helmet)
- [ ] Resource limits cho cracking jobs
- [ ] Audit logging
- [ ] Docker containerization
- [ ] Environment configuration

**Deliverable**: Production-ready application

### Phase 8: Advanced Features 🚀
**Mục tiêu**: Extended functionality

**Tasks**:
- [ ] RS*/PS* algorithm support
- [ ] Hashcat integration cho GPU cracking
- [ ] John the Ripper integration
- [ ] Advanced wordlist generation
- [ ] HSM/AWS KMS detection
- [ ] Nested JWT parsing
- [ ] Plugin system for custom checks

**Deliverable**: Advanced JWT security testing tool

---

# 2) Tính năng đề xuất (MVP → mở rộng)

MVP:

* Parse token (header.payload.signature, tự động base64url-decode).
* Hiển thị header + payload JSON, timestamps (exp/iat/nbf) humanized.
* Detect weak patterns: `"alg":"none"`, symmetric alg (HS256...) vs asymmetric (RS256...).
* Verify signature given key / wordlist.
* HS256 brute-force with wordlist + concurrency + progress UI.
* Export report (JSON / markdown).
* CLI và Web UI (single-file Flask + minimal React/Vue optional).

Mở rộng sau:

* Support HS384/HS512, PS*/RS* verifying with provided public keys.
* Integration với hashcat / john (offload heavy cracking).
* Add HSM / AWS KMS check (detect keys in cloud infra).
* Plugin to test common weak secrets (blank, secret, 123456, env var names).
* Rate limiting / safe-mode to avoid attacking production.

# 3) Kiến trúc high-level

Simple, single-service architecture for MVP:

* Frontend (single page) — upload token, choose mode (analyze / brute).
* Backend (Flask/FastAPI) — parse, verify, run worker tasks for brute-force (multiprocessing / asyncio).
* Worker: multiprocessing pool or Redis+RQ for heavy jobs (future).
* Storage: ephemeral — no secrets persistent; save reports optionally.

Mermaid sơ đồ (conceptual):

```mermaid
flowchart LR
  A[User UI] -->|POST token| B[API Server (Flask/FastAPI)]
  B --> C{Action}
  C -->|analyze| D[Parser + Verifier]
  C -->|crack| E[Brute-force Worker (multiprocess)]
  E --> F[Progress updates via SSE/WebSocket]
  D --> G[Report]
  E --> G
  G --> A
```

# 4) Tech stack (MVP)

* Backend: Python 3.11+, FastAPI (or Flask), PyJWT / cryptography / python-jose
* Frontend: simple HTML/vanilla JS or React
* Worker: Python multiprocessing or concurrent.futures; for scale use Redis + RQ or Celery
* Container: Docker
* Optional: hashcat / John for GPU-accelerated cracking

# 6) Web UI quick plan (MVP)

Endpoints:

* `POST /api/analyze` — body: `{ token: string }` → returns header, payload, alg warnings
* `POST /api/verify` — `{ token, key }` → returns verify result
* `POST /api/crack` — `{ token, mode: "wordlist", wordlist_name }` → spawns worker, returns job id
* `GET /api/job/{id}/status` — poll for progress
* `GET /api/report/{id}` — final report

UI:

* Single page: paste token → Analyze button → display header/payload + buttons: Verify (enter key), Crack (upload wordlist or choose default). Show progress bar and final secret if found. Export JSON.

# 8) Security hardening & ops

* **Never** persist user-supplied secrets to DB. If you must, encrypt and rotate keys.
* Run cracking jobs in isolated containers with CPU limit + cgroup to avoid host exhaustion.
* Add authentication & RBAC to web UI (who can run cracks).
* Rate-limit API and require explicit confirmation for destructive actions.
* Log audit trail (who requested what) and retention policy.
* If you expose to internet, disable crack endpoint or protect with strong auth and IP allowlist.
* Use HTTPS, helmet headers.

# 9) Performance & scaling tips

* For large wordlists / GPU: export the JWT signature as raw HMAC input and feed to `hashcat --hex` with JWT module (research exact flags) — much faster.
* For distributed cracking, chunk wordlist and run across workers (Kubernetes jobs).
* For RS256, brute-forcing private key is infeasible; you can only test candidate private keys or check weak public key configs.

# 10) Edge cases / gotchas

* Some JWT libraries accept JSON-alg header `alg: "none"` — that's a vulnerability to detect.
* Some tokens include nested JWTs (JWT inside claim) — recursively parse.
* Many tokens are signed with secrets like `secret`, `jwt-secret`, or environment variable values. Include a curated list of common keys in your default wordlist.
* For HS* tokens, secret length and charset matter — huge search spaces are infeasible.

# 11) Example usage scenarios (ethical)

* Audit your app's tokens — detect `alg: none`.
* Verify that token created by dev/staging can be validated with production secret.
* Show devs what a weak secret looks like by cracking a deliberately weak token in a sandbox.

# 12) Getting Started

Để bắt đầu implementation:

1. **Phase 1**: Clone repo này và chạy `python -m src.cli analyze <jwt_token>`
2. **Phase 2**: Test signature verification: `python -m src.cli verify <jwt_token> <key>`
3. **Phase 3**: Try brute-force: `python -m src.cli crack <jwt_token> --wordlist common.txt`
4. **Phase 4+**: Start web server: `python -m src.web` và truy cập `http://localhost:8000`

## Current Status: 🎉 Phases 1-6 COMPLETED!

### 🚀 Quick Start - Web Application

```bash
# 1. Navigate to project
cd /home/dathv2004/Documents/BKDN/Learning/Pentest/jwt-tool

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Start web server
python run_server.py
```

Then open browser: **http://localhost:8000**

### 📖 Available Interfaces

1. **Web UI**: http://localhost:8000 - Beautiful web interface
2. **API Docs**: http://localhost:8000/docs - Interactive API documentation
3. **CLI**: `python -m src.cli <command>` - Command-line interface
   - `analyze` - Parse and analyze tokens
   - `verify` - Verify signatures
   - `crack` - Brute-force weak secrets
   - `forge` - Forge/manipulate tokens

### 📚 Documentation

- **CLI Usage**: See [README_PHASE1.md](README_PHASE1.md), [README_PHASE2.md](README_PHASE2.md), [README_PHASE3.md](README_PHASE3.md)
- **Web App**: See [WEB_APP_GUIDE.md](WEB_APP_GUIDE.md)
- **API Details**: See [README_PHASE4-6.md](README_PHASE4-6.md)

**Next phases**: Security Hardening (Phase 7) and Advanced Features (Phase 8)
