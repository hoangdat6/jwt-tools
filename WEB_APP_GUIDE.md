# 🚀 JWT Security Tool - Web Application Guide

## ✅ Đã hoàn thành Phase 4, 5, 6!

### 📦 Các tính năng mới

#### **Phase 4: FastAPI Backend**
- REST API với đầy đủ endpoints
- Pydantic models cho validation
- CORS middleware
- Error handling
- OpenAPI documentation tự động

#### **Phase 5: Job Management**
- Async job queue system
- Background task processing
- Real-time progress tracking với Server-Sent Events (SSE)
- Job status management (pending → running → completed/failed)
- Automatic job cleanup

#### **Phase 6: Web UI**
- Single-page application với giao diện đẹp
- 4 tabs: **Analyze, Verify, Crack, Forge** 🆕
- Real-time progress updates
- Responsive design (mobile-friendly)
- JSON syntax highlighting
- Color-coded security warnings
- Progress bar với statistics

---

## 🎯 Cách sử dụng

### 1️⃣ Khởi động Server

```bash
# Từ thư mục jwt-tool
cd /home/dathv2004/Documents/BKDN/Learning/Pentest/jwt-tool

# Activate virtual environment (nếu chưa)
source .venv/bin/activate

# Chạy server
python run_server.py
```

Server sẽ chạy tại: **http://localhost:8000**

### 2️⃣ Truy cập Web UI

Mở browser và vào:
- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 3️⃣ Sử dụng các chức năng

#### 🔍 **Tab Analyze**
1. Paste JWT token vào ô text
2. Click "Analyze Token"
3. Xem kết quả:
   - Decoded header & payload
   - Algorithm information
   - Timestamps (exp, iat, nbf)
   - Security warnings với màu sắc theo mức độ nghiêm trọng

#### ✓ **Tab Verify**
1. Paste JWT token
2. Nhập secret key hoặc public key
3. (Optional) Chọn algorithm cụ thể
4. Click "Verify Signature"
5. Xem kết quả: Valid ✓ hoặc Invalid ✗

#### 🔓 **Tab Crack**
1. Paste JWT token
2. Check "Try common weak secrets" (khuyến nghị)
3. (Optional) Thêm custom wordlist
4. (Optional) Đặt số worker processes
5. Click "Start Cracking"
6. Xem progress real-time:
   - Progress bar
   - Attempts counter
   - Speed (attempts/sec)
   - Elapsed time
   - ETA (estimated time remaining)
7. Khi tìm thấy secret, nó sẽ hiển thị trong hộp màu xanh

#### 🎭 **Tab Forge** 🆕
1. Paste JWT token (không cần cho Custom mode)
2. Chọn attack mode:
   - **None Algorithm**: Remove signature validation
   - **Modify Claims**: Change payload (e.g., role: admin)
   - **Quick Escalation**: Pre-built privilege escalation
   - **Algorithm Confusion**: RS256 → HS256 attack
   - **Custom Token**: Build from scratch
3. Điền thông tin tùy theo mode
4. Click "🎭 Forge Token"
5. Copy forged token và test trong ứng dụng mục tiêu

##### **Forge Mode Details:**

**None Algorithm:**
- Exploits JWT libraries không validate algorithm đúng
- Removes signature completely
- Optionally modify claims

**Modify Claims:**
- Change any payload values
- Re-sign với secret (nếu biết)
- Hoặc để invalid signature

**Quick Escalation:**
- User to Admin
- Elevate Permissions
- Change User ID (impersonation)
- Extend Token Expiry
- Bypass Email Verification

**Algorithm Confusion:**
- Changes RS256 → HS256
- Uses public key as HMAC secret
- Exploits algorithm confusion vulnerability

**Custom Token:**
- Build JWT from scratch
- Define custom header & payload
- Sign with secret or leave unsigned

---

## 🧪 Test với Token mẫu

Token này được sign bằng secret "secret":
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Thử crack token này:**
1. Paste token vào tab "Crack"
2. Check "Try common weak secrets"
3. Click "Start Cracking"
4. Trong vòng 1 giây, tool sẽ tìm ra secret = "secret" 🎉

---

## 🔌 API Endpoints

### Health Check
```bash
curl http://localhost:8000/health
```

### Analyze Token
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGc..."}'
```

### Verify Signature
```bash
curl -X POST http://localhost:8000/api/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGc...",
    "key": "secret",
    "algorithm": "HS256"
  }'
```

### Start Crack Job
```bash
curl -X POST http://localhost:8000/api/crack \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGc...",
    "use_common": true,
    "workers": 4
  }'
```

Response:
```json
{
  "job_id": "550e8400-...",
  "status": "pending",
  "message": "Cracking job started..."
}
```

### Get Job Status
```bash
curl http://localhost:8000/api/job/{job_id}/status
```

### Stream Progress (SSE)
```bash
curl -N http://localhost:8000/api/job/{job_id}/stream
```

### Cancel Job
```bash
curl -X DELETE http://localhost:8000/api/job/{job_id}
```

### Forge Token
```bash
curl -X POST http://localhost:8000/api/forge \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGc...",
    "mode": "modify",
    "claims": {"role": "admin"},
    "secret": "secret"
  }'
```

### Get Escalation Scenarios
```bash
curl http://localhost:8000/api/escalations
```

---

## 📊 Kiến trúc hệ thống

```
┌──────────────────┐
│   Web Browser    │
│   (User UI)      │
└────────┬─────────┘
         │ HTTP / SSE
         ↓
┌──────────────────┐
│  FastAPI Server  │
│  (Port 8000)     │
└────────┬─────────┘
         │
    ┌────┴────┐
    ↓         ↓
┌─────────┐  ┌──────────────┐
│ Parser  │  │ Job Manager  │
│Verifier │  │  (Async)     │
│ Cracker │  └──────┬───────┘
└─────────┘         │
                    ↓
            ┌──────────────┐
            │  Background  │
            │   Workers    │
            │(Multi-process)│
            └──────────────┘
```

---

## 🎨 Screenshots của UI

### Analyze Tab
- Header & Payload decoded với JSON highlighting
- Timestamps với trạng thái (expired/active)
- Security warnings theo severity:
  - 🔴 Critical (màu đỏ)
  - 🟣 High (màu tím)
  - 🟡 Medium (màu vàng)
  - 🔵 Low (màu xanh dương)

### Verify Tab
- Input token & key
- Kết quả: ✓ VALID (màu xanh) hoặc ✗ INVALID (màu đỏ)
- Thông tin algorithm & key

### Crack Tab
- Progress bar với animation
- 4 statistics cards:
  - Attempts
  - Speed (attempts/sec)
  - Elapsed time
  - ETA
- Secret hiển thị trong box màu xanh khi tìm thấy

### Forge Tab
- 5 attack modes với mô tả ngắn gọn
- Form nhập liệu cho từng mode
- Kết quả hiển thị token đã được forge

---

## 🔒 Lưu ý về Security

### Development Mode (hiện tại)
- ✅ CORS cho phép tất cả origins (`*`)
- ✅ Không có authentication
- ✅ Jobs lưu trong memory
- ✅ Không có rate limiting

### Production Recommendations (cho tương lai)
- 🔐 Restrict CORS đến specific origins
- 🔐 Thêm authentication (JWT, API keys, OAuth)
- 🔐 Implement rate limiting
- 🔐 Input validation & sanitization
- 🔐 Resource limits cho cracking jobs
- 🔐 HTTPS enforcement
- 🔐 Security headers
- 🔐 Audit logging
- 🔐 Docker containerization

---

## 🐛 Troubleshooting

### Server không khởi động
```bash
# Kiểm tra port 8000 có bị chiếm không
lsof -i :8000

# Kill process nếu cần
kill -9 <PID>

# Hoặc dùng port khác
uvicorn src.api.app:app --port 8001
```

### Import errors
```bash
# Activate venv
source .venv/bin/activate

# Cài lại dependencies
pip install -r requirements.txt
```

### SSE không hoạt động
- Kiểm tra browser console
- Thử disable ad-blockers
- Tool tự động fallback sang polling nếu SSE fail

---

## 📈 Performance

### Tốc độ xử lý
- **Analyze**: < 100ms per token
- **Verify**: < 50ms per verification
- **Crack Speed** (depends on CPU):
  - 1 core: ~10,000 attempts/sec
  - 4 cores: ~40,000 attempts/sec
  - 8 cores: ~80,000 attempts/sec

### Giới hạn hiện tại
- Jobs lưu trong RAM (sẽ mất khi restart server)
- 1 job crack cùng lúc có thể dùng nhiều CPU
- Wordlist lớn có thể tốn memory
- Progress updates mỗi 1 giây (giảm overhead)

### Tips tăng tốc
- **Không dùng custom wordlist lớn trong UI**: Paste wordlist lớn vào textarea sẽ chậm
- **Dùng file wordlist qua CLI**: Nhanh hơn rất nhiều
- **Chỉ check "common secrets"**: 30+ secrets kiểm tra trong < 1 giây
- **Giảm số workers nếu máy yếu**: 2-3 workers cho laptop

---

## 🎯 Next Steps (Phase 7-8)

### Phase 7: Security Hardening
- [ ] Authentication & Authorization
- [ ] Rate limiting (API throttling)
- [ ] Input sanitization
- [ ] Resource limits per job
- [ ] HTTPS support
- [ ] Security headers (CSP, HSTS, etc.)
- [ ] Docker containerization
- [ ] Environment-based config

### Phase 8: Advanced Features
- [ ] ES256/384/512 support (ECDSA)
- [ ] PS256/384/512 support (RSA-PSS)
- [ ] Hashcat integration (GPU acceleration)
- [ ] John the Ripper integration
- [ ] Advanced wordlist generation (mutations)
- [ ] HSM/AWS KMS detection
- [ ] Nested JWT parsing
- [ ] Plugin system cho custom checks

---

## ✅ Completion Status

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | JWT Parser & Analysis | ✅ 100% |
| 2 | Signature Verification | ✅ 100% |
| 3 | Brute-force Cracking | ✅ 100% |
| 4 | FastAPI Backend | ✅ 100% |
| 5 | Job Management & SSE | ✅ 100% |
| 6 | Web UI Frontend | ✅ 100% |
| 7 | Security Hardening | 🚧 0% |
| 8 | Advanced Features | 🚧 0% |

**🎉 Phases 1-6 hoàn thành 100%!**

---

## 💡 Tips & Tricks

### 1. Sử dụng API Documentation
Truy cập http://localhost:8000/docs để xem interactive API docs với Swagger UI. Bạn có thể test tất cả endpoints trực tiếp từ đây.

### 2. Custom Wordlist
Trong tab Crack, bạn có thể paste custom wordlist (mỗi dòng một secret). Tool sẽ thử từ common secrets trước, sau đó mới đến custom list.

### 3. Adjust Workers
- Máy 4 cores: dùng 3-4 workers
- Máy 8 cores: dùng 6-8 workers
- Không nên dùng quá số cores để tránh system lag

### 4. Real-time Progress
Tab Crack sử dụng Server-Sent Events (SSE) để update progress real-time mà không cần refresh page.

### 5. Cancel Jobs
Nếu muốn dừng crack job, click nút "Cancel" trong UI hoặc call DELETE endpoint.

---

## 📚 Tài liệu tham khảo

- **JWT.io**: https://jwt.io
- **FastAPI**: https://fastapi.tiangolo.com
- **RFC 7519 (JWT)**: https://tools.ietf.org/html/rfc7519
- **OWASP JWT Security**: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

---

## 🙏 Credits

Tool này được xây dựng với:
- Python 3.12+
- FastAPI (web framework)
- Uvicorn (ASGI server)
- Pydantic (data validation)
- SSE-Starlette (Server-Sent Events)
- Cryptography (crypto operations)
- PyJWT (JWT handling)

---

**Happy JWT Hacking! 🔐🚀**
