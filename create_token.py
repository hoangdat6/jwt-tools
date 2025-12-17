import jwt
import json
from datetime import datetime, timedelta

def create_token(payload, secret_key, algorithm='HS256'):
    """
    Tạo JWT token đầy đủ thông tin chuẩn + custom claims
    """
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token


def main():
    secret_key = 'your-super-secret-key'  # KHÔNG để hardcode trong code thật
    
    now = datetime.utcnow()
    
    # ===== Payload đầy đủ =====
    payload = {
        # --- Standard claims ---
        "iss": "https://auth.example.com",         # Issuer: bên phát hành
        "aud": "https://api.example.com",          # Audience: bên nhận hợp lệ
        "iat": int(now.timestamp()),               # Issued At: thời điểm tạo token
        "exp": int((now + timedelta(hours=24)).timestamp()),  # Expiration Time: hết hạn sau 24h

        # --- Custom claims (tùy hệ thống) ---
        "sub": "123",                              # Subject: định danh user
        "user_id": 123,
        "role": "admin",
        "permissions": ["read", "write", "delete"],
        "organization": {
            "id": "org_001",
            "name": "Example Corp"
        },
        "device": {
            "id": "dev-abc-123",
            "os": "Linux",
            "browser": "Chrome"
        },
        "login_method": "password",
        "2fa_enabled": True,
        "session_id": "sess_456xyz"
    }

    # ===== Tạo token =====
    token = create_token(payload, secret_key)

    # ===== In kết quả =====
    print("✅ JWT Token tạo thành công:\n")
    print(token)
    print("\n" + "="*70)
    print("📦 Payload:")
    print(json.dumps(payload, indent=2))

if __name__ == "__main__":
    main()
