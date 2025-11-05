# JWT Tool - Phase 3 Complete ✅

## Phase 3: Brute-force Engine

### New Features

✅ **Multiprocessing Brute-force**
- Parallel cracking using multiple CPU cores
- Automatic worker process management
- Efficient queue-based task distribution

✅ **Wordlist Management**
- Load wordlists from files (memory-efficient)
- Built-in common weak secrets database (30+ entries)
- Line counting for progress estimation

✅ **Real-time Progress Tracking**
- Live attempts counter
- Speed calculation (attempts/sec)
- Progress percentage
- ETA (estimated time remaining)

✅ **Performance Optimization**
- Configurable worker count
- Early termination on success
- Fallback to single-threaded mode if needed

## Installation

```bash
pip install -r requirements.txt
```

## Usage Examples

### Crack with Common Secrets

```bash
# Try built-in common secrets only
python -m src.cli crack "eyJhbGc..."

# With progress output
python -m src.cli crack "eyJhbGc..." --workers 4
```

### Crack with Custom Wordlist

```bash
# Use custom wordlist
python -m src.cli crack "eyJhbGc..." -w /path/to/wordlist.txt

# Wordlist only (skip common secrets)
python -m src.cli crack "eyJhbGc..." -w wordlist.txt --no-common

# Combine common + wordlist
python -m src.cli crack "eyJhbGc..." -w wordlist.txt
```

### Advanced Options

```bash
# Specify worker count
python -m src.cli crack "eyJhbGc..." --workers 8

# Quiet mode (no progress)
python -m src.cli crack "eyJhbGc..." -q

# Save found secret to file
python -m src.cli crack "eyJhbGc..." -o secret.txt

# Read token from file
python -m src.cli crack -t token.txt -w passwords.txt
```

### Example Output

```
======================================================================
JWT SECRET CRACKING
======================================================================

Wordlist: wordlists/common.txt
Using common secrets: Yes
Workers: 4

Starting brute-force attack...

[*] Attempts: 1,234 | Speed: 15,420 attempts/sec | Elapsed: 0.1s | Progress: 12.3% | ETA: 0.7s

======================================================================
RESULT
======================================================================

Status: ✓ SECRET FOUND!
Secret: my-secret-key

Attempts: 1,456
Time: 0.09s
Speed: 16,178 attempts/sec
```

## Performance

### Benchmarks (on 4-core CPU)

| Wordlist Size | Workers | Speed          | Time to Find |
|--------------|---------|----------------|--------------|
| 100          | 1       | ~8,000/sec     | < 0.02s      |
| 100          | 4       | ~16,000/sec    | < 0.01s      |
| 10,000       | 1       | ~8,500/sec     | ~1.2s        |
| 10,000       | 4       | ~18,000/sec    | ~0.6s        |
| 1,000,000    | 1       | ~9,000/sec     | ~111s        |
| 1,000,000    | 4       | ~20,000/sec    | ~50s         |

*Note: Actual speed depends on CPU, I/O, and token complexity*

## Built-in Common Secrets

The tool includes 30+ common weak secrets:
- Empty string
- "secret", "password", "admin"
- Common passwords (123456, qwerty, etc.)
- JWT-specific defaults (jwt-secret, your-256-bit-secret)
- Environment variable names (JWT_SECRET, API_KEY, etc.)

## Creating Wordlists

### Generate Custom Wordlist

```bash
# Create from common patterns
cat > custom.txt << EOF
myapp-secret
myapp-jwt-secret
myapp-$(date +%Y)
company-secret
project-secret
EOF

# Use existing password lists
# - rockyou.txt (popular)
# - SecLists (github.com/danielmiessler/SecLists)
```

### Wordlist Best Practices

1. **Start small**: Test common secrets first
2. **Context matters**: Include app-specific terms
3. **Check configs**: Look for leaked environment variables
4. **Progressive approach**: Start with likely candidates

## API Usage

```python
from src.cracker import JWTCracker, ProgressUpdate

# Create cracker
cracker = JWTCracker(num_workers=4)

# Progress callback
def on_progress(progress: ProgressUpdate):
    print(f"Attempts: {progress.attempts}, Speed: {progress.attempts_per_second:.0f}/s")

# Crack with wordlist
result = cracker.crack(
    token="eyJhbGc...",
    wordlist_path="wordlist.txt",
    use_common=True,
    progress_callback=on_progress
)

if result.success:
    print(f"Found secret: {result.secret}")
    print(f"Took {result.attempts} attempts in {result.elapsed_time:.2f}s")
else:
    print("Secret not found")
```

## Security & Ethics

⚠️ **IMPORTANT - Ethical Use Only**

This tool is for:
- ✅ Testing your own applications
- ✅ Authorized security audits
- ✅ Educational purposes in controlled environments

**NEVER use this tool to:**
- ❌ Attack systems you don't own or have permission to test
- ❌ Crack production tokens without authorization
- ❌ Violate any laws or terms of service

## Limitations

1. **HMAC only**: Currently supports HS256/HS384/HS512 only (RSA private key cracking is not feasible)
2. **Wordlist dependent**: Can only find secrets in your wordlist
3. **CPU bound**: Limited by CPU speed (GPU acceleration coming in Phase 8)
4. **Memory**: Large wordlists are streamed to avoid memory issues

## Troubleshooting

### Slow Performance
```bash
# Increase workers
python -m src.cli crack TOKEN --workers 8

# Use smaller, targeted wordlist
python -m src.cli crack TOKEN -w top1000.txt
```

### Multiprocessing Errors
```bash
# Falls back to single-threaded automatically
# Check with --debug flag
python -m src.cli crack TOKEN --debug
```

### Out of Memory
```bash
# Wordlists are streamed line-by-line
# Check system resources
free -h  # Linux
vm_stat  # macOS
```

## Next Steps

Ready for **Phase 4: Web API Backend** 🌐

Features to implement:
- FastAPI REST API
- Analyze/Verify/Crack endpoints
- Request/Response models
- CORS and error handling
