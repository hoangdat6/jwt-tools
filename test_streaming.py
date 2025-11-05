#!/usr/bin/env python3
"""Test streaming crack functionality"""

import sys
sys.path.insert(0, '/home/dathv2004/Documents/BKDN/Learning/Pentest/jwt-tool')

from src.cracker import JWTCracker, ProgressUpdate

# Test token with secret "secret123"
# Generated with: forge_custom({'alg': 'HS256', 'typ': 'JWT'}, {'sub': '1234567890', 'name': 'Test User', 'admin': False}, 'secret123')
test_token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIlRlc3QgVXNlciIsICJhZG1pbiI6IGZhbHNlfQ.SgIGghwh8iKcwqDzXXjkUBCYcmzruVGn9haPs_CerVs"

# Test wordlist content (multi-line string)
wordlist_content = """password
admin
root
secret123
test
"""

def progress_callback(progress: ProgressUpdate):
    print(f"Progress: {progress.attempts} attempts, {progress.attempts_per_second:.2f} attempts/s")

print("=" * 60)
print("Testing Streaming Crack Approach")
print("=" * 60)

# Test 1: With wordlist content (NO temp file!)
print("\n[TEST 1] Cracking with wordlist content (no temp file)...")
cracker = JWTCracker(num_workers=4)
result = cracker.crack_streaming(
    token=test_token,
    wordlist_content=wordlist_content,
    use_common=True,
    progress_callback=progress_callback,
    chunk_size=100
)

print(f"\nResult:")
print(f"  Success: {result.success}")
print(f"  Secret: {result.secret}")
print(f"  Attempts: {result.attempts}")
print(f"  Time: {result.elapsed_time:.3f}s")
print(f"  Speed: {result.attempts_per_second:.2f} attempts/s")

# Test 2: With only common secrets
print("\n" + "=" * 60)
print("[TEST 2] Cracking with common secrets only...")
result2 = cracker.crack_streaming(
    token=test_token,
    use_common=True,
    progress_callback=progress_callback
)

print(f"\nResult:")
print(f"  Success: {result2.success}")
print(f"  Secret: {result2.secret}")
print(f"  Attempts: {result2.attempts}")
print(f"  Time: {result2.elapsed_time:.3f}s")

# Test 3: Regular crack method for comparison
print("\n" + "=" * 60)
print("[TEST 3] Regular crack method (for comparison)...")
result3 = cracker.crack(
    token=test_token,
    wordlist_content=wordlist_content,
    use_common=True,
    progress_callback=progress_callback
)

print(f"\nResult:")
print(f"  Success: {result3.success}")
print(f"  Secret: {result3.secret}")
print(f"  Attempts: {result3.attempts}")
print(f"  Time: {result3.elapsed_time:.3f}s")

print("\n" + "=" * 60)
print("✅ All tests completed!")
print("=" * 60)
