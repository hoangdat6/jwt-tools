"""Test runner for JWT Tool"""

import sys
import subprocess
from pathlib import Path

def run_test_file(test_file: Path):
    """Run a single test file"""
    print(f"\n{'='*70}")
    print(f"Running: {test_file.name}")
    print('='*70)
    
    result = subprocess.run(
        [sys.executable, str(test_file)],
        cwd=test_file.parent.parent,
        capture_output=False
    )
    
    return result.returncode == 0

def main():
    """Run all tests"""
    tests_dir = Path(__file__).parent / "tests"
    test_files = sorted(tests_dir.glob("test_*.py"))
    
    if not test_files:
        print("No test files found!")
        return 1
    
    print(f"Found {len(test_files)} test file(s)")
    
    results = {}
    for test_file in test_files:
        success = run_test_file(test_file)
        results[test_file.name] = success
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, success in results.items():
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"{status:12} {test_name}")
    
    print("="*70)
    
    total = len(results)
    passed = sum(1 for s in results.values() if s)
    print(f"\nTotal: {total} | Passed: {passed} | Failed: {total - passed}")
    
    return 0 if all(results.values()) else 1

if __name__ == '__main__':
    sys.exit(main())
