# Testing Guide

## Running Tests

### Option 1: Run All Tests (Recommended)

```bash
# Using the test runner
python run_tests.py
```

### Option 2: Run Individual Test Files

```bash
# Parser tests
python tests/test_parser.py

# Verifier tests
python tests/test_verifier.py

# Cracker tests
python tests/test_cracker.py
```

### Option 3: Using pytest (if installed)

```bash
# Install pytest
pip install pytest

# Run all tests
pytest tests/

# Run with verbose output
pytest -v tests/

# Run specific test file
pytest tests/test_cracker.py

# Run specific test function
pytest tests/test_cracker.py::test_crack_with_common_secret
```

### Option 4: Install as Package (Recommended for Development)

```bash
# Install in development mode
pip install -e .

# Now you can run tests from anywhere
python tests/test_parser.py
python run_tests.py

# Or use the CLI directly
jwt-tool analyze "eyJ..."
```

## Test Coverage

### Phase 1: Parser Tests
- ✅ Parse valid JWT
- ✅ Detect 'none' algorithm
- ✅ Detect missing expiration
- ✅ Timestamp parsing and humanization
- ✅ Detect sensitive data in payload

### Phase 2: Verifier Tests
- ✅ Verify valid HS256 token
- ✅ Detect invalid secret
- ✅ Verify HS384/HS512
- ✅ Handle 'none' algorithm
- ✅ Batch verification with secret list

### Phase 3: Cracker Tests
- ✅ Load common secrets
- ✅ Crack with common secret
- ✅ Crack with wordlist file
- ✅ Handle secret not found
- ✅ Wordlist line counting
- ✅ Progress callback

## Troubleshooting

### ModuleNotFoundError: No module named 'src'

**Solution 1**: Run from project root
```bash
cd /home/dathv2004/Documents/BKDN/Learning/Pentest/jwt-tool
python tests/test_cracker.py
```

**Solution 2**: Install package in development mode
```bash
pip install -e .
```

**Solution 3**: Use the test runner
```bash
python run_tests.py
```

### Import Errors

Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Multiprocessing Issues on Some Systems

If you get multiprocessing errors during cracker tests:
```bash
# The tests should still pass as there's a fallback to single-threaded mode
# Check output for "falling back to single-threaded" message
```

## Writing New Tests

### Template for New Test

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.your_module import YourClass

def test_your_feature():
    """Test description"""
    # Setup
    obj = YourClass()
    
    # Execute
    result = obj.your_method()
    
    # Assert
    assert result == expected_value

if __name__ == '__main__':
    test_your_feature()
    print("✓ test_your_feature")
```

## Continuous Integration

For CI/CD pipelines, use:

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python run_tests.py
```
