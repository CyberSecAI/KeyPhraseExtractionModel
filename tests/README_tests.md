# Test Suite for CVE Dataset Generator

Comprehensive test suite for the diverse CVE dataset generator with unit tests, integration tests, and performance tests.

## Test Structure

```
tests/
├── README_tests.md                 # This file
├── run_tests.py                    # Test runner script
├── test_cve_dataset.py            # Unit tests for core functionality
├── test_main_script.py             # Integration tests for main script
└── test_data/                      # Test data files
    ├── cve_info/                   # Test CVE files with keyphrases
    │   ├── 2024/0xxx/
    │   │   ├── CVE-2024-0001.json  # Complete keyphrase data
    │   │   ├── CVE-2024-0002.json  # Sparse keyphrase data
    │   │   └── CVE-2024-0003.json  # List-based keyphrases
    │   └── 2024/3xxx/
    │       └── CVE-2024-3125.json  # Real-world example
    │   └── 2025/3xxx/
    │       └── CVE-2025-3121.json  # Real-world example
    └── cvelistV5/cves/             # Test CWE data files
        ├── 2024/0xxx/
        │   ├── CVE-2024-0001.json  # Single CWE
        │   └── CVE-2024-0002.json  # No CWE data
        ├── 2024/3xxx/
        │   └── CVE-2024-3125.json  # Single CWE
        └── 2025/3xxx/
            └── CVE-2025-3121.json  # Multiple CWEs
```

## Test Categories

### Unit Tests (`test_cve_dataset.py`)

#### TestCVEDataSources
- Test directory structure validation
- Test CVEAnalyzer initialization with/without CWE directory
- Verify both cve_info and cvelistV5 directories exist

#### TestCWEExtraction
- Test single CWE extraction (`CVE-2024-0001` → `CWE-79`)
- Test multiple CWE extraction (`CVE-2025-3121` → `CWE-119`, `CWE-787`)
- Test missing CWE handling (`CVE-2024-0002` → no CWE)
- Test non-existent CVE handling

#### TestCVEFileAnalysis
- Test complete CVE file analysis (all keyphrases filled)
- Test sparse CVE file analysis (some empty keyphrases)
- Test list-based keyphrase handling
- Verify metadata extraction accuracy

#### TestFileScanning
- Test recursive file discovery
- Test inventory building from test files
- Test CSV export/import functionality
- Verify CWE distribution tracking

#### TestDiverseSampling
- Test DiverseSampler initialization
- Test small sample creation
- Test CWE count categorization logic
- Verify sampling constraints

#### TestEdgeCases
- Test non-existent directory handling
- Test missing CWE directory graceful handling
- Test malformed JSON file handling
- Test error recovery mechanisms

#### TestIntegration
- End-to-end workflow test with small dataset
- Verify complete pipeline: analysis → sampling → output
- Test data consistency across phases

### Integration Tests (`test_main_script.py`)

#### TestMainScriptExecution
- Test script help output
- Test `--create-all-cves-csv` functionality
- Test small sample generation (2 samples)
- Test error handling with invalid directories
- Test behavior with missing CWE directory

#### TestScriptPerformance
- Test execution time bounds (< 60 seconds for test data)
- Verify timeout handling
- Performance regression detection

## Test Data

### CVE Info Test Files (Keyphrases)
- **CVE-2024-0001**: Complete keyphrases, XSS vulnerability
- **CVE-2024-0002**: Sparse keyphrases, buffer overflow
- **CVE-2024-0003**: List-based keyphrases, multiple values
- **CVE-2024-3125**: Real-world example, partial keyphrases
- **CVE-2025-3121**: Real-world example, memory corruption

### CWE Test Files (Classifications)
- **CVE-2024-0001**: Single CWE (CWE-79)
- **CVE-2024-0002**: No CWE data (edge case)
- **CVE-2024-3125**: Single CWE (CWE-79)
- **CVE-2025-3121**: Multiple CWEs (CWE-119, CWE-787)

## Running Tests

### Run All Tests
```bash
cd tests/
python3 run_tests.py
```

### Run Specific Test Categories
```bash
# Unit tests only
python3 -m unittest test_cve_dataset -v

# Integration tests only
python3 -m unittest test_main_script -v

# Specific test class
python3 -m unittest test_cve_dataset.TestCWEExtraction -v

# Single test method
python3 -m unittest test_cve_dataset.TestCWEExtraction.test_extract_multiple_cwes -v
```

### Run Tests with Coverage (if coverage.py installed)
```bash
coverage run --source=.. -m unittest discover -v
coverage report
coverage html  # Generates htmlcov/ directory
```

## Expected Test Results

### Successful Run Output
```
Test Script Execution Time: X.XX seconds
Test Summary:
- Tests run: 25+
- Failures: 0
- Errors: 0
- Overall result: PASS
```

### What Tests Validate

#### Data Source Reading
- ✅ Both cve_info and cvelistV5 directories are accessible
- ✅ JSON files are correctly parsed
- ✅ Directory structure navigation works
- ✅ File discovery finds all test files

#### CWE Extraction
- ✅ Single CWE extraction via grep/JSON parsing
- ✅ Multiple CWE extraction with deduplication
- ✅ Missing CWE handling (no crash)
- ✅ Primary CWE selection logic

#### Keyphrase Processing
- ✅ String-based keyphrases processed correctly
- ✅ List-based keyphrases handled properly
- ✅ Empty/missing keyphrases detected
- ✅ Keyphrase counting logic

#### Sampling Logic
- ✅ Year-based categorization
- ✅ CWE count categorization
- ✅ Sample size constraints respected
- ✅ Diverse selection algorithm

#### Script Integration
- ✅ Command-line argument parsing
- ✅ File I/O operations
- ✅ Error handling and recovery
- ✅ Output file generation

#### Performance
- ✅ Execution time within bounds
- ✅ Memory usage reasonable
- ✅ Concurrent processing works
- ✅ Large dataset scalability indicators

## Troubleshooting Test Issues

### Common Issues

#### Import Errors
```bash
# Ensure you're in the tests directory
cd tests/
# Or add the parent directory to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/.."
```

#### Missing Test Data
```bash
# Verify test data files exist
ls test_data/cve_info/2024/0xxx/
ls test_data/cvelistV5/cves/2024/0xxx/
```

#### Permission Issues
```bash
# Make test files readable
chmod -R 644 test_data/
chmod 755 test_data/ test_data/*/
```

#### Timeout Issues
```bash
# Increase timeout in test files if needed
# Or run with fewer workers
python3 create_diverse_cve_dataset.py --max-workers 1
```

## Adding New Tests

### Test File Template
```python
import unittest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from create_diverse_cve_dataset import CVEAnalyzer

class TestNewFeature(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(__file__).parent / "test_data"
        
    def test_new_functionality(self):
        """Test description."""
        # Test implementation
        self.assertEqual(expected, actual)

if __name__ == '__main__':
    unittest.main(verbosity=2)
```

### Test Data Creation
1. Create minimal JSON files in appropriate directories
2. Follow the existing structure (year/xxx/ subdirectories)
3. Include both positive and negative test cases
4. Test edge cases (missing fields, malformed data)

## Continuous Integration

These tests are designed to be run in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    cd tests/
    python3 run_tests.py
```

The test suite provides comprehensive coverage of the CVE dataset generator functionality, ensuring reliability and correctness across different data sources and usage scenarios.