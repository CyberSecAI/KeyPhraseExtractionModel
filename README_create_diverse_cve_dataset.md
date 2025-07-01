# Diverse CVE Dataset Generator

A tool for creating diverse, stratified samples from large CVE datasets for training key phrase extraction models. The script implements multi-dimensional sampling across temporal, content, and vulnerability type diversity with enhanced CWE (Common Weakness Enumeration) support.

## Overview

This tool processes CVE JSON files to create balanced training datasets that represent the full spectrum of vulnerability types, temporal distribution, and complexity levels. It's specifically designed for fine-tuning cybersecurity AI models on vulnerability key phrase extraction tasks.

**Note**: This tool is for **large-scale automated dataset generation** (50K+ samples). For converting small, manually curated CSV datasets to JSONL format, use the separate `convert_csv_to_jsonl.py` utility (see `README_convert_script.md`).

## Input Directory Structure

**IMPORTANT**: The script requires **BOTH** directories to function properly:
- `../cve_info/` - Contains processed CVE files with extracted keyphrases (for training data)
- `../cvelistV5/` - Contains raw CVE files with CWE information (for vulnerability classification)

### Required Directory 1: cve_info (Keyphrases)

Contains processed CVE data with extracted keyphrases for training:

```
../cve_info/                     # CVE files with keyphrases
├── 1999/
│   └── 0xxx/
│       ├── CVE-1999-0001.json
│       ├── CVE-1999-0002.json
│       └── ...
├── 2024/
│   ├── 0xxx/
│   ├── 1xxx/
│   ├── 2xxx/
│   └── 3xxx/
│       ├── CVE-2024-3000.json
│       ├── CVE-2024-3125.json
│       └── ...
├── 2025/
│   └── 3xxx/
│       ├── CVE-2025-3121.json
│       └── ...
└── ...
```

### Required Directory 2: cvelistV5 (CWE Information)

Contains raw CVE data from MITRE with CWE classifications (same structure as cve_info but with cves/ prefix):

```
../cvelistV5/                    # Raw CVE data with CWE info
├── cves/
│   ├── 1999/
│   │   └── 0xxx/
│   │       ├── CVE-1999-0001.json
│   │       ├── CVE-1999-0002.json
│   │       └── ...
│   ├── 2024/
│   │   └── 3xxx/
│   │       ├── CVE-2024-3125.json
│   │       └── ...
│   ├── 2025/
│   │   └── 3xxx/
│   │       ├── CVE-2025-3121.json
│   │       └── ...
│   └── ...
```

### CVE JSON File Formats

#### Processed CVE with Keyphrases (cve_info)
The primary format includes extracted keyphrases for training:

```json
{
    "cveId": "CVE-2024-3125",
    "version": "1.0.0",
    "timestamp": "2024-12-06T11:32:07.789868+00:00",
    "description": "A vulnerability classified as problematic was found in Zebra ZTC GK420d 1.0. This vulnerability affects unknown code of the file /settings of the component Alert Setup Page. The manipulation of the argument Address leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-258868. NOTE The vendor was contacted early about this disclosure but did not respond in any way.",
    "keyphrases": {
        "rootcause": "",
        "weakness": "cross site scripting",
        "impact": "",
        "vector": "",
        "attacker": "",
        "product": "Zebra ZTC GK420d",
        "version": "1",
        "component": "/settings of the component Alert Setup Page"
    }
}
```

#### CWE Info
Standard CVE 5.0 format with CWE information (cvelistV5):

```json
{
  "dataType": "CVE_RECORD",
  "cveMetadata": {
    "cveId": "CVE-2025-3121"
  },
  "containers": {
    "cna": {
      "problemTypes": [
        {
          "descriptions": [
            {
              "type": "CWE",
              "cweId": "CWE-119",
              "description": "Memory Corruption"
            }
          ]
        }
      ],
      "descriptions": [
        {
          "lang": "en",
          "value": "A vulnerability classified as problematic..."
        }
      ]
    }
  }
}
```

### Setting Up Required Directories

**Both directories are required for the script to work properly:**

1. **Set up cve_info (Keyphrases)**:
   ```bash
   # Clone the processed CVE files with keyphrases
   git clone https://github.com/CyberSecAI/cve_info
   ```

2. **Set up cvelistV5 (CWE Information)**:
   ```bash
   # Clone the official CVE repository for CWE data
   git clone https://github.com/CVEProject/cvelistV5.git
   ```

3. **Run the script (uses both directories)**:
   ```bash
   # Uses default paths: ../cve_info and ../cvelistV5
   python create_diverse_cve_dataset.py
   
   # Or specify custom paths
   python create_diverse_cve_dataset.py --cve-dir /path/to/cve_info --cwe-dir /path/to/cvelistV5
   ```




## CWE Information Sources

The script extracts CWE (Common Weakness Enumeration) data from multiple sources within CVE files:

### Primary CWE Extraction
- **Location**: `containers.cna.problemTypes[].descriptions[]`
- **Pattern**: `"type": "CWE"` and `"cweId": "CWE-XXX"`
- **Method**: Fast `grep` extraction with JSON parsing fallback

### CWE Usage

The script uses raw CWE IDs directly for sampling diversity (no category mapping). Common CWE examples:

| CWE ID | Description |
|--------|-------------|
| CWE-79 | Cross-site Scripting |
| CWE-89 | SQL Injection |
| CWE-119 | Buffer Overflow |
| CWE-200 | Information Exposure |
| CWE-352 | Cross-Site Request Forgery |
| CWE-787 | Out-of-bounds Write |
| CWE-22 | Path Traversal |
| CWE-78 | OS Command Injection |

## Usage

### Basic Usage

```bash
# Create 50K diverse sample (requires both ../cve_info and ../cvelistV5)
python create_diverse_cve_dataset.py

# Create comprehensive CVE inventory with all CWEs first
python create_diverse_cve_dataset.py --create-all-cves-csv

# Custom directories for both keyphrases and CWE data
python create_diverse_cve_dataset.py --cve-dir /path/to/cve_info --cwe-dir /path/to/cvelistV5 --sample-size 25000
```

### Command Line Options

```bash
python create_diverse_cve_dataset.py [OPTIONS]

Options:
  --cve-dir PATH              Path to CVE directory with keyphrases (default: ../cve_info)
  --cwe-dir PATH              Path to CWE directory (default: ../cvelistV5)
  --output-dir PATH           Output directory (default: data_out)
  --sample-size INT           Number of CVEs to sample (default: 50000)
  --max-workers INT           Worker threads for processing (default: 8)
  --seed INT                  Random seed for reproducibility (default: 42)
  --create-all-cves-csv       Create comprehensive CSV with all CVEs and CWEs
  --help                      Show help message
```

### Example Workflows

#### 1. Initial Data Exploration
```bash
# First, ensure both directories are available
git clone https://github.com/CyberSecAI/cve_info     # CVE files with keyphrases
git clone https://github.com/CVEProject/cvelistV5.git # CVE files with CWE data

ls ../cve_info/       # Should contain CVE files with keyphrases
ls ../cvelistV5/cves/ # Should contain CVE files with CWE data

# Create comprehensive inventory to understand your dataset
python create_diverse_cve_dataset.py --create-all-cves-csv

# Review the generated all_cves_with_cwe.csv file
# Check CWE distribution and coverage
```

#### 2. Dataset Generation
```bash
# Generate training dataset (uses both keyphrases and CWE data)
python create_diverse_cve_dataset.py \
  --sample-size 50000 \
  --output-dir training_data \
  --max-workers 12

# With custom directory paths
python create_diverse_cve_dataset.py \
  --cve-dir /path/to/cve_info \
  --cwe-dir /path/to/cvelistV5 \
  --sample-size 50000 \
  --output-dir training_data
```

#### 3. Custom Sampling
```bash
# Smaller, focused sample for specific research
python create_diverse_cve_dataset.py \
  --sample-size 10000 \
  --seed 123 \
  --output-dir pilot_study
```

## Output Files

The script generates several output files in the specified output directory:

### Core Output Files
- **`cve_50k_diverse_sample.jsonl`**: Training dataset in JSONL format
- **`cve_inventory.csv`**: Metadata for sampled CVEs
- **`sampling_metadata.json`**: Detailed statistics and distributions
- **`generation_summary.md`**: Human-readable summary report

### Optional Output Files
- **`all_cves_with_cwe.csv`**: Complete inventory (with `--create-all-cves-csv`)

### CSV Column Definitions

#### cve_inventory.csv / all_cves_with_cwe.csv
| Column | Description | Example |
|--------|-------------|---------|
| `cve_id` | CVE identifier | `CVE-2025-3121` |
| `year` | CVE year | `2025` |
| `file_path` | Path to JSON file | `/path/to/CVE-2025-3121.json` |
| `description_length` | Character count | `245` |
| `keyphrase_count` | Number of keyphrases | `3` |
| `weakness_type` | Weakness category | `buffer_overflow` |
| `cwe_ids` | Pipe-separated CWE IDs | `CWE-119\|CWE-787` |
| `cwe_count` | Number of CWEs | `2` |
| `primary_cwe_id` | Primary CWE ID for sampling | `CWE-119` |
| `has_weakness` | Has weakness keyphrase | `True` |
| `has_impact` | Has impact keyphrase | `True` |
| `has_vector` | Has vector keyphrase | `False` |
| `has_product` | Has product keyphrase | `True` |

## Sampling Strategy

### Multi-Dimensional Stratification

The script implements sophisticated sampling across multiple dimensions:

#### 1. Temporal Distribution (Year-based)
- **1999-2009**: 5% (2,500 samples) - Historical vulnerabilities
- **2010-2015**: 10% (5,000 samples) - Early modern era
- **2016-2019**: 20% (10,000 samples) - Cloud/mobile era
- **2020-2024**: 65% (32,500 samples) - Recent vulnerabilities

#### 2. Content Diversity
- **Description Length**: Short (<250), Medium (250-400), Long (>400)
- **Keyphrase Completeness**: Complete (4+), Partial (2-3), Sparse (0-1)

#### 3. CWE-Based Diversity
- **CWE IDs**: Uses raw CWE IDs directly, distributed evenly across different CWE types
- **CWE Count**: 70% single CWE, 18% multiple, 10% none, 2% many

#### 4. Within-Category Sampling
- 70% allocated by individual CWE ID diversity (even distribution across all CWE IDs)
- 30% allocated by CWE count diversity (single vs multiple CWEs)
- Avoids duplicates between sampling dimensions

## Requirements

### System Requirements
- Python 3.6+
- Unix-like system with `grep` command
- Sufficient disk space for CVE data and outputs

### Python Dependencies
- Standard library only (no external packages required)
- `json`, `csv`, `subprocess`, `pathlib`, `collections`, `concurrent.futures`

### Performance Considerations
- **Memory**: ~1-2GB for 250K CVEs
- **Processing Time**: ~10-30 minutes for full dataset
- **Disk Space**: ~500MB for outputs
- **CPU**: Configurable worker threads (default: 8)

## Error Handling

The script includes robust error handling for common issues:

### File Processing Errors
- Malformed JSON files are skipped with warnings
- `grep` command failures fallback to JSON parsing
- Missing CWE information handled gracefully

### Performance Optimization
- Concurrent file processing with ThreadPoolExecutor
- Efficient `grep`-based CWE extraction
- Progress logging every 1000 files

### Data Quality Validation
- Removes duplicate CWE IDs within CVEs
- Validates CVE ID format
- Handles missing or empty fields

## Integration with Training Pipelines

### JSONL Format Compatibility
The output JSONL format is compatible with major ML frameworks:

```json
{
  "contents": [
    {
      "role": "user",
      "parts": [{"text": "Extract key phrases from this vulnerability description:\n\nA vulnerability..."}]
    },
    {
      "role": "model",
      "parts": [{"text": "{\"weakness\": \"memory corruption\", \"impact\": \"denial of service\"}"}]
    }
  ]
}
```

### Fine-tuning Integration
- **Google VertexAI**: Direct JSONL upload
- **OpenAI**: Compatible format
- **Hugging Face**: Easy conversion to datasets format

## Troubleshooting

### Common Issues

#### "No JSON files found"
- Verify CVE directory path: `--cve-dir /path/to/cve_info`
- Verify CWE directory path: `--cwe-dir /path/to/cvelistV5`
- Check directory permissions
- Ensure JSON files exist in correct locations
- For cvelistV5: JSON files should be in `cves/YYYY/Nxxx/` subdirectories

#### "grep command not found"
- Install grep: `apt-get install grep` (Ubuntu) or `brew install grep` (macOS)
- Script will fallback to JSON parsing (slower)

#### Memory issues with large datasets
- Reduce `--max-workers` value
- Process in smaller chunks
- Use `--create-all-cves-csv` to estimate memory needs first

#### Slow processing
- Increase `--max-workers` (but not beyond CPU cores)
- Ensure CVE directory is on fast storage (SSD)
- Use `grep` optimization by installing latest version

### Performance Tuning

```bash
# Fast processing for large datasets
python create_diverse_cve_dataset.py \
  --max-workers 16 \
  --cve-dir /ssd/path/to/cve_info \
  --cwe-dir /ssd/path/to/cvelistV5

# Conservative processing for limited resources
python create_diverse_cve_dataset.py \
  --max-workers 4 \
  --sample-size 10000
```

## Related Tools

This repository contains complementary dataset generation tools:

- **`create_diverse_cve_dataset.py`** (this tool) - Large-scale automated dataset generation from CVE repositories
- **`convert_csv_to_jsonl.py`** - Convert small, manually curated CSV datasets to JSONL format
- See `README_convert_script.md` for CSV conversion workflow

## License and Usage

This tool is designed for defensive cybersecurity research and training purposes. The generated datasets should be used responsibly for:

- Vulnerability analysis and classification
- Security research and education
- Defensive AI model training
- Threat intelligence applications

Do not use for malicious purposes or offensive security activities.