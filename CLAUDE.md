# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a **cybersecurity-focused dataset and fine-tuning project** for key phrase extraction from CVE (Common Vulnerabilities and Exposures) descriptions. The project extracts structured key phrases from vulnerability descriptions to identify root causes, weaknesses, impacts, attack vectors, and affected products/components.

### Core Purpose
- Extract key phrases from CVE vulnerability descriptions
- Train fine-tuned models (primarily Google Gemini Flash) for automated key phrase extraction  
- Process large-scale CVE datasets (targeting 250K+ CVEs)
- Support defensive cybersecurity analysis and vulnerability classification

## Key Development Commands

### Diverse Dataset Generation
```bash
# Generate 50K diverse training dataset from full CVE collection
python create_diverse_cve_dataset.py --cve-dir ../cve_info --cwe-dir ../cvelistV5 --sample-size 50000

# Create validation dataset (500 examples from recent CVEs)
python create_validation_dataset.py --cve-dir ../cve_info --size 500 --years 2023 2024

# Generate inventory of all CVEs with CWE data
python create_diverse_cve_dataset.py --cve-dir ../cve_info --cwe-dir ../cvelistV5 --create-all-cves-csv

# Test with small sample
python create_diverse_cve_dataset.py --cve-dir ../cve_info --cwe-dir ../cvelistV5 --sample-size 100
```

### Legacy Data Conversion
```bash
# Convert CSV training data to JSONL format for model fine-tuning
python convert_csv_to_jsonl.py

# Convert with custom file paths
python convert_csv_to_jsonl.py <input_csv> <output_jsonl>
```

### Python Environment
- Python 3.6+ required
- Standard library modules: `csv`, `json`, `sys`, `pathlib`, `subprocess`, `concurrent.futures`
- No additional dependencies for core scripts

## Architecture & Data Flow

### Dataset Structure
1. **Source Directories** (External - git clone required):
   - `../cve_info/` - CVE files with keyphrases (https://github.com/CyberSecAI/cve_info)
   - `../cvelistV5/` - CVE files with CWE data (https://github.com/CVEProject/cvelistV5)
   - Contains 250K+ CVE JSON files with keyphrase annotations

2. **Generated Training Data**: 
   - `training_data/cve_50k_diverse_sample.jsonl` - 50K diverse training samples
   - `validation_data/cve_validation_dataset.jsonl` - 500 validation samples from 2023-2024
   - Format: User prompt asking for key phrase extraction + model response with structured JSON
   - Stratified sampling across years, content types, and CWE categories

3. **Legacy Data** (Original manual dataset):
   - `data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv` - 5,216 manually reviewed samples
   - `data_in/converted_training_data.jsonl` - converted from CSV format

### Key Phrase Schema
The model extracts these primary key phrases:
- `rootcause`: Root cause of the vulnerability
- `weakness`: Type of weakness/vulnerability  
- `impact`: Impact/consequence of exploitation
- `vector`: Attack vector/method
- `attacker`: Type of attacker/privileges needed

Secondary key phrases (less reliable for complex cases):
- `product`: Affected product name
- `version`: Product version(s)
- `component`: Specific component affected

### Model Focus & Trade-offs
- **Primary focus**: Semantic understanding of vulnerability patterns over exact text matching
- **Approach**: Compound AI system combining LLMs with traditional matching techniques
- **Strengths**: Can identify semantically equivalent phrases even when lexically different
- **Limitations**: Product/version/component extraction less reliable for complex nested relationships

## Fine-tuning Process

### Data Pipeline
1. **Manual Examples** (5 samples) → Few-shot prompting with large LLM
2. **Initial Dataset** (~500 samples) → Fine-tune Gemini 1.5 Flash  
3. **Expanded Dataset** (~5K samples) → Manual curation baseline
4. **Large-Scale Generation** (250K+ CVEs) → Automated diverse sampling
5. **Production Training** (50K samples) → Stratified diverse dataset + 500 validation samples

### Model Platform
- **Primary**: Google VertexAI with Gemini Flash models
- **Previous**: Google AIStudio (no longer supports fine-tuning)
- **Current Model**: gemini-2.0-flash-lite-001

## File Structure

```
├── README.md                              # Main documentation with examples
├── README_create_diverse_cve_dataset.md   # Diverse dataset generation guide
├── README_convert_script.md               # CSV to JSONL conversion guide  
├── compound.md                            # Compound AI system approach
├── create_diverse_cve_dataset.py          # Main dataset generation script
├── create_validation_dataset.py           # Validation dataset generator
├── convert_csv_to_jsonl.py               # Legacy data conversion script
├── training_data/
│   ├── cve_50k_diverse_sample.jsonl      # 50K training dataset
│   ├── cve_inventory.csv                 # Full CVE inventory
│   ├── sampling_metadata.json            # Dataset quality metrics
│   └── generation_summary.md             # Generation summary report
├── validation_data/
│   ├── cve_validation_dataset.jsonl      # 500 validation examples
│   └── validation_summary.json           # Validation dataset summary
├── data_in/                              # Legacy manual data
│   ├── finetune_top25_KeyPhrase_WeaknessDescription_json.csv
│   ├── converted_training_data.jsonl
│   └── sft_train_data.jsonl
├── tests/                                # Comprehensive test suite
│   ├── test_cve_dataset.py              # Unit tests
│   ├── test_main_script.py               # Integration tests
│   ├── run_tests.py                      # Test runner
│   └── test_data/                        # Test data files
└── images/                               # Documentation images
```

## Development Guidelines

### Security Focus
- This is a **defensive cybersecurity project** for vulnerability analysis
- All work should support defensive security purposes only
- CVE data processing is for threat intelligence and defensive analysis

### Data Quality
- Training data has been validated using LLM-as-a-judge + manual review
- Focus on semantic accuracy over exact text matching
- Prioritize common vulnerability patterns and succinct key phrase extraction

### Model Behavior
- Extracts key phrases even when not explicitly stated (e.g., "insert HTML/js code" → "cross-site scripting")
- Prefers succinct over verbose phrases (e.g., "root CLI login without password" vs full description)
- May fix typos in vulnerability descriptions during extraction

## Dataset Generation & Testing

### Diverse Sampling Strategy
- **Temporal Diversity**: Stratified sampling across year categories (1999-2009: 5%, 2010-2015: 10%, 2016-2019: 20%, 2020-2024: 65%)
- **Content Diversity**: Balanced by description length and keyphrase completeness
- **CWE Diversity**: Samples across different Common Weakness Enumeration categories
- **Quality Control**: Automated filtering for minimum keyphrase requirements

### Dual Data Sources
- **Keyphrase Data**: `../cve_info/` - CVE files with extracted key phrases
- **CWE Data**: `../cvelistV5/` - CVE files with weakness classifications
- **Data Fusion**: Script combines both sources using CVE ID matching
- **Fallback**: Works with keyphrase-only data if CWE directory unavailable

### Validation Strategy
- **Training Set**: 50K samples from diverse years and categories (seed: 42)
- **Validation Set**: 500 recent samples from 2023-2024 only (seed: 999)
- **Non-overlapping**: Validation uses different years to ensure data separation
- **High Quality**: Validation examples require ≥3 filled keyphrases

### Testing Framework
- **Comprehensive Tests**: 26 unit and integration tests covering all functionality
- **Data Source Testing**: Validates both cve_info and cvelistV5 directory reading
- **CWE Extraction Testing**: Tests single/multiple CWE extraction via grep + JSON parsing
- **Sampling Testing**: Verifies diverse sampling algorithms and constraints
- **Error Handling**: Tests graceful handling of missing directories and malformed data
- **Performance Testing**: Ensures reasonable execution times for large datasets

### Command Reference
```bash
# Run complete test suite
cd tests/ && python3 run_tests.py

# Generate production datasets
python3 create_diverse_cve_dataset.py --cve-dir ../cve_info --cwe-dir ../cvelistV5 --sample-size 50000
python3 create_validation_dataset.py --cve-dir ../cve_info --size 500 --years 2023 2024

# Test fine-tuned model (requires VertexAI authentication)
python3 test_fine_tuned_model.py

# Lint and type checking (if available)
npm run lint && npm run typecheck  # Configure as needed
```

### Fine-tuned Model Testing

The `test_fine_tuned_model.py` script tests deployed VertexAI fine-tuned models:

**Authentication Setup:**
```bash
# Authenticate with Google Cloud (required for VertexAI)
gcloud auth application-default login
```

**Configuration:**
- Update `config.py` with your VertexAI project, location, and model endpoint
- For VertexAI endpoints, API keys are not needed - uses default credentials
- Ensure VertexAI API is enabled in your Google Cloud project

**Test Options:**
1. **Predefined Examples**: Test with built-in CVE descriptions
2. **Interactive Mode**: Enter custom CVE descriptions
3. **Conversation Format**: Test with multi-turn conversation examples
4. **Run All Tests**: Execute all test modes