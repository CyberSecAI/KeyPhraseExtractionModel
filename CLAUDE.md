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

### Data Conversion
```bash
# Convert CSV training data to JSONL format for model fine-tuning
python convert_csv_to_jsonl.py

# Convert with custom file paths
python convert_csv_to_jsonl.py <input_csv> <output_jsonl>
```

### Python Environment
- Python 3.6+ required
- Uses standard library modules: `csv`, `json`, `sys`, `pathlib`
- No additional dependencies for core conversion script

## Architecture & Data Flow

### Dataset Structure
1. **Source Data**: CSV format with `Description` and `JSON` columns
   - Located in `data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv`
   - Contains 5,216 manually reviewed training samples

2. **Training Data**: JSONL format for model fine-tuning
   - `data_in/converted_training_data.jsonl` - converted from CSV
   - `data_in/sft_train_data.jsonl` - supervised fine-tuning format
   - Format: User prompt asking for key phrase extraction + model response with structured JSON

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
3. **Expanded Dataset** (~5K samples) → Current training set
4. **Production Scale** (250K CVEs) → Target deployment

### Model Platform
- **Primary**: Google VertexAI with Gemini Flash models
- **Previous**: Google AIStudio (no longer supports fine-tuning)
- **Current Model**: gemini-2.0-flash-lite-001

## File Structure

```
├── README.md                          # Main documentation with examples
├── README_convert_script.md           # CSV to JSONL conversion guide  
├── compound.md                        # Compound AI system approach
├── convert_csv_to_jsonl.py           # Data conversion script
├── data_in/
│   ├── finetune_top25_KeyPhrase_WeaknessDescription_json.csv  # Training data
│   ├── converted_training_data.jsonl                         # Converted format
│   └── sft_train_data.jsonl                                  # SFT training data
└── images/                           # Documentation images
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