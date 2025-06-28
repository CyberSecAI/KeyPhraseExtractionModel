# CSV to JSONL Converter Script

## Overview

This script converts vulnerability description data from CSV format to JSONL format suitable for fine-tuning language models on key phrase extraction tasks.

## Input Format

The script expects a CSV file with two columns:
- `Description`: Vulnerability descriptions (text)
- `JSON`: Structured key phrase data in JSON format

Example CSV row:
```csv
Description,JSON
"In geniezone driver, there is a possible out of bounds read due to an incorrect bounds check...","{""rootcause"": ""incorrect bounds check"", ""weakness"": ""out of bounds read"", ""impact"": ""local information disclosure""...}"
```

## Output Format

The script generates JSONL (JSON Lines) format where each line contains a training example with:
- User prompt asking to extract key phrases from the vulnerability description
- Model response containing the structured JSON data

Example JSONL output:
```json
{"contents": [{"role": "user", "parts": [{"text": "Extract key phrases from this vulnerability description:\n\nIn geniezone driver, there is a possible out of bounds read due to an incorrect bounds check..."}]}, {"role": "model", "parts": [{"text": "{\"rootcause\": \"incorrect bounds check\", \"weakness\": \"out of bounds read\", \"impact\": \"local information disclosure\"...}"}]}]}
```

## Usage

### Basic Usage
```bash
python convert_csv_to_jsonl.py
```

This uses default file paths:
- Input: `data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv`
- Output: `data_in/converted_training_data.jsonl`

### Custom File Paths
```bash
python convert_csv_to_jsonl.py <input_csv_file> <output_jsonl_file>
```

Example:
```bash
python convert_csv_to_jsonl.py my_data.csv my_training_data.jsonl
```

## Features

- **Error Handling**: Validates JSON data and skips invalid entries
- **Progress Reporting**: Shows conversion progress and final count
- **UTF-8 Support**: Handles international characters properly
- **Flexible Input**: Accepts command-line arguments for file paths

## Requirements

- Python 3.6+
- Standard library modules: `csv`, `json`, `sys`, `pathlib`

## Output

The script will:
1. Display the files being processed
2. Show warnings for any invalid JSON entries (skipped)
3. Report the total number of successfully converted entries
4. Create the output JSONL file ready for model training

## Error Handling

- Checks if input CSV file exists
- Validates JSON format in each row
- Reports specific errors with row numbers
- Continues processing valid entries even if some are invalid