#!/usr/bin/env python3
"""
Convert CSV dataset to JSONL format for fine-tuning.
Converts finetune_top25_KeyPhrase_WeaknessDescription_json.csv to JSONL format
matching the structure of sft_train_data.jsonl.
"""

import csv
import json
import sys
from pathlib import Path


def convert_csv_to_jsonl(csv_file_path, jsonl_file_path):
    """
    Convert CSV with Description and JSON columns to JSONL format.
    
    Args:
        csv_file_path: Path to input CSV file
        jsonl_file_path: Path to output JSONL file
    """
    csv_path = Path(csv_file_path)
    jsonl_path = Path(jsonl_file_path)
    
    if not csv_path.exists():
        print(f"Error: CSV file not found: {csv_file_path}")
        return False
    
    converted_count = 0
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile, \
             open(jsonl_path, 'w', encoding='utf-8') as jsonlfile:
            
            reader = csv.DictReader(csvfile)
            
            for row in reader:
                description = row['Description'].strip()
                json_data = row['JSON'].strip()
                
                # Parse the JSON data to validate it
                try:
                    parsed_json = json.loads(json_data)
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON in row {converted_count + 1}: {e}")
                    continue
                
                # Create the JSONL entry matching the target format
                jsonl_entry = {
                    "contents": [
                        {
                            "role": "user",
                            "parts": [
                                {
                                    "text": f"Extract key phrases from this vulnerability description:\n\n{description}"
                                }
                            ]
                        },
                        {
                            "role": "model",
                            "parts": [
                                {
                                    "text": json_data
                                }
                            ]
                        }
                    ]
                }
                
                # Write to JSONL file
                jsonlfile.write(json.dumps(jsonl_entry, ensure_ascii=False) + '\n')
                converted_count += 1
        
        print(f"Successfully converted {converted_count} entries to {jsonl_file_path}")
        return True
        
    except Exception as e:
        print(f"Error during conversion: {e}")
        return False


def main():
    """Main function to run the conversion."""
    # Default file paths
    csv_file = "data_in/finetune_top25_KeyPhrase_WeaknessDescription_json.csv"
    jsonl_file = "data_in/converted_training_data.jsonl"
    
    # Allow command line arguments
    if len(sys.argv) >= 2:
        csv_file = sys.argv[1]
    if len(sys.argv) >= 3:
        jsonl_file = sys.argv[2]
    
    print(f"Converting {csv_file} to {jsonl_file}")
    
    success = convert_csv_to_jsonl(csv_file, jsonl_file)
    
    if success:
        print("Conversion completed successfully!")
    else:
        print("Conversion failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()