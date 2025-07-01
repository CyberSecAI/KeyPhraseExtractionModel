#!/usr/bin/env python3
"""
Create a validation dataset that's different from the training dataset.
Uses a different sampling strategy focusing on recent CVEs (2023-2024) for validation.
"""

import json
import csv
import random
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import logging
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def find_recent_cve_files(cve_directory: Path, years: List[int] = [2023, 2024]) -> List[Path]:
    """Find CVE files from recent years for validation dataset."""
    cve_files = []
    
    for year in years:
        year_dir = cve_directory / str(year)
        if year_dir.exists():
            # Find all JSON files in year subdirectories
            for subdir in year_dir.iterdir():
                if subdir.is_dir():
                    json_files = list(subdir.glob("*.json"))
                    cve_files.extend(json_files)
    
    logger.info(f"Found {len(cve_files)} CVE files from years {years}")
    return cve_files

def load_and_validate_cve(file_path: Path) -> dict:
    """Load CVE file and check if it has good keyphrases for validation."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        cve_id = data.get('cveId', '')
        description = data.get('description', '')
        keyphrases = data.get('keyphrases', {})
        
        # Check if it has reasonable data for validation
        if not cve_id.startswith('CVE-') or len(description) < 50:
            return None
        
        # Count non-empty keyphrases
        filled_keyphrases = 0
        for key, value in keyphrases.items():
            if value:
                if isinstance(value, list):
                    if any(str(item).strip() for item in value):
                        filled_keyphrases += 1
                elif str(value).strip():
                    filled_keyphrases += 1
        
        # Only include CVEs with at least 3 filled keyphrases for good validation examples
        if filled_keyphrases >= 3:
            return {
                'cve_id': cve_id,
                'file_path': str(file_path),
                'description': description,
                'keyphrases': keyphrases,
                'keyphrase_count': filled_keyphrases
            }
    
    except Exception as e:
        logger.warning(f"Error processing {file_path}: {e}")
        return None

def create_validation_jsonl(selected_cves: List[dict], output_path: Path):
    """Create JSONL validation dataset."""
    logger.info(f"Creating validation JSONL with {len(selected_cves)} examples")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for cve_data in selected_cves:
            # Create training example in the same format as training data
            prompt = f"Extract key phrases from this vulnerability description:\n\n{cve_data['description']}"
            
            jsonl_entry = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": prompt}]
                    },
                    {
                        "role": "model", 
                        "parts": [{"text": json.dumps(cve_data['keyphrases'], ensure_ascii=False)}]
                    }
                ]
            }
            
            f.write(json.dumps(jsonl_entry, ensure_ascii=False) + '\n')
    
    logger.info(f"Validation dataset saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Create validation dataset from recent CVEs')
    parser.add_argument('--cve-dir', type=str, default='../cve_info',
                       help='Path to CVE directory (default: ../cve_info)')
    parser.add_argument('--output-dir', type=str, default='validation_data',
                       help='Output directory (default: validation_data)')
    parser.add_argument('--size', type=int, default=500,
                       help='Validation dataset size (default: 500)')
    parser.add_argument('--years', type=int, nargs='+', default=[2023, 2024],
                       help='Years to sample from (default: 2023 2024)')
    parser.add_argument('--seed', type=int, default=999,
                       help='Random seed (default: 999, different from training)')
    
    args = parser.parse_args()
    
    # Set random seed (different from training)
    random.seed(args.seed)
    
    # Setup paths
    cve_dir = Path(args.cve_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    logger.info(f"Creating validation dataset from {cve_dir}")
    logger.info(f"Target years: {args.years}")
    logger.info(f"Target size: {args.size}")
    
    # Find recent CVE files
    cve_files = find_recent_cve_files(cve_dir, args.years)
    
    if len(cve_files) == 0:
        logger.error(f"No CVE files found in {cve_dir} for years {args.years}")
        return
    
    # Process files to find good validation candidates
    logger.info("Processing CVE files to find validation candidates...")
    validation_candidates = []
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        # Submit tasks
        future_to_file = {
            executor.submit(load_and_validate_cve, file_path): file_path 
            for file_path in cve_files
        }
        
        # Process results
        processed = 0
        for future in as_completed(future_to_file):
            cve_data = future.result()
            if cve_data:
                validation_candidates.append(cve_data)
            
            processed += 1
            if processed % 1000 == 0:
                logger.info(f"Processed {processed}/{len(cve_files)} files, found {len(validation_candidates)} candidates")
    
    logger.info(f"Found {len(validation_candidates)} validation candidates")
    
    # Select random sample for validation
    if len(validation_candidates) < args.size:
        logger.warning(f"Only {len(validation_candidates)} candidates available, using all")
        selected_cves = validation_candidates
    else:
        selected_cves = random.sample(validation_candidates, args.size)
    
    logger.info(f"Selected {len(selected_cves)} CVEs for validation dataset")
    
    # Create validation JSONL
    validation_jsonl_path = output_dir / "cve_validation_dataset.jsonl"
    create_validation_jsonl(selected_cves, validation_jsonl_path)
    
    # Create summary
    summary = {
        "validation_size": len(selected_cves),
        "source_years": args.years,
        "avg_keyphrase_count": sum(cve['keyphrase_count'] for cve in selected_cves) / len(selected_cves),
        "cve_id_sample": [cve['cve_id'] for cve in selected_cves[:10]]
    }
    
    summary_path = output_dir / "validation_summary.json"
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Validation dataset created successfully!")
    logger.info(f"Dataset: {validation_jsonl_path}")
    logger.info(f"Size: {len(selected_cves)} examples")
    logger.info(f"Average keyphrases per CVE: {summary['avg_keyphrase_count']:.1f}")
    logger.info(f"Summary: {summary_path}")

if __name__ == "__main__":
    main()