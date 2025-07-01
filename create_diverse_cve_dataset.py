#!/usr/bin/env python3
"""
Create a diverse 50K CVE dataset from the ~260K CVEs in ../cve_info
for fine-tuning key phrase extraction models.

This script implements stratified sampling across multiple dimensions:
- Temporal diversity (year-based distribution)
- Content diversity (description length, keyphrase completeness)
- Vulnerability type diversity (weakness categories)
"""

import json
import csv
import random
import subprocess
from pathlib import Path
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
import logging
from dataclasses import dataclass
import argparse
import time
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class CVEMetadata:
    """Metadata for a single CVE entry."""
    cve_id: str
    year: int
    file_path: str
    description_length: int
    keyphrase_count: int
    weakness_type: str
    cwe_ids: List[str]  # List of CWE IDs
    cwe_count: int  # Number of CWEs
    primary_cwe_id: str  # Primary CWE ID for sampling
    has_weakness: bool
    has_impact: bool
    has_vector: bool
    has_product: bool

class CVEAnalyzer:
    """Analyzes CVE dataset and creates inventory for diverse sampling."""
    
    def __init__(self, cve_directory: Path, cwe_directory: Path = None):
        self.cve_directory = Path(cve_directory)
        self.cwe_directory = Path(cwe_directory) if cwe_directory else None
        self.inventory: List[CVEMetadata] = []
        self.year_distribution = Counter()
        self.weakness_distribution = Counter()
        self.cwe_distribution = Counter()
        self.cwe_count_distribution = Counter()
        
    def extract_cwes_from_file(self, file_path: Path) -> Tuple[List[str], int, str]:
        """Extract all CWE IDs from CVE JSON file using grep pattern.
        Returns: (cwe_ids, cwe_count, primary_cwe_id)
        """
        cwe_ids = []
        
        try:
            # Use grep to find all CWE lines more efficiently
            result = subprocess.run(
                ['grep', '-E', r'"cweId":\s*"CWE-[0-9]+"', str(file_path)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # Extract all CWE IDs using regex
                cwe_matches = re.findall(r'"cweId":\s*"(CWE-\d+)"', result.stdout)
                if cwe_matches:
                    # Remove duplicates while preserving order
                    seen = set()
                    for cwe_id in cwe_matches:
                        if cwe_id not in seen:
                            cwe_ids.append(cwe_id)
                            seen.add(cwe_id)
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            # Fallback to JSON parsing if grep fails
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Look for CWE in problemTypes
                containers = data.get('containers', {})
                cna = containers.get('cna', {})
                problem_types = cna.get('problemTypes', [])
                
                seen = set()
                for problem_type in problem_types:
                    descriptions = problem_type.get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('type') == 'CWE' and 'cweId' in desc:
                            cwe_id = desc['cweId']
                            if cwe_id not in seen:
                                cwe_ids.append(cwe_id)
                                seen.add(cwe_id)
                                
            except Exception:
                pass
        
        # Determine primary CWE ID for sampling
        primary_cwe_id = cwe_ids[0] if cwe_ids else ""
        
        return cwe_ids, len(cwe_ids), primary_cwe_id

    def extract_cwes_from_cve_id(self, cve_id: str) -> Tuple[List[str], int, str]:
        """Extract CWE IDs for a given CVE ID from the CWE directory.
        Returns: (cwe_ids, cwe_count, primary_cwe_id)
        """
        cwe_ids = []
        
        if not self.cwe_directory:
            return cwe_ids, 0, ""
        
        # Extract year and number from CVE ID (e.g., CVE-2025-3121)
        try:
            parts = cve_id.split('-')
            if len(parts) != 3 or parts[0] != 'CVE':
                return cwe_ids, 0, ""
            
            year = parts[1]
            number = int(parts[2])
            
            # Determine the subdirectory (0xxx, 1xxx, etc.)
            subdir = f"{number // 1000}xxx"
            
            # Construct path to CWE file
            cwe_file_path = self.cwe_directory / "cves" / year / subdir / f"{cve_id}.json"
            
            if not cwe_file_path.exists():
                return cwe_ids, 0, ""
            
            # Use the existing file-based extraction method
            return self.extract_cwes_from_file(cwe_file_path)
                    
        except (ValueError, IndexError):
            pass
        
        return cwe_ids, 0, ""
    
        
    def analyze_cve_file(self, file_path: Path) -> Optional[CVEMetadata]:
        """Analyze a single CVE JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            cve_id = data.get('cveId', '')
            if not cve_id.startswith('CVE-'):
                return None
                
            # Extract year from CVE ID
            year = int(cve_id.split('-')[1])
            
            description = data.get('description', '')
            description_length = len(description)
            
            keyphrases = data.get('keyphrases', {})
            
            # Count non-empty keyphrases (handle both strings and lists)
            keyphrase_count = 0
            for value in keyphrases.values():
                if value:
                    if isinstance(value, list):
                        # For lists, count if any non-empty elements
                        if any(str(item).strip() for item in value):
                            keyphrase_count += 1
                    elif str(value).strip():
                        keyphrase_count += 1
            
            # Extract CWE information from CWE directory
            cwe_ids, cwe_count, primary_cwe_id = self.extract_cwes_from_cve_id(cve_id)
            
            # Extract weakness type (primary categorization)
            weakness = keyphrases.get('weakness', '')
            if isinstance(weakness, list):
                weakness = ', '.join(str(w) for w in weakness if w)
            weakness = str(weakness).strip()
            weakness_type = self.categorize_weakness(weakness)
            
            # Check for key field presence (handle lists and strings)
            def has_content(field_value):
                if isinstance(field_value, list):
                    return any(str(item).strip() for item in field_value)
                return bool(str(field_value).strip()) if field_value else False
            
            has_weakness = has_content(weakness)
            has_impact = has_content(keyphrases.get('impact', ''))
            has_vector = has_content(keyphrases.get('vector', ''))
            has_product = has_content(keyphrases.get('product', ''))
            
            return CVEMetadata(
                cve_id=cve_id,
                year=year,
                file_path=str(file_path),
                description_length=description_length,
                keyphrase_count=keyphrase_count,
                weakness_type=weakness_type,
                cwe_ids=cwe_ids,
                cwe_count=cwe_count,
                primary_cwe_id=primary_cwe_id,
                has_weakness=has_weakness,
                has_impact=has_impact,
                has_vector=has_vector,
                has_product=has_product
            )
            
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {e}")
            return None
    
    def categorize_weakness(self, weakness: str) -> str:
        """Categorize weakness into broad types for diversity."""
        if not weakness:
            return "unknown"
            
        weakness_lower = weakness.lower()
        
        # XSS and Injection vulnerabilities
        if any(term in weakness_lower for term in [
            'cross-site scripting', 'xss', 'injection', 'sql injection', 
            'code injection', 'command injection'
        ]):
            return "injection"
        
        # Access Control issues
        if any(term in weakness_lower for term in [
            'access control', 'authorization', 'authentication', 'privilege',
            'permission', 'bypass'
        ]):
            return "access_control"
        
        # Buffer/Memory issues
        if any(term in weakness_lower for term in [
            'buffer overflow', 'buffer underflow', 'out of bounds', 
            'memory corruption', 'heap overflow', 'stack overflow'
        ]):
            return "buffer_overflow"
        
        # Information Disclosure
        if any(term in weakness_lower for term in [
            'information disclosure', 'information leak', 'data exposure',
            'sensitive information'
        ]):
            return "info_disclosure"
        
        # Denial of Service
        if any(term in weakness_lower for term in [
            'denial of service', 'dos', 'crash', 'resource exhaustion'
        ]):
            return "denial_of_service"
        
        # Cryptographic issues
        if any(term in weakness_lower for term in [
            'cryptographic', 'encryption', 'certificate', 'crypto'
        ]):
            return "cryptographic"
        
        return "other"
    
    def scan_cve_files(self, max_workers: int = 8) -> None:
        """Scan all CVE files and build inventory."""
        logger.info(f"Scanning CVE files in {self.cve_directory}")
        
        # Find all JSON files
        json_files = list(self.cve_directory.rglob("*.json"))
        if not json_files:
            raise ValueError(f"No JSON files found in {self.cve_directory}")
        
        logger.info(f"Found {len(json_files)} JSON files to analyze")
        
        processed = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self.analyze_cve_file, file_path): file_path 
                for file_path in json_files
            }
            
            # Process completed tasks
            for future in as_completed(future_to_file):
                metadata = future.result()
                if metadata:
                    self.inventory.append(metadata)
                    self.year_distribution[metadata.year] += 1
                    self.weakness_distribution[metadata.weakness_type] += 1
                    self.cwe_count_distribution[metadata.cwe_count] += 1
                    
                    # Count each CWE ID occurrence
                    for cwe_id in metadata.cwe_ids:
                        self.cwe_distribution[cwe_id] += 1
                
                processed += 1
                if processed % 1000 == 0:
                    logger.info(f"Processed {processed}/{len(json_files)} files")
        
        logger.info(f"Successfully analyzed {len(self.inventory)} CVE files")
        
    def save_inventory(self, output_path: Path) -> None:
        """Save inventory to CSV for analysis."""
        logger.info(f"Saving inventory to {output_path}")
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'cve_id', 'year', 'file_path', 'description_length', 
                'keyphrase_count', 'weakness_type', 'cwe_ids',
                'cwe_count', 'primary_cwe_id',
                'has_weakness', 'has_impact', 'has_vector', 'has_product'
            ])
            
            for metadata in self.inventory:
                writer.writerow([
                    metadata.cve_id, metadata.year, metadata.file_path,
                    metadata.description_length, metadata.keyphrase_count,
                    metadata.weakness_type, 
                    '|'.join(metadata.cwe_ids),  # Join multiple CWEs with |
                    metadata.cwe_count, metadata.primary_cwe_id,
                    metadata.has_weakness, metadata.has_impact, metadata.has_vector, metadata.has_product
                ])

class DiverseSampler:
    """Implements stratified sampling for diverse CVE selection."""
    
    def __init__(self, inventory: List[CVEMetadata]):
        self.inventory = inventory
        self.sample_size = 50000
        
        # Define sampling weights
        self.year_weights = {
            range(1999, 2010): 0.05,  # 2,500 samples
            range(2010, 2016): 0.10,  # 5,000 samples  
            range(2016, 2020): 0.20,  # 10,000 samples
            range(2020, 2025): 0.65   # 32,500 samples
        }
        
        # Define CWE category weights for diversity
        self.cwe_category_weights = {
            "web_application": 0.15,
            "injection": 0.15,
            "access_control": 0.12,
            "memory_corruption": 0.12,
            "information_disclosure": 0.10,
            "denial_of_service": 0.08,
            "cryptographic": 0.06,
            "path_traversal": 0.05,
            "resource_management": 0.05,
            "concurrency": 0.04,
            "other": 0.06,
            "unknown": 0.02
        }
        
        # Define CWE count weights for diversity
        self.cwe_count_weights = {
            "no_cwe": 0.10,
            "single_cwe": 0.60,
            "multiple_cwe": 0.25,
            "many_cwe": 0.05
        }
        
    def get_year_category(self, year: int) -> str:
        """Get year category for a given year."""
        for year_range, _ in self.year_weights.items():
            if year in year_range:
                if year_range.start == 1999:
                    return "1999-2009"
                elif year_range.start == 2010:
                    return "2010-2015"
                elif year_range.start == 2016:
                    return "2016-2019"
                else:
                    return "2020-2024"
        return "other"
    
    def categorize_by_length(self, length: int) -> str:
        """Categorize description by length."""
        if length < 250:
            return "short"
        elif length < 400:
            return "medium"
        else:
            return "long"
    
    def categorize_by_completeness(self, keyphrase_count: int) -> str:
        """Categorize by keyphrase completeness."""
        if keyphrase_count >= 4:
            return "complete"
        elif keyphrase_count >= 2:
            return "partial"
        else:
            return "sparse"
    
    def categorize_by_cwe_count(self, cwe_count: int) -> str:
        """Categorize by CWE count for sampling diversity."""
        if cwe_count == 0:
            return "no_cwe"
        elif cwe_count == 1:
            return "single_cwe"
        elif cwe_count <= 3:
            return "multiple_cwe"
        else:
            return "many_cwe"
    
    def create_diverse_sample(self) -> List[CVEMetadata]:
        """Create a diverse sample using stratified sampling."""
        logger.info(f"Creating diverse sample of {self.sample_size} CVEs")
        
        # Group inventory by year category
        year_groups = defaultdict(list)
        for cve in self.inventory:
            year_cat = self.get_year_category(cve.year)
            year_groups[year_cat].append(cve)
        
        logger.info("Year distribution in inventory:")
        for year_cat, cves in year_groups.items():
            logger.info(f"  {year_cat}: {len(cves)} CVEs")
        
        # Calculate samples per year category
        samples_per_year = {}
        for year_range, weight in self.year_weights.items():
            year_cat = self.get_year_category(year_range.start)
            samples_per_year[year_cat] = int(self.sample_size * weight)
        
        logger.info("Target samples per year category:")
        for year_cat, count in samples_per_year.items():
            logger.info(f"  {year_cat}: {count} samples")
        
        selected_cves = []
        
        # Sample from each year category
        for year_cat, target_count in samples_per_year.items():
            available_cves = year_groups.get(year_cat, [])
            if not available_cves:
                logger.warning(f"No CVEs available for {year_cat}")
                continue
            
            # Apply secondary diversification within year category
            sampled = self.diversify_within_category(available_cves, target_count)
            selected_cves.extend(sampled)
            
            logger.info(f"Selected {len(sampled)} CVEs from {year_cat} "
                       f"(available: {len(available_cves)})")
        
        # Shuffle final selection
        random.shuffle(selected_cves)
        
        logger.info(f"Final diverse sample: {len(selected_cves)} CVEs")
        return selected_cves
    
    def diversify_within_category(self, cves: List[CVEMetadata], 
                                 target_count: int) -> List[CVEMetadata]:
        """Apply secondary diversification within a year category."""
        if len(cves) <= target_count:
            return cves
        
        # Group by length and completeness
        groups = defaultdict(list)
        for cve in cves:
            length_cat = self.categorize_by_length(cve.description_length)
            completeness_cat = self.categorize_by_completeness(cve.keyphrase_count)
            key = f"{length_cat}_{completeness_cat}"
            groups[key].append(cve)
        
        # Target distribution within category  
        length_dist = {"short": 0.3, "medium": 0.5, "long": 0.2}
        completeness_dist = {"complete": 0.6, "partial": 0.3, "sparse": 0.1}
        
        selected = []
        remaining_count = target_count
        
        # Sample proportionally from each group
        for length_cat, length_weight in length_dist.items():
            for comp_cat, comp_weight in completeness_dist.items():
                group_key = f"{length_cat}_{comp_cat}"
                group_cves = groups.get(group_key, [])
                
                if not group_cves:
                    continue
                
                # Calculate target for this group
                group_target = int(target_count * length_weight * comp_weight)
                group_target = min(group_target, len(group_cves), remaining_count)
                
                if group_target > 0:
                    # Further diversify by CWE category and count within group
                    cwe_groups = defaultdict(list)
                    cwe_count_groups = defaultdict(list)
                    
                    for cve in group_cves:
                        cwe_groups[cve.primary_cwe_id].append(cve)
                        cwe_count_cat = self.categorize_by_cwe_count(cve.cwe_count)
                        cwe_count_groups[cwe_count_cat].append(cve)
                    
                    # Split target between CWE category diversity (70%) and CWE count diversity (30%)
                    cwe_category_target = int(group_target * 0.7)
                    cwe_count_target = group_target - cwe_category_target
                    
                    group_selected = []
                    
                    # Sample by CWE category
                    for cwe_category, cwe_cves in cwe_groups.items():
                        cwe_weight = self.cwe_category_weights.get(cwe_category, 0.02)
                        cwe_target = max(1, int(cwe_category_target * cwe_weight))
                        cwe_sample = min(cwe_target, len(cwe_cves))
                        if cwe_sample > 0:
                            group_selected.extend(random.sample(cwe_cves, cwe_sample))
                    
                    # Sample by CWE count (avoiding duplicates)
                    remaining_cves = [cve for cve in group_cves if cve not in group_selected]
                    if remaining_cves and cwe_count_target > 0:
                        remaining_count_groups = defaultdict(list)
                        for cve in remaining_cves:
                            cwe_count_cat = self.categorize_by_cwe_count(cve.cwe_count)
                            remaining_count_groups[cwe_count_cat].append(cve)
                        
                        for cwe_count_cat, count_cves in remaining_count_groups.items():
                            count_weight = self.cwe_count_weights.get(cwe_count_cat, 0.05)
                            count_target = max(1, int(cwe_count_target * count_weight))
                            count_sample = min(count_target, len(count_cves))
                            if count_sample > 0:
                                group_selected.extend(random.sample(count_cves, count_sample))
                    
                    # Fill remaining slots randomly
                    if len(group_selected) < group_target:
                        remaining_cves = [cve for cve in group_cves 
                                        if cve not in group_selected]
                        additional = min(group_target - len(group_selected), 
                                       len(remaining_cves))
                        group_selected.extend(random.sample(remaining_cves, additional))
                    
                    selected.extend(group_selected[:group_target])
                    remaining_count -= len(group_selected[:group_target])
        
        # Fill any remaining slots randomly
        if remaining_count > 0:
            remaining_cves = [cve for cve in cves if cve not in selected]
            if remaining_cves:
                additional = min(remaining_count, len(remaining_cves))
                selected.extend(random.sample(remaining_cves, additional))
        
        return selected

class JSONLGenerator:
    """Generates JSONL training dataset from selected CVEs."""
    
    def __init__(self, selected_cves: List[CVEMetadata]):
        self.selected_cves = selected_cves
        
    def generate_jsonl(self, output_path: Path) -> None:
        """Generate JSONL dataset matching the training format."""
        logger.info(f"Generating JSONL dataset to {output_path}")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for i, metadata in enumerate(self.selected_cves):
                try:
                    # Load the CVE data
                    with open(metadata.file_path, 'r', encoding='utf-8') as cve_file:
                        cve_data = json.load(cve_file)
                    
                    description = cve_data.get('description', '')
                    keyphrases = cve_data.get('keyphrases', {})
                    
                    # Create the training example
                    prompt = f"Extract key phrases from this vulnerability description:\n\n{description}"
                    
                    jsonl_entry = {
                        "contents": [
                            {
                                "role": "user",
                                "parts": [{"text": prompt}]
                            },
                            {
                                "role": "model", 
                                "parts": [{"text": json.dumps(keyphrases, ensure_ascii=False)}]
                            }
                        ]
                    }
                    
                    f.write(json.dumps(jsonl_entry, ensure_ascii=False) + '\n')
                    
                    if (i + 1) % 1000 == 0:
                        logger.info(f"Generated {i + 1}/{len(self.selected_cves)} entries")
                        
                except Exception as e:
                    logger.error(f"Error processing {metadata.cve_id}: {e}")
                    continue
        
        logger.info(f"Successfully generated JSONL dataset with {len(self.selected_cves)} entries")

class QualityValidator:
    """Validates the generated dataset quality and diversity."""
    
    def __init__(self, selected_cves: List[CVEMetadata]):
        self.selected_cves = selected_cves
        
    def generate_report(self, output_path: Path) -> Dict:
        """Generate quality and diversity report."""
        logger.info("Generating quality validation report")
        
        # Calculate distributions
        year_dist = Counter(cve.year for cve in self.selected_cves)
        weakness_dist = Counter(cve.weakness_type for cve in self.selected_cves)
        cwe_category_dist = Counter(cve.primary_cwe_id for cve in self.selected_cves)
        cwe_count_dist = Counter(cve.cwe_count for cve in self.selected_cves)
        
        # Flatten all CWE IDs for distribution
        all_cwe_ids = []
        for cve in self.selected_cves:
            all_cwe_ids.extend(cve.cwe_ids)
        cwe_dist = Counter(all_cwe_ids)
        length_dist = Counter(
            "short" if cve.description_length < 250 
            else "medium" if cve.description_length < 400 
            else "long" 
            for cve in self.selected_cves
        )
        completeness_dist = Counter(
            "complete" if cve.keyphrase_count >= 4
            else "partial" if cve.keyphrase_count >= 2
            else "sparse"
            for cve in self.selected_cves
        )
        
        # Calculate year category distribution
        year_cat_dist = Counter()
        for cve in self.selected_cves:
            if 1999 <= cve.year <= 2009:
                year_cat_dist["1999-2009"] += 1
            elif 2010 <= cve.year <= 2015:
                year_cat_dist["2010-2015"] += 1
            elif 2016 <= cve.year <= 2019:
                year_cat_dist["2016-2019"] += 1
            elif 2020 <= cve.year <= 2024:
                year_cat_dist["2020-2024"] += 1
        
        report = {
            "dataset_size": len(self.selected_cves),
            "year_category_distribution": dict(year_cat_dist),
            "year_distribution": dict(year_dist),
            "weakness_distribution": dict(weakness_dist),
            "cwe_count_distribution": dict(cwe_count_dist),
            "cwe_distribution": dict(cwe_dist),
            "description_length_distribution": dict(length_dist),
            "keyphrase_completeness_distribution": dict(completeness_dist),
            "statistics": {
                "avg_description_length": sum(cve.description_length for cve in self.selected_cves) / len(self.selected_cves),
                "avg_keyphrase_count": sum(cve.keyphrase_count for cve in self.selected_cves) / len(self.selected_cves),
                "avg_cwe_count": sum(cve.cwe_count for cve in self.selected_cves) / len(self.selected_cves),
                "unique_years": len(set(cve.year for cve in self.selected_cves)),
                "unique_weakness_types": len(set(cve.weakness_type for cve in self.selected_cves)),
                "unique_cwe_categories": len(set(cve.primary_cwe_id for cve in self.selected_cves)),
                "unique_cwe_ids": len(set(all_cwe_ids)),
                "total_cwe_instances": len(all_cwe_ids),
                "cves_with_cwe": len([cve for cve in self.selected_cves if cve.cwe_count > 0]),
                "cves_with_multiple_cwe": len([cve for cve in self.selected_cves if cve.cwe_count > 1])
            }
        }
        
        # Save report
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Quality report saved to {output_path}")
        return report

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Create diverse CVE dataset for training')
    parser.add_argument('--cve-dir', type=str, default='../cve_info',
                       help='Path to CVE directory with keyphrases (default: ../cve_info)')
    parser.add_argument('--cwe-dir', type=str, default='../cvelistV5',
                       help='Path to CWE directory (default: ../cvelistV5)')
    parser.add_argument('--output-dir', type=str, default='data_out',
                       help='Output directory for generated files')
    parser.add_argument('--sample-size', type=int, default=50000,
                       help='Number of CVEs to sample')
    parser.add_argument('--max-workers', type=int, default=8,
                       help='Maximum worker threads for file processing')
    parser.add_argument('--seed', type=int, default=42,
                       help='Random seed for reproducible sampling')
    parser.add_argument('--create-all-cves-csv', action='store_true',
                       help='Create CSV with all CVEs and their CWEs before sampling')
    
    args = parser.parse_args()
    
    # Set random seed for reproducibility
    random.seed(args.seed)
    
    # Setup paths
    cve_dir = Path(args.cve_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    logger.info(f"Starting diverse CVE dataset generation")
    logger.info(f"CVE directory (keyphrases): {cve_dir}")
    logger.info(f"CWE directory: {args.cwe_dir}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Target sample size: {args.sample_size}")
    
    start_time = time.time()
    
    try:
        # Phase 1: Analyze CVE dataset
        logger.info("=== Phase 1: CVE Dataset Analysis ===")
        cwe_dir = Path(args.cwe_dir)
        
        analyzer = CVEAnalyzer(cve_dir, cwe_dir)
        
        # Verify CWE directory exists if provided
        if not cwe_dir.exists():
            logger.warning(f"CWE directory not found: {cwe_dir}")
            logger.warning("CWE information will not be available")
            analyzer.cwe_directory = None
        
        # Create all CVEs CSV first if requested
        if args.create_all_cves_csv:
            logger.info("Creating comprehensive CVE-CWE inventory...")
            all_cves_path = output_dir / "all_cves_with_cwe.csv"
            analyzer.scan_cve_files(max_workers=args.max_workers)
            analyzer.save_inventory(all_cves_path)
            logger.info(f"All CVEs inventory saved to: {all_cves_path}")
            logger.info(f"Total CVEs analyzed: {len(analyzer.inventory)}")
            cves_with_cwe = len([cve for cve in analyzer.inventory if cve.cwe_count > 0])
            logger.info(f"CVEs with CWE: {cves_with_cwe} ({cves_with_cwe/len(analyzer.inventory)*100:.1f}%)")
            logger.info(f"Top CWE IDs: {dict(analyzer.cwe_distribution.most_common(10))}")
            logger.info(f"CWE count distribution: {dict(analyzer.cwe_count_distribution.most_common())}")
            return
        
        analyzer.scan_cve_files(max_workers=args.max_workers)
        
        inventory_path = output_dir / "cve_inventory.csv"
        analyzer.save_inventory(inventory_path)
        
        # Phase 2: Create diverse sample
        logger.info("=== Phase 2: Diverse Sampling ===")
        sampler = DiverseSampler(analyzer.inventory)
        sampler.sample_size = args.sample_size
        selected_cves = sampler.create_diverse_sample()
        
        # Phase 3: Generate JSONL dataset
        logger.info("=== Phase 3: JSONL Generation ===")
        generator = JSONLGenerator(selected_cves)
        jsonl_path = output_dir / "cve_50k_diverse_sample.jsonl"
        generator.generate_jsonl(jsonl_path)
        
        # Phase 4: Quality validation
        logger.info("=== Phase 4: Quality Validation ===")
        validator = QualityValidator(selected_cves)
        report_path = output_dir / "sampling_metadata.json"
        report = validator.generate_report(report_path)
        
        # Summary
        elapsed_time = time.time() - start_time
        logger.info("=== Generation Complete ===")
        logger.info(f"Total time: {elapsed_time:.2f} seconds")
        logger.info(f"Generated dataset: {jsonl_path}")
        logger.info(f"Sample size: {report['dataset_size']}")
        logger.info(f"Year categories: {report['year_category_distribution']}")
        logger.info(f"Weakness types: {len(report['weakness_distribution'])}")
        logger.info(f"Unique CWE IDs: {report['statistics']['unique_cwe_ids']}")
        logger.info(f"CVEs with CWE: {report['statistics']['cves_with_cwe']}")
        logger.info(f"CVEs with multiple CWEs: {report['statistics']['cves_with_multiple_cwe']}")
        logger.info(f"Average CWE count: {report['statistics']['avg_cwe_count']:.2f}")
        
        # Create summary report
        summary_path = output_dir / "generation_summary.md"
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(f"# Diverse CVE Dataset Generation Summary\n\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Processing time: {elapsed_time:.2f} seconds\n")
            f.write(f"Source directory: {cve_dir}\n")
            f.write(f"Total CVEs analyzed: {len(analyzer.inventory)}\n")
            f.write(f"Selected sample size: {report['dataset_size']}\n\n")
            f.write(f"## Year Distribution\n")
            for year_cat, count in report['year_category_distribution'].items():
                percentage = (count / report['dataset_size']) * 100
                f.write(f"- {year_cat}: {count} ({percentage:.1f}%)\n")
            f.write(f"\n## Weakness Type Distribution\n")
            for weakness, count in sorted(report['weakness_distribution'].items(), 
                                        key=lambda x: x[1], reverse=True):
                percentage = (count / report['dataset_size']) * 100
                f.write(f"- {weakness}: {count} ({percentage:.1f}%)\n")
            f.write(f"\n## CWE Count Distribution\n")
            for cwe_count, count in sorted(report['cwe_count_distribution'].items()):
                percentage = (count / report['dataset_size']) * 100
                f.write(f"- {cwe_count} CWE(s): {count} ({percentage:.1f}%)\n")
            f.write(f"\n## Top CWE IDs\n")
            for cwe_id, count in sorted(report['cwe_distribution'].items(), 
                                      key=lambda x: x[1], reverse=True)[:20]:
                percentage = (count / report['statistics']['total_cwe_instances']) * 100
                f.write(f"- {cwe_id}: {count} ({percentage:.1f}% of all CWE instances)\n")
        
        logger.info(f"Summary report: {summary_path}")
        logger.info("Dataset generation completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during dataset generation: {e}")
        raise

if __name__ == "__main__":
    main()