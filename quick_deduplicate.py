#!/usr/bin/env python3
"""
Quick deduplication using hash-based exact matching and simple pattern matching.
Faster alternative for large datasets.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Set
import argparse
import time
import hashlib
import re
import random

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QuickDeduplicator:
    """Fast hash-based deduplication."""
    
    def __init__(self, inventory_path: str = None):
        self.inventory_path = inventory_path
        self.replacement_pool = []
        
    def normalize_for_hash(self, description: str) -> str:
        """Normalize description for exact duplicate detection."""
        # Remove extra whitespace and convert to lowercase
        normalized = re.sub(r'\s+', ' ', description.lower().strip())
        
        # Remove common variable parts that don't affect the vulnerability pattern
        normalized = re.sub(r'\bv?\d+\.\d+[\.\d]*\b', 'VERSION', normalized)
        normalized = re.sub(r'\bcve-\d{4}-\d+\b', 'CVEID', normalized)
        normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', 'DATE', normalized)
        
        return normalized
    
    def get_content_hash(self, description: str) -> str:
        """Get hash of normalized content."""
        normalized = self.normalize_for_hash(description)
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def get_pattern_signature(self, description: str) -> str:
        """Get a signature based on vulnerability patterns."""
        desc_lower = description.lower()
        
        # Key vulnerability patterns
        patterns = []
        
        if any(term in desc_lower for term in ['xss', 'cross-site scripting', 'script injection']):
            patterns.append('XSS')
        if any(term in desc_lower for term in ['sql injection', 'sqli']):
            patterns.append('SQLI')
        if any(term in desc_lower for term in ['buffer overflow', 'buffer overrun']):
            patterns.append('BUFFER')
        if any(term in desc_lower for term in ['privilege escalation', 'escalation of privilege']):
            patterns.append('PRIVESC')
        if any(term in desc_lower for term in ['denial of service', 'dos']):
            patterns.append('DOS')
        if any(term in desc_lower for term in ['information disclosure', 'information leak']):
            patterns.append('INFODIS')
        if any(term in desc_lower for term in ['authentication bypass', 'auth bypass']):
            patterns.append('AUTHBYPASS')
        if any(term in desc_lower for term in ['directory traversal', 'path traversal']):
            patterns.append('PATHTRAVERSAL')
        
        # Estimate description length category
        if len(description) < 200:
            patterns.append('SHORT')
        elif len(description) < 400:
            patterns.append('MEDIUM')
        else:
            patterns.append('LONG')
            
        return '_'.join(sorted(patterns)) if patterns else 'OTHER'
    
    def load_replacement_pool(self):
        """Load alternative descriptions."""
        if not self.inventory_path or not Path(self.inventory_path).exists():
            logger.warning("No inventory file found")
            return
        
        logger.info("Loading replacement pool...")
        
        # Sample from inventory to create replacement pool
        with open(self.inventory_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()[1:]  # Skip header
            
        # Sample 10K random lines for replacement pool
        sample_lines = random.sample(lines, min(10000, len(lines)))
        
        for line in sample_lines:
            parts = line.strip().split(',')
            if len(parts) >= 3:
                cve_id = parts[0]
                file_path = parts[2]
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as cve_file:
                        data = json.load(cve_file)
                        description = data.get('description', '').strip()
                        
                        if description and len(description) > 50:
                            self.replacement_pool.append({
                                'cve_id': cve_id,
                                'description': description,
                                'file_path': file_path,
                                'hash': self.get_content_hash(description),
                                'pattern': self.get_pattern_signature(description)
                            })
                except:
                    continue
        
        logger.info(f"Loaded {len(self.replacement_pool)} replacement descriptions")
    
    def find_duplicates_fast(self, descriptions: List[Dict]) -> Dict[str, List[int]]:
        """Find exact and near-exact duplicates using hashes."""
        logger.info("Finding duplicates using hash matching...")
        
        hash_groups = {}
        pattern_groups = {}
        
        for i, desc in enumerate(descriptions):
            content_hash = self.get_content_hash(desc['description'])
            pattern_sig = self.get_pattern_signature(desc['description'])
            
            # Group by exact content hash
            if content_hash not in hash_groups:
                hash_groups[content_hash] = []
            hash_groups[content_hash].append(i)
            
            # Also group by pattern for near-duplicates
            if pattern_sig not in pattern_groups:
                pattern_groups[pattern_sig] = []
            pattern_groups[pattern_sig].append(i)
        
        # Find groups with duplicates
        duplicate_groups = {}
        
        # Exact duplicates
        for content_hash, indices in hash_groups.items():
            if len(indices) > 1:
                duplicate_groups[f"exact_{content_hash}"] = indices
        
        # Pattern-based near duplicates (only for groups with many similar entries)
        for pattern_sig, indices in pattern_groups.items():
            if len(indices) > 20:  # Only check groups with many similar descriptions
                # Sub-group by first 100 characters
                subgroups = {}
                for idx in indices:
                    prefix = descriptions[idx]['description'][:100].lower()
                    prefix_hash = hashlib.md5(prefix.encode()).hexdigest()[:8]
                    
                    if prefix_hash not in subgroups:
                        subgroups[prefix_hash] = []
                    subgroups[prefix_hash].append(idx)
                
                # Add subgroups with duplicates
                for prefix_hash, sub_indices in subgroups.items():
                    if len(sub_indices) > 1:
                        duplicate_groups[f"pattern_{pattern_sig}_{prefix_hash}"] = sub_indices
        
        return duplicate_groups
    
    def find_replacement(self, used_hashes: Set[str], original_desc: str, original_pattern: str) -> Dict:
        """Find suitable replacement with different pattern."""
        # Prefer replacements with different vulnerability patterns
        candidates = [
            r for r in self.replacement_pool 
            if r['hash'] not in used_hashes and r['pattern'] != original_pattern
        ]
        
        if not candidates:
            # Fallback to any unused replacement
            candidates = [r for r in self.replacement_pool if r['hash'] not in used_hashes]
        
        return random.choice(candidates) if candidates else None
    
    def deduplicate_quick(self, jsonl_path: Path, output_path: Path):
        """Quick deduplication process."""
        logger.info(f"Quick deduplication: {jsonl_path}")
        
        # Load dataset
        descriptions = []
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                data = json.loads(line)
                description = data['contents'][0]['parts'][0]['text'].split('\n\n')[1]
                descriptions.append({
                    'index': i,
                    'description': description,
                    'original_data': data,
                    'pattern': self.get_pattern_signature(description)
                })
        
        # Load replacements
        self.load_replacement_pool()
        
        # Find duplicates
        duplicate_groups = self.find_duplicates_fast(descriptions)
        
        logger.info(f"Found {len(duplicate_groups)} duplicate groups")
        
        # Determine replacements
        to_replace = set()
        used_hashes = set()
        
        for group_name, indices in duplicate_groups.items():
            if len(indices) > 1:
                # Keep first, replace others
                keep_idx = indices[0]
                used_hashes.add(self.get_content_hash(descriptions[keep_idx]['description']))
                
                for replace_idx in indices[1:]:
                    to_replace.add(replace_idx)
        
        logger.info(f"Replacing {len(to_replace)} descriptions")
        
        # Perform replacements
        replaced_count = 0
        for idx in to_replace:
            original_desc = descriptions[idx]['description']
            original_pattern = descriptions[idx]['pattern']
            
            replacement = self.find_replacement(used_hashes, original_desc, original_pattern)
            
            if replacement:
                try:
                    # Load replacement CVE data
                    with open(replacement['file_path'], 'r', encoding='utf-8') as f:
                        cve_data = json.load(f)
                    
                    new_description = cve_data.get('description', '')
                    new_keyphrases = cve_data.get('keyphrases', {})
                    
                    # Update JSONL entry
                    prompt = f"Extract key phrases from this vulnerability description:\n\n{new_description}"
                    descriptions[idx]['original_data']['contents'][0]['parts'][0]['text'] = prompt
                    descriptions[idx]['original_data']['contents'][1]['parts'][0]['text'] = json.dumps(new_keyphrases, ensure_ascii=False)
                    
                    used_hashes.add(replacement['hash'])
                    replaced_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to replace {idx}: {e}")
        
        # Write output
        with open(output_path, 'w', encoding='utf-8') as f:
            for desc in descriptions:
                f.write(json.dumps(desc['original_data'], ensure_ascii=False) + '\n')
        
        logger.info(f"Deduplication complete: {replaced_count} descriptions replaced")

def main():
    parser = argparse.ArgumentParser(description='Quick deduplication of CVE descriptions')
    parser.add_argument('--input', type=str, required=True, help='Input JSONL file')
    parser.add_argument('--output', type=str, required=True, help='Output JSONL file')
    parser.add_argument('--inventory', type=str, default='data_out/cve_inventory.csv', help='CVE inventory file')
    
    args = parser.parse_args()
    
    start_time = time.time()
    
    deduplicator = QuickDeduplicator(inventory_path=args.inventory)
    deduplicator.deduplicate_quick(Path(args.input), Path(args.output))
    
    elapsed_time = time.time() - start_time
    logger.info(f"Quick deduplication completed in {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()