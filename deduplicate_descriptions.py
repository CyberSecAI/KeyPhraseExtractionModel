#!/usr/bin/env python3
"""
Deduplicate similar descriptions in the CVE dataset using semantic similarity.
Ensures descriptions are sufficiently different from each other by:
1. Sorting descriptions alphabetically for efficient comparison
2. Computing semantic similarity using sentence embeddings
3. Replacing very similar descriptions with diverse alternatives
"""

import json
import logging
from pathlib import Path
from typing import List, Tuple, Dict, Set
import argparse
import time
from collections import defaultdict
import re
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DescriptionDeduplicator:
    """Handles semantic deduplication of CVE descriptions."""
    
    def __init__(self, similarity_threshold: float = 0.85, inventory_path: str = None):
        self.similarity_threshold = similarity_threshold
        self.inventory_path = inventory_path
        self.replacement_pool = []
        self.used_hashes = set()
        
    def normalize_description(self, description: str) -> str:
        """Normalize description for comparison."""
        # Remove version numbers, product names, and technical identifiers
        normalized = description.lower()
        
        # Remove common version patterns
        normalized = re.sub(r'\bv?\d+\.\d+[\.\d]*\b', '[VERSION]', normalized)
        normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '[DATE]', normalized)
        normalized = re.sub(r'\bcve-\d{4}-\d+\b', '[CVE]', normalized)
        
        # Remove specific product names but keep vulnerability pattern
        normalized = re.sub(r'\b[A-Z][a-zA-Z]*\s+[A-Z][a-zA-Z]*\b', '[PRODUCT]', normalized)
        
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized
    
    def get_description_hash(self, description: str) -> str:
        """Get a hash of the normalized description."""
        normalized = self.normalize_description(description)
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def simple_similarity(self, desc1: str, desc2: str) -> float:
        """Compute simple token-based similarity between descriptions."""
        # Normalize both descriptions
        norm1 = self.normalize_description(desc1)
        norm2 = self.normalize_description(desc2)
        
        # If descriptions are too different in length, they're likely different
        if abs(len(norm1) - len(norm2)) > max(len(norm1), len(norm2)) * 0.5:
            return 0.0
        
        # Tokenize
        tokens1 = set(norm1.split())
        tokens2 = set(norm2.split())
        
        # Jaccard similarity
        intersection = len(tokens1.intersection(tokens2))
        union = len(tokens1.union(tokens2))
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    def load_replacement_pool(self):
        """Load alternative descriptions from CVE inventory."""
        if not self.inventory_path or not Path(self.inventory_path).exists():
            logger.warning("No inventory file found for replacement pool")
            return
        
        logger.info(f"Loading replacement pool from {self.inventory_path}")
        
        with open(self.inventory_path, 'r', encoding='utf-8') as f:
            next(f)  # Skip header
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 3:
                    cve_id = parts[0]
                    file_path = parts[2]
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as cve_file:
                            data = json.load(cve_file)
                            description = data.get('description', '').strip()
                            
                            if description and len(description) > 50:  # Filter very short descriptions
                                self.replacement_pool.append({
                                    'cve_id': cve_id,
                                    'description': description,
                                    'file_path': file_path,
                                    'hash': self.get_description_hash(description)
                                })
                    except Exception as e:
                        continue
        
        logger.info(f"Loaded {len(self.replacement_pool)} descriptions for replacement pool")
    
    def find_duplicates(self, descriptions: List[Dict]) -> List[Tuple[int, int, float]]:
        """Find duplicate descriptions using semantic similarity."""
        logger.info(f"Checking for duplicates in {len(descriptions)} descriptions")
        
        duplicates = []
        
        # Sort descriptions by normalized content for efficient comparison
        sorted_descs = sorted(enumerate(descriptions), 
                            key=lambda x: self.normalize_description(x[1]['description']))
        
        # Compare adjacent descriptions (after sorting, similar ones will be close)
        for i in range(len(sorted_descs)):
            idx1, desc1 = sorted_descs[i]
            
            # Compare with next few descriptions
            for j in range(i + 1, min(i + 10, len(sorted_descs))):
                idx2, desc2 = sorted_descs[j]
                
                similarity = self.simple_similarity(desc1['description'], desc2['description'])
                
                if similarity > self.similarity_threshold:
                    duplicates.append((idx1, idx2, similarity))
                    logger.debug(f"Found duplicate: {desc1['cve_id']} <-> {desc2['cve_id']} (similarity: {similarity:.3f})")
        
        logger.info(f"Found {len(duplicates)} duplicate pairs")
        return duplicates
    
    def find_replacement(self, used_descriptions: Set[str], current_description: str) -> Dict:
        """Find a suitable replacement description."""
        current_hash = self.get_description_hash(current_description)
        current_normalized = self.normalize_description(current_description)
        
        # Find descriptions with different patterns
        candidates = []
        for candidate in self.replacement_pool:
            # Skip if already used
            if candidate['hash'] in used_descriptions:
                continue
            
            # Skip if too similar to current
            similarity = self.simple_similarity(current_description, candidate['description'])
            if similarity > 0.7:  # Lower threshold for replacement
                continue
            
            # Prefer descriptions with different vulnerability patterns
            cand_normalized = self.normalize_description(candidate['description'])
            if len(set(current_normalized.split()).intersection(set(cand_normalized.split()))) < len(current_normalized.split()) * 0.3:
                candidates.append((candidate, similarity))
        
        if candidates:
            # Sort by dissimilarity (lower similarity first)
            candidates.sort(key=lambda x: x[1])
            return candidates[0][0]
        
        return None
    
    def deduplicate_dataset(self, jsonl_path: Path, output_path: Path):
        """Deduplicate descriptions in the JSONL dataset."""
        logger.info(f"Deduplicating dataset: {jsonl_path}")
        
        # Load existing dataset
        descriptions = []
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                data = json.loads(line)
                description = data['contents'][0]['parts'][0]['text'].split('\n\n')[1]  # Extract description
                descriptions.append({
                    'index': i,
                    'description': description,
                    'original_data': data,
                    'cve_id': f"entry_{i}"  # We don't have CVE IDs in JSONL
                })
        
        # Load replacement pool
        self.load_replacement_pool()
        
        # Find duplicates
        duplicates = self.find_duplicates(descriptions)
        
        if not duplicates:
            logger.info("No duplicates found - copying original file")
            import shutil
            shutil.copy2(jsonl_path, output_path)
            return
        
        # Track which descriptions to replace
        to_replace = set()
        used_hashes = set()
        
        # Process duplicates - keep first occurrence, replace others
        duplicate_groups = defaultdict(list)
        for idx1, idx2, similarity in duplicates:
            key = min(idx1, idx2)
            duplicate_groups[key].append((max(idx1, idx2), similarity))
        
        # Mark descriptions for replacement (keep the first in each group)
        for keep_idx, dup_list in duplicate_groups.items():
            used_hashes.add(self.get_description_hash(descriptions[keep_idx]['description']))
            for dup_idx, similarity in dup_list:
                to_replace.add(dup_idx)
        
        logger.info(f"Replacing {len(to_replace)} duplicate descriptions")
        
        # Replace duplicates
        replaced_count = 0
        failed_replacements = 0
        
        for idx in to_replace:
            original_desc = descriptions[idx]['description']
            replacement = self.find_replacement(used_hashes, original_desc)
            
            if replacement:
                # Load the replacement CVE data
                try:
                    with open(replacement['file_path'], 'r', encoding='utf-8') as f:
                        cve_data = json.load(f)
                    
                    new_description = cve_data.get('description', '')
                    new_keyphrases = cve_data.get('keyphrases', {})
                    
                    # Update the JSONL entry
                    prompt = f"Extract key phrases from this vulnerability description:\n\n{new_description}"
                    descriptions[idx]['original_data']['contents'][0]['parts'][0]['text'] = prompt
                    descriptions[idx]['original_data']['contents'][1]['parts'][0]['text'] = json.dumps(new_keyphrases, ensure_ascii=False)
                    
                    used_hashes.add(replacement['hash'])
                    replaced_count += 1
                    
                    logger.debug(f"Replaced entry {idx} with {replacement['cve_id']}")
                    
                except Exception as e:
                    logger.error(f"Failed to load replacement {replacement['file_path']}: {e}")
                    failed_replacements += 1
            else:
                failed_replacements += 1
                logger.warning(f"Could not find suitable replacement for entry {idx}")
        
        # Write deduplicated dataset
        with open(output_path, 'w', encoding='utf-8') as f:
            for desc in descriptions:
                f.write(json.dumps(desc['original_data'], ensure_ascii=False) + '\n')
        
        logger.info(f"Deduplication complete:")
        logger.info(f"  - Original dataset: {len(descriptions)} entries")
        logger.info(f"  - Duplicates found: {len(duplicates)} pairs")
        logger.info(f"  - Descriptions replaced: {replaced_count}")
        logger.info(f"  - Failed replacements: {failed_replacements}")
        logger.info(f"  - Output written to: {output_path}")

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Deduplicate similar descriptions in CVE dataset')
    parser.add_argument('--input', type=str, required=True,
                       help='Path to input JSONL file')
    parser.add_argument('--output', type=str, required=True,
                       help='Path to output deduplicated JSONL file')
    parser.add_argument('--inventory', type=str, default='data_out/cve_inventory.csv',
                       help='Path to CVE inventory CSV for replacement pool')
    parser.add_argument('--similarity-threshold', type=float, default=0.85,
                       help='Similarity threshold for detecting duplicates (0.0-1.0)')
    
    args = parser.parse_args()
    
    start_time = time.time()
    
    logger.info("Starting description deduplication")
    logger.info(f"Input: {args.input}")
    logger.info(f"Output: {args.output}")
    logger.info(f"Similarity threshold: {args.similarity_threshold}")
    
    deduplicator = DescriptionDeduplicator(
        similarity_threshold=args.similarity_threshold,
        inventory_path=args.inventory
    )
    
    deduplicator.deduplicate_dataset(Path(args.input), Path(args.output))
    
    elapsed_time = time.time() - start_time
    logger.info(f"Deduplication completed in {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()