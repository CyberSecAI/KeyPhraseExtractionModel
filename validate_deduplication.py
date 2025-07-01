#!/usr/bin/env python3
"""
Validate the quality of deduplication by analyzing description diversity.
"""

import json
import re
import hashlib
from collections import Counter, defaultdict
from pathlib import Path
import argparse

def normalize_description(description: str) -> str:
    """Normalize description for comparison."""
    normalized = description.lower()
    normalized = re.sub(r'\bv?\d+\.\d+[\.\d]*\b', '[VERSION]', normalized)
    normalized = re.sub(r'\bcve-\d{4}-\d+\b', '[CVE]', normalized)
    normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '[DATE]', normalized)
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return normalized

def get_description_patterns(description: str) -> list:
    """Extract vulnerability patterns from description."""
    desc_lower = description.lower()
    patterns = []
    
    pattern_map = {
        'XSS': ['xss', 'cross-site scripting', 'script injection'],
        'SQL_INJECTION': ['sql injection', 'sqli'],
        'BUFFER_OVERFLOW': ['buffer overflow', 'buffer overrun', 'out of bounds'],
        'PRIVILEGE_ESCALATION': ['privilege escalation', 'escalation of privilege'],
        'DENIAL_OF_SERVICE': ['denial of service', 'dos'],
        'INFO_DISCLOSURE': ['information disclosure', 'information leak'],
        'AUTH_BYPASS': ['authentication bypass', 'auth bypass'],
        'PATH_TRAVERSAL': ['directory traversal', 'path traversal'],
        'INJECTION': ['injection', 'code injection', 'command injection'],
        'ACCESS_CONTROL': ['access control', 'authorization'],
        'CRYPTOGRAPHIC': ['encryption', 'cryptographic', 'certificate'],
    }
    
    for pattern_name, keywords in pattern_map.items():
        if any(keyword in desc_lower for keyword in keywords):
            patterns.append(pattern_name)
    
    return patterns

def analyze_dataset(jsonl_path: Path) -> dict:
    """Analyze diversity and patterns in the dataset."""
    descriptions = []
    
    # Load descriptions
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            description = data['contents'][0]['parts'][0]['text'].split('\n\n')[1]
            descriptions.append(description)
    
    # Analyze diversity
    analysis = {
        'total_descriptions': len(descriptions),
        'unique_normalized': len(set(normalize_description(d) for d in descriptions)),
        'unique_hashes': len(set(hashlib.md5(normalize_description(d).encode()).hexdigest() for d in descriptions)),
        'length_distribution': Counter(),
        'pattern_distribution': Counter(),
        'duplicate_examples': []
    }
    
    # Length analysis
    for desc in descriptions:
        if len(desc) < 200:
            analysis['length_distribution']['short'] += 1
        elif len(desc) < 400:
            analysis['length_distribution']['medium'] += 1
        else:
            analysis['length_distribution']['long'] += 1
    
    # Pattern analysis
    all_patterns = []
    for desc in descriptions:
        patterns = get_description_patterns(desc)
        if patterns:
            all_patterns.extend(patterns)
        else:
            all_patterns.append('OTHER')
    
    analysis['pattern_distribution'] = Counter(all_patterns)
    
    # Find remaining duplicates
    hash_groups = defaultdict(list)
    for i, desc in enumerate(descriptions):
        desc_hash = hashlib.md5(normalize_description(desc).encode()).hexdigest()
        hash_groups[desc_hash].append((i, desc[:100] + '...'))
    
    duplicates = {h: indices for h, indices in hash_groups.items() if len(indices) > 1}
    analysis['remaining_duplicates'] = len(duplicates)
    analysis['duplicate_examples'] = list(duplicates.values())[:5]  # First 5 examples
    
    return analysis

def main():
    parser = argparse.ArgumentParser(description='Validate deduplication quality')
    parser.add_argument('--original', type=str, required=True, help='Original JSONL file')
    parser.add_argument('--deduplicated', type=str, required=True, help='Deduplicated JSONL file')
    
    args = parser.parse_args()
    
    print("=== DEDUPLICATION VALIDATION REPORT ===\n")
    
    # Analyze original dataset
    print("Original Dataset Analysis:")
    original_analysis = analyze_dataset(Path(args.original))
    
    print(f"  Total descriptions: {original_analysis['total_descriptions']}")
    print(f"  Unique normalized: {original_analysis['unique_normalized']}")
    print(f"  Unique hashes: {original_analysis['unique_hashes']}")
    print(f"  Remaining duplicates: {original_analysis['remaining_duplicates']}")
    print(f"  Diversity ratio: {original_analysis['unique_hashes'] / original_analysis['total_descriptions']:.3f}")
    
    print("\n  Length distribution:")
    for length_cat, count in original_analysis['length_distribution'].items():
        pct = (count / original_analysis['total_descriptions']) * 100
        print(f"    {length_cat}: {count} ({pct:.1f}%)")
    
    print("\n  Vulnerability patterns:")
    for pattern, count in original_analysis['pattern_distribution'].most_common(10):
        print(f"    {pattern}: {count}")
    
    # Analyze deduplicated dataset
    print("\n" + "="*50)
    print("Deduplicated Dataset Analysis:")
    dedup_analysis = analyze_dataset(Path(args.deduplicated))
    
    print(f"  Total descriptions: {dedup_analysis['total_descriptions']}")
    print(f"  Unique normalized: {dedup_analysis['unique_normalized']}")
    print(f"  Unique hashes: {dedup_analysis['unique_hashes']}")
    print(f"  Remaining duplicates: {dedup_analysis['remaining_duplicates']}")
    print(f"  Diversity ratio: {dedup_analysis['unique_hashes'] / dedup_analysis['total_descriptions']:.3f}")
    
    print("\n  Length distribution:")
    for length_cat, count in dedup_analysis['length_distribution'].items():
        pct = (count / dedup_analysis['total_descriptions']) * 100
        print(f"    {length_cat}: {count} ({pct:.1f}%)")
    
    print("\n  Vulnerability patterns:")
    for pattern, count in dedup_analysis['pattern_distribution'].most_common(10):
        print(f"    {pattern}: {count}")
    
    # Summary comparison
    print("\n" + "="*50)
    print("IMPROVEMENT SUMMARY:")
    
    original_diversity = original_analysis['unique_hashes'] / original_analysis['total_descriptions']
    dedup_diversity = dedup_analysis['unique_hashes'] / dedup_analysis['total_descriptions']
    
    print(f"  Diversity improvement: {original_diversity:.3f} → {dedup_diversity:.3f}")
    print(f"  Duplicates reduced: {original_analysis['remaining_duplicates']} → {dedup_analysis['remaining_duplicates']}")
    print(f"  Descriptions replaced: {original_analysis['total_descriptions'] - dedup_analysis['unique_hashes']}")
    
    if dedup_analysis['remaining_duplicates'] > 0:
        print(f"\n  Note: {dedup_analysis['remaining_duplicates']} duplicate groups still remain")
        print("  This is expected for very common vulnerability patterns")

if __name__ == "__main__":
    main()