#!/usr/bin/env python3
"""
Unit tests for the diverse CVE dataset generator.
Tests data source reading, CWE extraction, and script functionality.
"""

import unittest
import tempfile
import shutil
import json
import csv
from pathlib import Path
import sys
import os

# Add the parent directory to sys.path to import the main module
sys.path.insert(0, str(Path(__file__).parent.parent))

from create_diverse_cve_dataset import CVEAnalyzer, CVEMetadata, DiverseSampler


class TestCVEDataSources(unittest.TestCase):
    """Test reading from both cve_info and cvelistV5 data sources."""
    
    def setUp(self):
        """Set up test data directories."""
        self.test_dir = Path(__file__).parent / "test_data"
        self.cve_info_dir = self.test_dir / "cve_info"
        self.cwe_dir = self.test_dir / "cvelistV5"
        
    def test_cve_info_directory_exists(self):
        """Test that cve_info test directory exists."""
        self.assertTrue(self.cve_info_dir.exists())
        self.assertTrue((self.cve_info_dir / "2024" / "0xxx").exists())
        
    def test_cvelistv5_directory_exists(self):
        """Test that cvelistV5 test directory exists."""
        self.assertTrue(self.cwe_dir.exists())
        self.assertTrue((self.cwe_dir / "cves" / "2024" / "0xxx").exists())
        
    def test_cve_analyzer_initialization(self):
        """Test CVEAnalyzer initialization with both directories."""
        analyzer = CVEAnalyzer(self.cve_info_dir, self.cwe_dir)
        self.assertEqual(analyzer.cve_directory, self.cve_info_dir)
        self.assertEqual(analyzer.cwe_directory, self.cwe_dir)
        
    def test_cve_analyzer_without_cwe_dir(self):
        """Test CVEAnalyzer initialization without CWE directory."""
        analyzer = CVEAnalyzer(self.cve_info_dir)
        self.assertEqual(analyzer.cve_directory, self.cve_info_dir)
        self.assertIsNone(analyzer.cwe_directory)


class TestCWEExtraction(unittest.TestCase):
    """Test CWE extraction from various JSON formats."""
    
    def setUp(self):
        """Set up test analyzer."""
        self.test_dir = Path(__file__).parent / "test_data"
        self.cve_info_dir = self.test_dir / "cve_info"
        self.cwe_dir = self.test_dir / "cvelistV5"
        self.analyzer = CVEAnalyzer(self.cve_info_dir, self.cwe_dir)
        
    def test_extract_single_cwe(self):
        """Test extracting single CWE from CVE-2024-0001."""
        cwe_ids, cwe_count, primary_cwe = self.analyzer.extract_cwes_from_cve_id("CVE-2024-0001")
        self.assertEqual(cwe_ids, ["CWE-79"])
        self.assertEqual(cwe_count, 1)
        self.assertEqual(primary_cwe, "CWE-79")
        
    def test_extract_multiple_cwes(self):
        """Test extracting multiple CWEs from CVE-2025-3121."""
        cwe_ids, cwe_count, primary_cwe = self.analyzer.extract_cwes_from_cve_id("CVE-2025-3121")
        self.assertEqual(set(cwe_ids), {"CWE-119", "CWE-787"})
        self.assertEqual(cwe_count, 2)
        self.assertEqual(primary_cwe, "CWE-119")  # First CWE becomes primary
        
    def test_extract_no_cwe(self):
        """Test extracting CWE from file without CWE info."""
        cwe_ids, cwe_count, primary_cwe = self.analyzer.extract_cwes_from_cve_id("CVE-2024-0002")
        self.assertEqual(cwe_ids, [])
        self.assertEqual(cwe_count, 0)
        self.assertEqual(primary_cwe, "")
        
    def test_extract_nonexistent_cve(self):
        """Test extracting CWE from non-existent CVE."""
        cwe_ids, cwe_count, primary_cwe = self.analyzer.extract_cwes_from_cve_id("CVE-9999-9999")
        self.assertEqual(cwe_ids, [])
        self.assertEqual(cwe_count, 0)
        self.assertEqual(primary_cwe, "")


class TestCVEFileAnalysis(unittest.TestCase):
    """Test analysis of individual CVE files."""
    
    def setUp(self):
        """Set up test analyzer."""
        self.test_dir = Path(__file__).parent / "test_data"
        self.cve_info_dir = self.test_dir / "cve_info"
        self.cwe_dir = self.test_dir / "cvelistV5"
        self.analyzer = CVEAnalyzer(self.cve_info_dir, self.cwe_dir)
        
    def test_analyze_complete_cve_file(self):
        """Test analyzing CVE file with complete keyphrases."""
        cve_file = self.cve_info_dir / "2024" / "0xxx" / "CVE-2024-0001.json"
        metadata = self.analyzer.analyze_cve_file(cve_file)
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.cve_id, "CVE-2024-0001")
        self.assertEqual(metadata.year, 2024)
        self.assertEqual(metadata.cwe_ids, ["CWE-79"])
        self.assertEqual(metadata.cwe_count, 1)
        self.assertEqual(metadata.primary_cwe_id, "CWE-79")
        self.assertTrue(metadata.has_weakness)
        self.assertTrue(metadata.has_impact)
        self.assertTrue(metadata.has_vector)
        self.assertTrue(metadata.has_product)
        
    def test_analyze_sparse_cve_file(self):
        """Test analyzing CVE file with sparse keyphrases."""
        cve_file = self.cve_info_dir / "2024" / "0xxx" / "CVE-2024-0002.json"
        metadata = self.analyzer.analyze_cve_file(cve_file)
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.cve_id, "CVE-2024-0002")
        self.assertEqual(metadata.year, 2024)
        self.assertEqual(metadata.cwe_ids, [])  # No CWE in test file
        self.assertEqual(metadata.cwe_count, 0)
        self.assertTrue(metadata.has_weakness)
        self.assertTrue(metadata.has_impact)
        self.assertFalse(metadata.has_product)  # Empty product field
        
    def test_analyze_list_keyphrases(self):
        """Test analyzing CVE file with list-based keyphrases."""
        cve_file = self.cve_info_dir / "2024" / "0xxx" / "CVE-2024-0003.json"
        metadata = self.analyzer.analyze_cve_file(cve_file)
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.cve_id, "CVE-2024-0003")
        self.assertTrue(metadata.has_weakness)  # List with content
        self.assertTrue(metadata.has_vector)    # List with content
        self.assertTrue(metadata.keyphrase_count > 5)  # Multiple filled keyphrases


class TestFileScanning(unittest.TestCase):
    """Test file scanning and inventory building."""
    
    def setUp(self):
        """Set up test analyzer."""
        self.test_dir = Path(__file__).parent / "test_data"
        self.cve_info_dir = self.test_dir / "cve_info"
        self.cwe_dir = self.test_dir / "cvelistV5"
        self.analyzer = CVEAnalyzer(self.cve_info_dir, self.cwe_dir)
        
    def test_scan_test_files(self):
        """Test scanning all test CVE files."""
        self.analyzer.scan_cve_files(max_workers=1)  # Single worker for predictable testing
        
        # Should find our test files
        self.assertGreater(len(self.analyzer.inventory), 0)
        
        # Check that we found expected CVEs
        cve_ids = [cve.cve_id for cve in self.analyzer.inventory]
        self.assertIn("CVE-2024-0001", cve_ids)
        self.assertIn("CVE-2024-3125", cve_ids)
        self.assertIn("CVE-2025-3121", cve_ids)
        
        # Check CWE distribution
        self.assertGreater(len(self.analyzer.cwe_distribution), 0)
        self.assertIn("CWE-79", self.analyzer.cwe_distribution)
        
    def test_inventory_save_and_load(self):
        """Test saving inventory to CSV."""
        self.analyzer.scan_cve_files(max_workers=1)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            temp_csv = Path(f.name)
            
        try:
            self.analyzer.save_inventory(temp_csv)
            self.assertTrue(temp_csv.exists())
            
            # Read back and verify
            with open(temp_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
            self.assertGreater(len(rows), 0)
            
            # Check expected columns
            expected_columns = {
                'cve_id', 'year', 'file_path', 'description_length',
                'keyphrase_count', 'weakness_type', 'cwe_ids', 
                'cwe_count', 'primary_cwe_id', 'has_weakness',
                'has_impact', 'has_vector', 'has_product'
            }
            self.assertEqual(set(rows[0].keys()), expected_columns)
            
        finally:
            if temp_csv.exists():
                temp_csv.unlink()


class TestDiverseSampling(unittest.TestCase):
    """Test diverse sampling functionality."""
    
    def setUp(self):
        """Set up test data for sampling."""
        self.test_dir = Path(__file__).parent / "test_data"
        self.cve_info_dir = self.test_dir / "cve_info"
        self.cwe_dir = self.test_dir / "cvelistV5"
        self.analyzer = CVEAnalyzer(self.cve_info_dir, self.cwe_dir)
        self.analyzer.scan_cve_files(max_workers=1)
        
    def test_sampler_initialization(self):
        """Test DiverseSampler initialization."""
        sampler = DiverseSampler(self.analyzer.inventory)
        self.assertEqual(len(sampler.inventory), len(self.analyzer.inventory))
        self.assertEqual(sampler.sample_size, 50000)  # Default
        
    def test_small_sample_creation(self):
        """Test creating a small diverse sample."""
        sampler = DiverseSampler(self.analyzer.inventory)
        sampler.sample_size = min(3, len(self.analyzer.inventory))  # Small sample
        
        selected = sampler.create_diverse_sample()
        self.assertLessEqual(len(selected), sampler.sample_size)
        self.assertGreater(len(selected), 0)
        
        # Verify all selected items are CVEMetadata
        for item in selected:
            self.assertIsInstance(item, CVEMetadata)
            
    def test_cwe_count_categorization(self):
        """Test CWE count categorization."""
        sampler = DiverseSampler(self.analyzer.inventory)
        
        self.assertEqual(sampler.categorize_by_cwe_count(0), "no_cwe")
        self.assertEqual(sampler.categorize_by_cwe_count(1), "single_cwe")
        self.assertEqual(sampler.categorize_by_cwe_count(2), "multiple_cwe")
        self.assertEqual(sampler.categorize_by_cwe_count(5), "many_cwe")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    def setUp(self):
        """Set up test analyzer."""
        self.test_dir = Path(__file__).parent / "test_data"
        self.cve_info_dir = self.test_dir / "cve_info"
        self.cwe_dir = self.test_dir / "cvelistV5"
        
    def test_nonexistent_cve_directory(self):
        """Test handling of non-existent CVE directory."""
        fake_dir = Path("/nonexistent/path")
        analyzer = CVEAnalyzer(fake_dir, self.cwe_dir)
        
        with self.assertRaises(ValueError):
            analyzer.scan_cve_files()
            
    def test_missing_cwe_directory(self):
        """Test handling of missing CWE directory."""
        analyzer = CVEAnalyzer(self.cve_info_dir, None)
        analyzer.scan_cve_files(max_workers=1)
        
        # Should still work, just with no CWE data
        self.assertGreater(len(analyzer.inventory), 0)
        for cve in analyzer.inventory:
            self.assertEqual(cve.cwe_count, 0)
            self.assertEqual(cve.cwe_ids, [])
            
    def test_malformed_json_handling(self):
        """Test handling of malformed JSON files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create malformed JSON file
            bad_file = temp_path / "CVE-2024-bad.json"
            with open(bad_file, 'w') as f:
                f.write('{"invalid": json content}')
                
            analyzer = CVEAnalyzer(temp_path, None)
            analyzer.scan_cve_files(max_workers=1)
            
            # Should handle gracefully (skip bad files)
            self.assertEqual(len(analyzer.inventory), 0)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete workflow."""
    
    def test_end_to_end_small_dataset(self):
        """Test complete workflow with small test dataset."""
        test_dir = Path(__file__).parent / "test_data"
        cve_info_dir = test_dir / "cve_info"
        cwe_dir = test_dir / "cvelistV5"
        
        with tempfile.TemporaryDirectory() as output_dir:
            output_path = Path(output_dir)
            
            # Phase 1: Analysis
            analyzer = CVEAnalyzer(cve_info_dir, cwe_dir)
            analyzer.scan_cve_files(max_workers=1)
            
            inventory_path = output_path / "test_inventory.csv"
            analyzer.save_inventory(inventory_path)
            
            # Verify inventory file
            self.assertTrue(inventory_path.exists())
            
            # Phase 2: Sampling
            sampler = DiverseSampler(analyzer.inventory)
            sampler.sample_size = min(2, len(analyzer.inventory))
            selected_cves = sampler.create_diverse_sample()
            
            self.assertGreater(len(selected_cves), 0)
            self.assertLessEqual(len(selected_cves), sampler.sample_size)
            
            # Verify selected CVEs have both keyphrase and CWE data where available
            for cve in selected_cves:
                self.assertTrue(cve.cve_id.startswith("CVE-"))
                self.assertGreater(cve.year, 2020)  # Our test data is 2024-2025
                self.assertGreater(len(cve.file_path), 0)


if __name__ == '__main__':
    # Set up logging to see what's happening during tests
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Run tests
    unittest.main(verbosity=2)