#!/usr/bin/env python3
"""
Integration tests for the main script execution.
Tests the complete script with small test datasets.
"""

import unittest
import subprocess
import tempfile
import json
from pathlib import Path
import sys
import os

class TestMainScriptExecution(unittest.TestCase):
    """Test running the main script with test data."""
    
    def setUp(self):
        """Set up test environment."""
        self.script_dir = Path(__file__).parent.parent
        self.script_path = self.script_dir / "create_diverse_cve_dataset.py"
        self.test_data_dir = Path(__file__).parent / "test_data"
        
    def test_script_help(self):
        """Test that script shows help without errors."""
        result = subprocess.run(
            [sys.executable, str(self.script_path), "--help"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("Create diverse CVE dataset", result.stdout)
        self.assertIn("--cve-dir", result.stdout)
        self.assertIn("--cwe-dir", result.stdout)
        
    def test_script_create_all_cves_csv(self):
        """Test running script with --create-all-cves-csv flag."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            
            # Run script with test data
            cmd = [
                sys.executable, str(self.script_path),
                "--create-all-cves-csv",
                "--cve-dir", str(self.test_data_dir / "cve_info"),
                "--cwe-dir", str(self.test_data_dir / "cvelistV5"),
                "--output-dir", str(output_dir),
                "--max-workers", "1"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Check that script ran successfully
            if result.returncode != 0:
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
            
            self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
            
            # Check that output file was created
            csv_file = output_dir / "all_cves_with_cwe.csv"
            self.assertTrue(csv_file.exists(), "Output CSV file was not created")
            
            # Check CSV content
            with open(csv_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            self.assertIn("CVE-2024-0001", content)
            self.assertIn("CWE-79", content)
            
    def test_script_small_sample_generation(self):
        """Test generating a very small sample dataset."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            
            # Run script with small sample
            cmd = [
                sys.executable, str(self.script_path),
                "--cve-dir", str(self.test_data_dir / "cve_info"),
                "--cwe-dir", str(self.test_data_dir / "cvelistV5"),
                "--output-dir", str(output_dir),
                "--sample-size", "2",
                "--max-workers", "1",
                "--seed", "42"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Check results
            if result.returncode != 0:
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
            
            self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
            
            # Check output files
            jsonl_file = output_dir / "cve_50k_diverse_sample.jsonl"
            inventory_file = output_dir / "cve_inventory.csv"
            metadata_file = output_dir / "sampling_metadata.json"
            
            self.assertTrue(jsonl_file.exists(), "JSONL output file not created")
            self.assertTrue(inventory_file.exists(), "Inventory CSV not created")
            self.assertTrue(metadata_file.exists(), "Metadata JSON not created")
            
            # Verify JSONL content
            with open(jsonl_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            self.assertGreater(len(lines), 0, "JSONL file is empty")
            self.assertLessEqual(len(lines), 2, "Sample size exceeded")
            
            # Verify JSONL format
            for line in lines:
                data = json.loads(line)
                self.assertIn("contents", data)
                self.assertEqual(len(data["contents"]), 2)  # User + model
                self.assertEqual(data["contents"][0]["role"], "user")
                self.assertEqual(data["contents"][1]["role"], "model")
                
            # Verify metadata
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
                
            self.assertIn("dataset_size", metadata)
            self.assertIn("cwe_distribution", metadata)
            self.assertLessEqual(metadata["dataset_size"], 2)
            
    def test_script_error_handling(self):
        """Test script error handling with invalid directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            
            # Test with non-existent CVE directory
            cmd = [
                sys.executable, str(self.script_path),
                "--cve-dir", "/nonexistent/path",
                "--cwe-dir", str(self.test_data_dir / "cvelistV5"),
                "--output-dir", str(output_dir),
                "--sample-size", "1"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Should fail gracefully
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No JSON files found", result.stderr)
            
    def test_script_with_missing_cwe_dir(self):
        """Test script behavior when CWE directory is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            
            cmd = [
                sys.executable, str(self.script_path),
                "--create-all-cves-csv",
                "--cve-dir", str(self.test_data_dir / "cve_info"),
                "--cwe-dir", "/nonexistent/cwe/path",
                "--output-dir", str(output_dir),
                "--max-workers", "1"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Should succeed but warn about missing CWE directory
            self.assertEqual(result.returncode, 0)
            self.assertIn("CWE directory not found", result.stderr)
            
            # Output should still be created (without CWE data)
            csv_file = output_dir / "all_cves_with_cwe.csv"
            self.assertTrue(csv_file.exists())


class TestScriptPerformance(unittest.TestCase):
    """Test script performance characteristics."""
    
    def setUp(self):
        """Set up test environment."""
        self.script_dir = Path(__file__).parent.parent
        self.script_path = self.script_dir / "create_diverse_cve_dataset.py"
        self.test_data_dir = Path(__file__).parent / "test_data"
        
    def test_script_execution_time(self):
        """Test that script completes within reasonable time."""
        import time
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            
            start_time = time.time()
            
            cmd = [
                sys.executable, str(self.script_path),
                "--create-all-cves-csv",
                "--cve-dir", str(self.test_data_dir / "cve_info"),
                "--cwe-dir", str(self.test_data_dir / "cvelistV5"),
                "--output-dir", str(output_dir),
                "--max-workers", "2"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            execution_time = time.time() - start_time
            
            self.assertEqual(result.returncode, 0)
            self.assertLess(execution_time, 60, "Script took too long to execute")
            
            print(f"Script execution time: {execution_time:.2f} seconds")


if __name__ == '__main__':
    unittest.main(verbosity=2)