~!/bin/sh

# Create comprehensive inventory to understand your dataset
python3 create_diverse_cve_dataset.py --create-all-cves-csv

# Generate training dataset (uses both keyphrases and CWE data)
python3 create_diverse_cve_dataset.py \
  --sample-size 50000 \
  --output-dir training_data \
  --max-workers 12