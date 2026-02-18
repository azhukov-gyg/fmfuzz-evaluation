#!/usr/bin/env python3
"""
Simple script to join coverage mapping files.
"""

import json
import os
import sys

def main():
    # Find all coverage mapping files
    mapping_files = []
    for root, dirs, files in os.walk('coverage-mappings'):
        for file in files:
            if file.startswith('coverage_mapping_') and file.endswith('.json'):
                mapping_files.append(os.path.join(root, file))
    
    if not mapping_files:
        print("No coverage mapping files found!")
        sys.exit(1)
    
    print(f"Found {len(mapping_files)} mapping files")
    
    # Merge all mappings
    merged_mapping = {}
    for file_path in mapping_files:
        print(f"Processing {os.path.basename(file_path)}")
        with open(file_path, 'r') as f:
            data = json.load(f)
            for func, tests in data.items():
                if func not in merged_mapping:
                    merged_mapping[func] = []
                merged_mapping[func].extend(tests)
    
    # Remove duplicates and sort
    for func in merged_mapping:
        merged_mapping[func] = sorted(list(set(merged_mapping[func])))
    
    # Save merged mapping
    with open('coverage_mapping.json', 'w') as f:
        json.dump(merged_mapping, f, separators=(',', ':'))
    
    # Get file size
    original_size = os.path.getsize('coverage_mapping.json')
    print(f"Original size: {original_size:,} bytes")
    
    # Compress
    os.system("gzip -k coverage_mapping.json")
    compressed_size = os.path.getsize('coverage_mapping.json.gz')
    compression_ratio = (compressed_size / original_size) * 100
    print(f"Compressed size: {compressed_size:,} bytes ({compression_ratio:.1f}% of original)")
    
    print(f"Functions: {len(merged_mapping)}")
    print("Merged coverage mapping saved")

if __name__ == "__main__":
    main()
