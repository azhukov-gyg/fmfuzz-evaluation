#!/usr/bin/env python3
"""
Sancov Coverage Tracker for CVC5 Fuzzing

Tracks coverage using shared memory from our custom coverage agent.
The agent (libcov_agent.so) writes coverage data to shared memory,
and this tracker reads it after each test execution.
"""

import os
import sys
import struct
import mmap
from pathlib import Path
from typing import Set, Dict, Optional, Tuple
import json
import uuid

# Shared memory constants (must match coverage_agent.cpp)
# Structure: pid(4+4), guard_count(4+4), hit_guard_count(4+4), pc_table_size(4+4),
#            hit_guards bitmap(MAX_GUARDS/8), pc_table(MAX_PCS*8)
MAX_GUARDS = 65536
MAX_PCS = 65536
SHM_SIZE = 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + (MAX_GUARDS // 8) + MAX_PCS * 8


class SancovCoverageTracker:
    """Track coverage using shared memory from coverage agent."""
    
    def __init__(self, coverage_dir: str = ".", binary_path: Optional[str] = None, 
                 shm_name: Optional[str] = None):
        """
        Initialize coverage tracker.
        
        Args:
            coverage_dir: Directory for coverage output (used for reports)
            binary_path: Path to the instrumented binary
            shm_name: Shared memory name (if None, generates unique name)
        """
        self.coverage_dir = Path(coverage_dir)
        self.binary_path = Path(binary_path) if binary_path else None
        self.binary_name = self.binary_path.name if self.binary_path else None
        
        # Generate unique shared memory name
        self.shm_name = shm_name or f"cvc5_cov_{uuid.uuid4().hex[:8]}"
        self.shm_path = f"/dev/shm/{self.shm_name}"
        
        # Track unique coverage indices seen (counter indices with non-zero values)
        self.covered_indices: Set[int] = set()
        
        # Track unique PCs (program counters) seen
        self.covered_pcs: Set[int] = set()
        
        # Track coverage per test/file
        self.test_coverage: Dict[str, Set[int]] = {}
        
        # Track processed count for stats
        self.processed_count: int = 0
    
    def get_env_vars(self) -> Dict[str, str]:
        """Get environment variables to pass to the target binary."""
        return {
            'COVERAGE_SHM_NAME': self.shm_name,
            'ASAN_OPTIONS': 'abort_on_error=0:detect_leaks=0'
        }
    
    def get_ld_preload_path(self) -> Optional[str]:
        """Get path to coverage agent shared library."""
        if self.binary_path:
            # Look for libcov_agent.so in the same directory as the binary
            agent_path = self.binary_path.parent / 'libcov_agent.so'
            if agent_path.exists():
                return str(agent_path)
        return None
    
    def cleanup_shm(self):
        """Remove shared memory file."""
        try:
            if os.path.exists(self.shm_path):
                os.unlink(self.shm_path)
        except:
            pass
    
    def read_shm_coverage(self) -> Tuple[Set[int], Set[int], int, int]:
        """
        Read coverage from default shared memory.
        Returns: (covered_indices, pcs, counter_count, pc_table_size)
        """
        return self._read_shm_at_path(self.shm_path)
    
    def update_coverage(self, test_id: Optional[str] = None) -> Dict[str, int]:
        """
        Update coverage by reading from default shared memory.
        
        Returns:
            Dict with 'new_pcs', 'total_pcs', 'new_files' counts
        """
        return self.update_coverage_from_shm(shm_name=self.shm_name, test_id=test_id)
    
    def update_coverage_from_shm(self, shm_name: str, test_id: Optional[str] = None) -> Dict[str, int]:
        """
        Update coverage by reading from specified shared memory.
        
        Args:
            shm_name: Name of the shared memory segment to read
            test_id: Optional test identifier for tracking per-test coverage
        
        Returns:
            Dict with 'new_pcs', 'total_pcs', 'new_files' counts
        """
        # Read from the specified shared memory
        shm_path = f"/dev/shm/{shm_name}"
        covered_indices, pcs, counter_count, pc_table_size = self._read_shm_at_path(shm_path)
        
        # Track new coverage
        new_indices = covered_indices - self.covered_indices
        new_pcs = pcs - self.covered_pcs
        
        if new_indices or new_pcs:
            self.processed_count += 1
            
            # Update test coverage if test_id provided
            if test_id:
                if test_id not in self.test_coverage:
                    self.test_coverage[test_id] = set()
                self.test_coverage[test_id].update(covered_indices)
        
        # Update total coverage
        self.covered_indices.update(new_indices)
        self.covered_pcs.update(new_pcs)
        
        # Clean up this worker's shared memory
        try:
            if os.path.exists(shm_path):
                os.unlink(shm_path)
        except:
            pass
        
        return {
            'new_pcs': len(new_indices),  # Use indices as "PCs" for consistency
            'total_pcs': len(self.covered_indices),
            'new_files': 1 if new_indices else 0
        }
    
    def _read_shm_at_path(self, shm_path: str) -> Tuple[Set[int], Set[int], int, int]:
        """
        Read coverage from shared memory at specified path.
        Returns: (covered_guard_indices, pcs, guard_count, pc_table_size)
        """
        covered_guard_indices = set()
        pcs = set()
        guard_count = 0
        pc_table_size = 0
        
        try:
            if not os.path.exists(shm_path):
                return covered_guard_indices, pcs, guard_count, pc_table_size
            
            file_size = os.path.getsize(shm_path)
            if file_size < SHM_SIZE:
                return covered_guard_indices, pcs, guard_count, pc_table_size
            
            with os.fdopen(os.open(shm_path, os.O_RDONLY), 'rb') as fd:
                shm_mmap = mmap.mmap(fd.fileno(), file_size, access=mmap.ACCESS_READ)
                
                try:
                    shm_mmap.seek(0)
                    
                    # pid (atomic<uint32_t>) - offset 0, 4 bytes
                    pid = struct.unpack('I', shm_mmap.read(4))[0]
                    shm_mmap.read(4)  # Skip padding
                    
                    # guard_count (atomic<uint32_t>) - offset 8, 4 bytes
                    guard_count = struct.unpack('I', shm_mmap.read(4))[0]
                    shm_mmap.read(4)  # Skip padding
                    
                    # hit_guard_count (atomic<uint32_t>) - offset 16, 4 bytes
                    hit_guard_count = struct.unpack('I', shm_mmap.read(4))[0]
                    shm_mmap.read(4)  # Skip padding
                    
                    # pc_table_size (atomic<uint32_t>) - offset 24, 4 bytes
                    pc_table_size = struct.unpack('I', shm_mmap.read(4))[0]
                    shm_mmap.read(4)  # Skip padding
                    
                    if guard_count == 0:
                        return covered_guard_indices, pcs, guard_count, pc_table_size
                    
                    # hit_guards bitmap starts at offset 32
                    hit_guards_bytes = shm_mmap.read(MAX_GUARDS // 8)
                    
                    # PC table starts after hit_guards bitmap
                    pc_table_bytes = shm_mmap.read(MAX_PCS * 8)
                    
                    # Extract covered guard indices from bitmap
                    for byte_idx in range(min(len(hit_guards_bytes), MAX_GUARDS // 8)):
                        byte_val = hit_guards_bytes[byte_idx]
                        if byte_val != 0:
                            for bit_idx in range(8):
                                if byte_val & (1 << bit_idx):
                                    guard_idx = byte_idx * 8 + bit_idx
                                    if guard_idx < guard_count:
                                        covered_guard_indices.add(guard_idx)
                    
                    # Extract PCs
                    for i in range(min(pc_table_size, MAX_PCS)):
                        pc = struct.unpack('Q', pc_table_bytes[i*8:(i+1)*8])[0]
                        if pc != 0:
                            pcs.add(pc)
                finally:
                    shm_mmap.close()
        except Exception as e:
            print(f"[Sancov] Error reading shared memory at {shm_path}: {e}", file=sys.stderr)
        
        return covered_guard_indices, pcs, guard_count, pc_table_size
    
    def get_coverage_stats(self) -> Dict:
        """Get current coverage statistics."""
        return {
            'total_pcs': len(self.covered_indices),
            'tests_tracked': len(self.test_coverage),
            'processed_files': self.processed_count
        }
    
    def save_coverage(self, output_file: str):
        """Save coverage data to JSON file."""
        data = {
            'covered_pcs': sorted(list(self.covered_indices)),
            'covered_pc_addresses': sorted(list(self.covered_pcs)),
            'test_coverage': {k: sorted(list(v)) for k, v in self.test_coverage.items()},
            'processed_files': [],  # Shared memory doesn't use files
            'stats': self.get_coverage_stats()
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_coverage(self, input_file: str):
        """Load coverage data from JSON file."""
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        self.covered_indices = set(data.get('covered_pcs', []))
        self.covered_pcs = set(data.get('covered_pc_addresses', []))
        self.test_coverage = {k: set(v) for k, v in data.get('test_coverage', {}).items()}
        self.processed_count = data.get('stats', {}).get('processed_files', 0)


def main():
    """CLI for testing coverage tracker."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Track sancov coverage')
    parser.add_argument('--coverage-dir', default='.', help='Directory with .sancov files')
    parser.add_argument('--binary', help='Binary name to match .sancov files')
    parser.add_argument('--update', action='store_true', help='Update coverage from new files')
    parser.add_argument('--stats', action='store_true', help='Print coverage statistics')
    parser.add_argument('--save', help='Save coverage to JSON file')
    parser.add_argument('--load', help='Load coverage from JSON file')
    
    args = parser.parse_args()
    
    tracker = SancovCoverageTracker(args.coverage_dir, args.binary)
    
    if args.load:
        tracker.load_coverage(args.load)
        print(f"Loaded coverage from {args.load}")
    
    if args.update:
        result = tracker.update_coverage()
        print(f"New PCs: {result['new_pcs']}, Total PCs: {result['total_pcs']}, New files: {result['new_files']}")
    
    if args.stats:
        stats = tracker.get_coverage_stats()
        print(f"Coverage Statistics:")
        print(f"  Total PCs: {stats['total_pcs']}")
        print(f"  Tests tracked: {stats['tests_tracked']}")
        print(f"  Processed files: {stats['processed_files']}")
    
    if args.save:
        tracker.save_coverage(args.save)
        print(f"Saved coverage to {args.save}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

