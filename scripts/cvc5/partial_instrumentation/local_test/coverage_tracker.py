#!/usr/bin/env python3
"""
Coverage Tracker for CVC5
=========================
Runs multiple tests and tracks edge coverage progression.
Shows which tests discover new edges.

Usage:
    python coverage_tracker.py /path/to/cvc5 test1.smt2 test2.smt2 test3.smt2
    python coverage_tracker.py /path/to/cvc5 --test-dir /path/to/tests/
"""

import argparse
import os
import subprocess
import sys
import tempfile
import mmap
import json
from pathlib import Path
from typing import List, Dict, Set, Tuple
from datetime import datetime


# Bitmap size (AFL++ style)
BITMAP_SIZE = 65536


class CoverageTracker:
    """Track edge coverage across multiple test runs."""
    
    def __init__(self, binary_path: str, shm_name: str = None):
        self.binary_path = binary_path
        
        # Check if __AFL_SHM_ID is set (by parent bash script or AFL++)
        afl_shm_id = os.environ.get('__AFL_SHM_ID')
        if afl_shm_id:
            # Use AFL-style shm naming (matches coverage_agent.cpp)
            self.shm_id = f"afl_shm_{afl_shm_id}"
            self.use_afl_shm = True
        else:
            # Create our own shm
            self.shm_id = shm_name or f"cov_{os.getpid()}"
            self.use_afl_shm = False
        
        self.shm_name = f"/{self.shm_id}"  # For shm_open() which needs leading /
        self.shm_path = f"/dev/shm/{self.shm_id}"  # Direct file path
        self.bitmap = bytearray(BITMAP_SIZE)
        self.total_edges = 0
        self.test_results: List[Dict] = []
        
        # Create shared memory file
        self._init_shm()
    
    def _init_shm(self):
        """Initialize shared memory for coverage bitmap."""
        # Create/reset the shm file in /dev/shm
        with open(self.shm_path, 'wb') as f:
            f.write(b'\x00' * BITMAP_SIZE)
        os.chmod(self.shm_path, 0o666)
    
    def _read_bitmap(self) -> bytearray:
        """Read current bitmap from shared memory."""
        with open(self.shm_path, 'rb') as f:
            return bytearray(f.read())
    
    def _reset_bitmap(self):
        """Reset bitmap to zeros."""
        with open(self.shm_path, 'wb') as f:
            f.write(b'\x00' * BITMAP_SIZE)
    
    def _count_edges(self, bitmap: bytearray) -> int:
        """Count number of non-zero bytes (edges hit)."""
        return sum(1 for b in bitmap if b > 0)
    
    def _find_new_edges(self, old_bitmap: bytearray, new_bitmap: bytearray) -> Set[int]:
        """Find indices of newly covered edges."""
        new_edges = set()
        for i in range(BITMAP_SIZE):
            if old_bitmap[i] == 0 and new_bitmap[i] > 0:
                new_edges.add(i)
        return new_edges
    
    def run_test(self, test_file: str, timeout: float = 30.0) -> Dict:
        """Run a single test and record coverage."""
        test_name = os.path.basename(test_file)
        
        # Save bitmap state before test
        bitmap_before = self.bitmap.copy()
        
        # Run the test - env vars are already set correctly
        # (we inherit __AFL_SHM_ID from parent if it was set)
        env = os.environ.copy()
        if not self.use_afl_shm:
            # Only set COVERAGE_SHM_NAME if we're not using AFL shm
            env['COVERAGE_SHM_NAME'] = self.shm_name
        
        start_time = datetime.now()
        try:
            result = subprocess.run(
                [self.binary_path, test_file],
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
        except subprocess.TimeoutExpired:
            exit_code = -1
            stdout = ""
            stderr = "TIMEOUT"
        except Exception as e:
            exit_code = -2
            stdout = ""
            stderr = str(e)
        
        end_time = datetime.now()
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        # Read bitmap after test
        bitmap_after = self._read_bitmap()
        
        # Merge into cumulative bitmap
        for i in range(BITMAP_SIZE):
            if bitmap_after[i] > 0:
                self.bitmap[i] = max(self.bitmap[i], bitmap_after[i])
        
        # Calculate coverage stats
        edges_before = self._count_edges(bitmap_before)
        edges_after = self._count_edges(self.bitmap)
        new_edges = self._find_new_edges(bitmap_before, self.bitmap)
        
        test_result = {
            'test_name': test_name,
            'test_path': test_file,
            'exit_code': exit_code,
            'duration_ms': round(duration_ms, 1),
            'edges_before': edges_before,
            'edges_after': edges_after,
            'new_edges_count': len(new_edges),
            'new_edge_indices': sorted(new_edges)[:100],  # Store first 100 for debugging
            'total_edges': edges_after,
            'stdout': stdout[:200] if stdout else "",
        }
        
        self.test_results.append(test_result)
        self.total_edges = edges_after
        
        # Reset bitmap for next test (cumulative tracking is in self.bitmap)
        self._reset_bitmap()
        
        return test_result
    
    def run_tests(self, test_files: List[str], verbose: bool = True) -> Dict:
        """Run multiple tests and track coverage progression."""
        if verbose:
            print(f"\n{'='*70}")
            print(f"Coverage Tracker - Running {len(test_files)} tests")
            print(f"Binary: {self.binary_path}")
            shm_source = "AFL" if self.use_afl_shm else "custom"
            print(f"SHM: {self.shm_path} ({shm_source})")
            print(f"{'='*70}\n")
        
        for i, test_file in enumerate(test_files, 1):
            result = self.run_test(test_file)
            
            if verbose:
                status = "✅" if result['exit_code'] == 0 else "❌"
                new_str = f"+{result['new_edges_count']} new" if result['new_edges_count'] > 0 else "no new"
                print(f"  [{i}/{len(test_files)}] {status} {result['test_name']}")
                print(f"       Time: {result['duration_ms']:.0f}ms | Edges: {result['total_edges']:,} ({new_str})")
                if result['stdout']:
                    print(f"       Output: {result['stdout'].strip()}")
                print()
        
        summary = self.get_summary()
        
        if verbose:
            print(f"{'='*70}")
            print(f"Summary")
            print(f"{'='*70}")
            print(f"  Total tests: {summary['total_tests']}")
            print(f"  Passed: {summary['passed_tests']}")
            print(f"  Total edges discovered: {summary['total_edges']:,}")
            print(f"  Tests that found new edges: {summary['tests_with_new_edges']}")
            print(f"{'='*70}\n")
        
        return summary
    
    def get_summary(self) -> Dict:
        """Get summary of all test runs."""
        return {
            'total_tests': len(self.test_results),
            'passed_tests': sum(1 for r in self.test_results if r['exit_code'] == 0),
            'total_edges': self.total_edges,
            'tests_with_new_edges': sum(1 for r in self.test_results if r['new_edges_count'] > 0),
            'total_new_edges': sum(r['new_edges_count'] for r in self.test_results),
            'test_results': self.test_results,
        }
    
    def save_report(self, output_file: str):
        """Save detailed coverage report as JSON."""
        report = {
            'binary': self.binary_path,
            'timestamp': datetime.now().isoformat(),
            'summary': self.get_summary(),
            'bitmap_size': BITMAP_SIZE,
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📊 Report saved to: {output_file}")
    
    def cleanup(self):
        """Clean up shared memory."""
        try:
            os.unlink(self.shm_path)
        except:
            pass


def find_test_files(test_dir: str, extensions: List[str] = None) -> List[str]:
    """Find all test files in a directory."""
    extensions = extensions or ['.smt2', '.smt']
    test_files = []
    
    for ext in extensions:
        test_files.extend(Path(test_dir).glob(f'**/*{ext}'))
    
    return sorted(str(f) for f in test_files)


def main():
    parser = argparse.ArgumentParser(description='Track CVC5 edge coverage across tests')
    parser.add_argument('binary', help='Path to instrumented CVC5 binary')
    parser.add_argument('tests', nargs='*', help='Test files to run')
    parser.add_argument('--test-dir', help='Directory containing test files')
    parser.add_argument('--output', '-o', help='Output JSON report file')
    parser.add_argument('--timeout', type=float, default=30.0, help='Timeout per test (seconds)')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"❌ Binary not found: {args.binary}")
        return 1
    
    # Collect test files
    test_files = list(args.tests) if args.tests else []
    
    if args.test_dir:
        test_files.extend(find_test_files(args.test_dir))
    
    if not test_files:
        print("❌ No test files specified. Use positional args or --test-dir")
        return 1
    
    # Check test files exist
    for f in test_files:
        if not os.path.exists(f):
            print(f"❌ Test file not found: {f}")
            return 1
    
    # Run coverage tracking
    tracker = CoverageTracker(args.binary)
    
    try:
        summary = tracker.run_tests(test_files, verbose=not args.quiet)
        
        if args.output:
            tracker.save_report(args.output)
        
        return 0 if summary['passed_tests'] == summary['total_tests'] else 1
    
    finally:
        tracker.cleanup()


if __name__ == '__main__':
    sys.exit(main())

