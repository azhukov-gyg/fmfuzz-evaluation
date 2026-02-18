#!/usr/bin/env python3
"""
Coverage Mapper for Z3
Processes SMT test files and extracts coverage data using fastcov.
"""

import os
import sys
import json
import subprocess
import re
import argparse
import time
import gc
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import z3test utilities for test validation
z3test_scripts = Path(__file__).parent.parent.parent / "z3test" / "scripts"
if z3test_scripts.exists():
    sys.path.insert(0, str(z3test_scripts))
    try:
        import util as z3test_util
        HAS_Z3TEST_UTIL = True
    except ImportError:
        HAS_Z3TEST_UTIL = False
else:
    HAS_Z3TEST_UTIL = False

class CoverageMapper:
    def __init__(self, build_dir: str = "build", z3test_dir: str = "z3test"):
        self.build_dir = Path(build_dir)
        self.z3test_dir = Path(z3test_dir)
        self.z3_binary = self.build_dir / "z3"
        # Cache for demangled names to avoid repeated subprocess calls
        self.demangle_cache = {}
        # Memory monitoring
        self.max_memory_mb = 10000  # 10GB limit
        self.memory_check_interval = 50  # Check every 50 tests

    def demangle_function_name(self, mangled_name: str) -> str:
        """Demangle C++ function names using c++filt with caching"""
        if mangled_name in self.demangle_cache:
            return self.demangle_cache[mangled_name]
        
        try:
            result = subprocess.run(['c++filt', mangled_name], capture_output=True, text=True)
            demangled = result.stdout.strip() if result.returncode == 0 else mangled_name
            self.demangle_cache[mangled_name] = demangled
            return demangled
        except FileNotFoundError:
            self.demangle_cache[mangled_name] = mangled_name
            return mangled_name
    
    def simplify_file_path(self, file_path: str) -> str:
        """Simplify file path to show only the relevant project path starting from src/"""
        # Always look for 'src/' directory and start from there
        if '/src/' in file_path:
            parts = file_path.split('/src/')
            if len(parts) > 1:
                return 'src/' + parts[1]
        
        # Fallback: return the original path
        return file_path

    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB"""
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except:
            return 0.0

    def check_memory_limit(self) -> bool:
        """Check if memory usage is within limits"""
        memory_mb = self.get_memory_usage_mb()
        if memory_mb > self.max_memory_mb:
            print(f"⚠️ Memory limit exceeded: {memory_mb:.1f}MB > {self.max_memory_mb}MB")
            return False
        return True

    def cleanup_memory(self):
        """Force garbage collection and clear caches"""
        # Clear demangle cache periodically
        if len(self.demangle_cache) > 1000:
            self.demangle_cache.clear()
        
        # Force garbage collection
        gc.collect()

    def write_intermediate_mapping(self, function_to_tests: Dict, output_file: Path):
        """Write intermediate mapping to disk to save memory"""
        with open(output_file, 'w') as f:
            json.dump(function_to_tests, f, separators=(',', ':'))

    def get_smt2_tests(self) -> List[Tuple[int, str]]:
        """Get list of all SMT test files from z3test repository"""
        try:
            if not self.z3test_dir.exists():
                print(f"Error: z3test directory not found: {self.z3test_dir}")
                sys.stdout.flush()
                return []
            
            regressions_dir = self.z3test_dir / "regressions"
            if not regressions_dir.exists():
                print(f"Error: regressions directory not found: {regressions_dir}")
                sys.stdout.flush()
                return []
            
            tests = []
            # Find all .smt and .smt2 files recursively in regressions directory
            for smt_file in regressions_dir.rglob("*.smt*"):
                # Skip .disabled files themselves (they are marker files, not test files)
                if smt_file.name.endswith('.disabled'):
                    continue
                    
                # Get relative path from z3test directory
                rel_path = smt_file.relative_to(self.z3test_dir)
                tests.append(str(rel_path))
            
            # Sort for consistent indexing (always same order)
            tests = sorted(tests)
            
            # Convert to (index, test_name) format (1-based indexing like ctest)
            indexed_tests = [(i + 1, test) for i, test in enumerate(tests)]
            
            print(f"Found {len(indexed_tests)} SMT tests")
            sys.stdout.flush()
            return indexed_tests
            
        except Exception as e:
            print(f"Error getting SMT tests: {e}")
            sys.stdout.flush()
            return []

    def process_single_test(self, test_info: Tuple[int, str]) -> Optional[Dict]:
        """Process a single test by running Z3 on SMT file and extract coverage data"""
        test_id, test_name = test_info

        # Clear existing .gcda files before running test
        for gcda in self.build_dir.rglob("*.gcda"):
            gcda.unlink()

        # Reset coverage counters
        self.reset_coverage_counters()

        # Get full path to SMT file
        smt_file = self.z3test_dir / test_name

        if not smt_file.exists():
            print(f"⚠️ Test file not found: {smt_file}")
            sys.stdout.flush()
            return None

        # Check if expected output file exists (required for validation)
        base_path = str(smt_file).rsplit('.', 1)[0]  # Remove extension
        expected_file = f"{base_path}.expected.out"
        if not os.path.exists(expected_file):
            print(f"⏭️ {test_name} - no expected output file, skipping")
            sys.stdout.flush()
            return None

        # Measure test execution time
        start_time = time.time()

        # Use z3test's validation if available (like cvc5 uses ctest)
        test_passed = False
        if HAS_Z3TEST_UTIL:
            try:
                # test_benchmark returns True on success, raises exception on failure
                z3test_util.test_benchmark(
                    str(self.z3_binary),
                    str(smt_file),
                    timeout=120,
                    expected=expected_file
                )
                test_passed = True
            except Exception as e:
                test_passed = False
        else:
            # Fallback: just run Z3 and check exit code (not ideal)
            result = subprocess.run(
                [str(self.z3_binary), str(smt_file)],
                cwd=self.build_dir,
                capture_output=True,
                text=True,
                check=False,
                timeout=120
            )
            test_passed = (result.returncode == 0)

        end_time = time.time()
        execution_time = round(end_time - start_time, 2)

        if not test_passed:
            print(f"❌ {test_name} - {execution_time}s")
            sys.stdout.flush()
            return None

        # Extract coverage data
        coverage_data = self.extract_coverage_data(test_name)

        if coverage_data:
            print(f"✅ {test_name} - {len(coverage_data['functions'])} functions - {execution_time}s")
        else:
            print(f"❌ {test_name} - {execution_time}s")
        sys.stdout.flush()

        # Clean up memory after each test
        self.cleanup_memory()

        return coverage_data

    def extract_coverage_data(self, test_name: str) -> Optional[Dict]:
        """Extract coverage data using fastcov"""
        # Sanitize test name for filename
        safe_name = test_name.replace('/', '_').replace('\\', '_')
        fastcov_output = self.build_dir / f"fastcov_{safe_name}.json"
        
        # Run fastcov with optimized settings
        result = subprocess.run([
            "fastcov", "--gcov", "gcov", "--search-directory", str(self.build_dir),
            "--output", str(fastcov_output), "--exclude", "/usr/include/*",
            "--exclude", "*/deps/*", "--jobs", "4"
        ], cwd=self.build_dir.parent, capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            return None
        
        result_data = self.parse_fastcov_json(fastcov_output, test_name)
        
        # Clean up temporary fastcov file to save disk space
        try:
            fastcov_output.unlink()
        except:
            pass
        
        return result_data

    def parse_fastcov_json(self, fastcov_file: Path, test_name: str) -> Optional[Dict]:
        """Parse fastcov JSON file to extract function information"""
        with open(fastcov_file, 'r') as f:
            data = json.load(f)
        
        functions = set()
        
        if 'sources' in data:
            for file_path, file_data in data['sources'].items():
                if self.is_z3_source_file(file_path):
                    if '' in file_data and 'functions' in file_data['']:
                        for func_name, func_data in file_data['']['functions'].items():
                            if func_data.get('execution_count', 0) > 0:
                                demangled_name = self.demangle_function_name(func_name)
                                simplified_path = self.simplify_file_path(file_path)
                                line_num = func_data.get('start_line', 0)
                                func_id = f"{simplified_path}:{demangled_name}:{line_num}"
                                functions.add(func_id)
        
        if not functions:
            return None
        
        return {
            "test_name": test_name,
            "functions": sorted(list(functions))
        }

    def is_z3_source_file(self, file_path: str) -> bool:
        """Check if a file path belongs to the Z3 project"""
        # Check if it's a Z3 source file by looking for 'src/' directory
        has_src_dir = 'src/' in file_path
        
        # Exclude system and build directories
        excluded_patterns = [
            '/usr/include/', '/usr/lib/', '/System/', '/Library/',
            '/Applications/', '/opt/', '/deps/', '/build/deps/',
            '/build/src/', '/build/', '/include/', '/lib/', 
            '/bin/', '/share/', 'CMakeFiles/', 'cmake/', 'Makefile'
        ]
        
        has_excluded_pattern = any(exclude in file_path for exclude in excluded_patterns)
        
        return has_src_dir and not has_excluded_pattern

    def reset_coverage_counters(self):
        """Reset coverage counters using fastcov --zerocounters"""
        subprocess.run([
            "fastcov", "--zerocounters", "--search-directory", str(self.build_dir),
            "--exclude", "/usr/include/*", "--exclude", "*/deps/*"
        ], cwd=self.build_dir.parent, capture_output=True, text=True, check=False)

    def process_tests(self, tests: List[Tuple[int, str]], max_tests: int = None) -> str:
        """Process tests sequentially with streaming to disk to avoid memory issues"""
        if max_tests:
            tests = tests[:max_tests]
        
        print(f"🚀 Processing {len(tests)} tests")
        print(f"💾 Memory limit: {self.max_memory_mb}MB")
        sys.stdout.flush()
        
        # Use streaming approach - write to disk incrementally
        temp_file = self.build_dir / "coverage_temp.json"
        function_to_tests = {}
        
        for i, test_info in enumerate(tests, 1):
            test_id, test_name = test_info
            print(f"Test {i}/{len(tests)} (#{test_id}): {test_name}")
            sys.stdout.flush()
            
            # Check memory every N tests
            if i % self.memory_check_interval == 0:
                if not self.check_memory_limit():
                    print(f"🛑 Stopping at test {i} due to memory limit")
                    sys.stdout.flush()
                    break
                self.cleanup_memory()
                memory_mb = self.get_memory_usage_mb()
                print(f"💾 Memory usage: {memory_mb:.1f}MB")
                sys.stdout.flush()
            
            try:
                result = self.process_single_test(test_info)
                if result:
                    # Add to mapping immediately and don't keep in memory
                    test_name = result["test_name"]
                    for func in result["functions"]:
                        if func not in function_to_tests:
                            function_to_tests[func] = []
                        function_to_tests[func].append(test_name)
                    
                    # Write intermediate results every 100 tests to avoid losing progress
                    if i % 100 == 0:
                        self.write_intermediate_mapping(function_to_tests, temp_file)
            except Exception as e:
                # Catch any unexpected errors and continue processing
                print(f"⚠️ {test_name} - unexpected error: {e} (skipping)")
                sys.stdout.flush()
                continue
        
        # Write final mapping
        self.write_intermediate_mapping(function_to_tests, temp_file)
        return str(temp_file)


    def run(self, max_tests: int = None, test_pattern: str = None, start_index: int = None, end_index: int = None):
        """Main execution method"""
        print("🔍 Discovering tests...")
        sys.stdout.flush()
        tests = self.get_smt2_tests()
        
        if not tests:
            print("❌ No tests found")
            sys.stdout.flush()
            return
        
        if test_pattern:
            tests = [t for t in tests if test_pattern in t[1]]
            print(f"🔍 Filtered to {len(tests)} tests matching pattern: {test_pattern}")
            sys.stdout.flush()
        
        # Handle test range selection (1-based indexing to match ctest)
        if start_index is not None and end_index is not None:
            # Convert 1-based to 0-based for slicing
            start_idx = max(0, start_index - 1)
            end_idx = min(len(tests), end_index)
            tests = tests[start_idx:end_idx]
            print(f"🔍 Selected tests {start_index}-{end_index}: {len(tests)} tests")
            sys.stdout.flush()
        elif max_tests:
            tests = tests[:max_tests]
            print(f"🔍 Limited to {len(tests)} tests")
            sys.stdout.flush()
        
        # Process tests with streaming to avoid memory issues
        temp_file = self.process_tests(tests, max_tests)
        
        if not temp_file or not Path(temp_file).exists():
            print("❌ No coverage data generated")
            sys.stdout.flush()
            return
        
        # Move temp file to final location
        output_file = f"coverage_mapping_{start_index}_{end_index}.json" if start_index is not None else "coverage_mapping.json"
        Path(temp_file).rename(output_file)
        
        # Get stats from the final file
        with open(output_file, 'r') as f:
            coverage_mapping = json.load(f)
        
        print(f"📄 Coverage mapping saved to {output_file}")
        print(f"📊 Total functions: {len(coverage_mapping)}")
        print(f"📊 Total tests: {len(tests)}")
        sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description='Coverage Mapper for Z3')
    parser.add_argument('--build-dir', default='build', help='Build directory path')
    parser.add_argument('--z3test-dir', default='z3test', help='Z3 test repository directory path')
    parser.add_argument('--max-tests', type=int, help='Maximum number of tests to process')
    parser.add_argument('--test-pattern', help='Filter tests by pattern')
    parser.add_argument('--start-index', type=int, help='Start index for test range (1-based)')
    parser.add_argument('--end-index', type=int, help='End index for test range (1-based, inclusive)')

    args = parser.parse_args()

    mapper = CoverageMapper(args.build_dir, args.z3test_dir)
    mapper.run(max_tests=args.max_tests, test_pattern=args.test_pattern,
               start_index=args.start_index, end_index=args.end_index)

if __name__ == "__main__":
    main()

