#!/usr/bin/env python3

import argparse
import gc
import json
import multiprocessing
import os
import psutil
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple


class SimpleCommitFuzzer:
    EXIT_CODE_BUGS_FOUND = 10
    EXIT_CODE_UNSUPPORTED = 3
    EXIT_CODE_SUCCESS = 0
    
    RESOURCE_CONFIG = {
        'cpu_warning': 85.0,
        'cpu_critical': 95.0,
        'memory_warning_available_gb': 2.0,  # Warning if less than 2GB available
        'memory_critical_available_gb': 0.5,  # Critical if less than 500MB available (real low memory)
        'check_interval': 2,  # Check every 2 seconds
        'pause_duration': 10,
        'max_process_memory_mb': 2048,  # Kill processes exceeding 2GB (normal operation) - allows normal solver usage but catches runaway processes
        'max_process_memory_mb_warning': 1536,  # Stricter threshold (1.5GB) when system memory is low
        'z3_memory_limit_mb': 2048,  # Z3 memory limit: 2GB per process (4 workers × 2GB = 8GB total)
    }
    
    def __init__(
        self,
        tests: List[str],
        tests_root: str,
        bugs_folder: str = "bugs",
        num_workers: int = 4,
        iterations: int = 250,
        modulo: int = 2,
        seed: int = 42,
        time_remaining: Optional[int] = None,
        job_start_time: Optional[float] = None,
        stop_buffer_minutes: int = 5,
        z3_old_path: Optional[str] = None,
        cvc4_path: Optional[str] = None,
        z3_path: str = "./build/z3",
        cvc5_path: Optional[str] = None,
        job_id: Optional[str] = None,
    ):
        self.tests = tests
        self.tests_root = Path(tests_root)
        self.bugs_folder = Path(bugs_folder)
        self.iterations = iterations
        self.modulo = modulo
        self.seed = seed
        self.job_id = job_id
        self.start_time = time.time()
        
        try:
            self.cpu_count = psutil.cpu_count()
        except Exception:
            self.cpu_count = 4
        
        self.num_workers = min(num_workers, self.cpu_count) if num_workers > 0 else self.cpu_count
        if num_workers > self.cpu_count:
            print(f"[WARN] Requested {num_workers} workers but only {self.cpu_count} CPU cores available, using {self.num_workers} workers", file=sys.stderr)
        
        if job_start_time is not None:
            self.time_remaining = self._compute_time_remaining(job_start_time, stop_buffer_minutes)
            print(f"[DEBUG] Job start time: {job_start_time} ({time.ctime(job_start_time)})")
            print(f"[DEBUG] Script start time: {self.start_time} ({time.ctime(self.start_time)})")
            build_time = self.start_time - job_start_time
            print(f"[DEBUG] Build time: {build_time:.1f}s ({build_time / 60:.1f} minutes)")
            print(f"[DEBUG] Stop buffer: {stop_buffer_minutes} minutes")
            print(f"[DEBUG] Computed remaining time: {self.time_remaining}s ({self.time_remaining / 60:.1f} minutes)")
        elif time_remaining is not None:
            self.time_remaining = time_remaining
            print(f"[DEBUG] Using provided time_remaining: {time_remaining}s ({time_remaining / 60:.1f} minutes)")
        else:
            self.time_remaining = None
            print("[DEBUG] No timeout set (running indefinitely)")
        
        # Limit Z3 to configured RAM per process
        z3_memory_mb = self.RESOURCE_CONFIG['z3_memory_limit_mb']
        self.z3_path = Path(z3_path)
        # self.z3_old_path = Path(z3_old_path) if z3_old_path else None
        # self.cvc4_path = Path(cvc4_path) if cvc4_path else None
        self.cvc5_path = Path(cvc5_path) if cvc5_path else None
        
        self._validate_solvers()
        self.bugs_folder.mkdir(parents=True, exist_ok=True)
        
        self.test_queue = multiprocessing.Queue()
        self.bugs_lock = multiprocessing.Lock()
        self.shutdown_event = multiprocessing.Event()
        
        self.resource_state = multiprocessing.Manager().dict({
            'cpu_percent': [0.0] * self.cpu_count,
            'memory_percent': 0.0,
            'status': 'normal',
            'paused': False,
            'last_update': time.time(),
        })
        self.resource_lock = multiprocessing.Lock()
        
        # Track which test each worker is currently processing (worker_id -> test_name)
        self.current_tests = multiprocessing.Manager().dict()
        
        self.stats = multiprocessing.Manager().dict({
            'tests_processed': 0,
            'bugs_found': 0,
            'tests_removed_unsupported': 0,
            'tests_removed_timeout': 0,
            'tests_requeued': 0,
        })
    
    def _validate_solvers(self):
        if not self.z3_path.exists():
            raise ValueError(f"z3 not found at: {self.z3_path}")
        # if self.z3_old_path and not self.z3_old_path.exists():
        #     raise ValueError(f"z3-old not found at: {self.z3_old_path}")
        # if self.cvc4_path and not self.cvc4_path.exists():
        #     raise ValueError(f"cvc4 not found at: {self.cvc4_path}")
        if self.cvc5_path and not self.cvc5_path.exists():
            raise ValueError(f"cvc5 not found at: {self.cvc5_path}")
    
    def _monitor_resources(self):
        while not self.shutdown_event.is_set():
            try:
                try:
                    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
                    memory = psutil.virtual_memory()
                    memory_percent = memory.percent
                    memory_available_gb = memory.available / (1024**3)  # Real available memory (excludes cache/buffers)
                    
                    max_cpu = max(cpu_percent) if cpu_percent else 0.0
                    avg_cpu = sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0.0
                    
                    status = 'normal'
                    
                    # Use available memory (not percent) to detect real memory pressure
                    # On Linux, memory.percent includes cache/buffers which can be misleading
                    if (avg_cpu >= self.RESOURCE_CONFIG['cpu_critical'] or 
                        memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']):
                        status = 'critical'
                    elif (avg_cpu >= self.RESOURCE_CONFIG['cpu_warning'] or 
                          memory_available_gb < self.RESOURCE_CONFIG['memory_warning_available_gb']):
                        status = 'warning'
                    
                    with self.resource_lock:
                        self.resource_state['cpu_percent'] = cpu_percent
                        self.resource_state['memory_percent'] = memory_percent
                        self.resource_state['memory_available_gb'] = memory_available_gb
                        self.resource_state['status'] = status
                        self.resource_state['last_update'] = time.time()
                        self.resource_state['max_cpu'] = max_cpu
                        self.resource_state['avg_cpu'] = avg_cpu
                        self.resource_state['memory_total_gb'] = memory.total / (1024**3)
                        self.resource_state['memory_used_gb'] = memory.used / (1024**3)
                    
                    # Proactively kill high memory processes every cycle to catch orphaned processes
                    # Use adaptive threshold: stricter when memory is low
                    threshold = (self.RESOURCE_CONFIG['max_process_memory_mb_warning'] 
                                if memory_available_gb < self.RESOURCE_CONFIG['memory_warning_available_gb']
                                else self.RESOURCE_CONFIG['max_process_memory_mb'])
                    self._kill_high_memory_processes(threshold_mb=threshold)
                    
                    if status == 'critical':
                        self._handle_critical_resources(cpu_percent, max_cpu, avg_cpu, memory_percent, memory_available_gb, memory.total, memory.used)
                    elif status == 'warning':
                        self._handle_warning_resources()
                        # Log CPU breakdown on warnings to diagnose resource usage
                        self._log_cpu_usage_by_process_type()
                    
                except (ImportError, AttributeError) as e:
                    print(f"[WARN] psutil not available, skipping resource monitoring: {e}", file=sys.stderr)
                    break
                
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
            except Exception as e:
                print(f"[WARN] Error in resource monitoring: {e}", file=sys.stderr)
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
    
    def _kill_high_memory_processes(self, threshold_mb: Optional[float] = None):
        """Kill processes exceeding RAM threshold using recursive descendant tracking.
        Catches orphaned solver processes that typefuzz doesn't clean up properly.
        
        Args:
            threshold_mb: RAM threshold in MB (defaults to max_process_memory_mb)
        """
        if threshold_mb is None:
            threshold_mb = self.RESOURCE_CONFIG['max_process_memory_mb']
        
        # Threshold for reporting which test caused the issue (14GB = 14336MB)
        HIGH_MEMORY_REPORT_THRESHOLD_MB = 14336
        
        try:
            # Get all tracked PIDs (main, workers, and all descendants)
            main_pid = os.getpid()
            worker_pids = {}
            if hasattr(self, 'workers'):
                for worker_id, w in enumerate(self.workers, start=1):
                    try:
                        worker_pids[w.pid] = worker_id
                    except (AttributeError, ValueError):
                        pass
            
            # Build mapping: pid -> worker_id (for finding which worker spawned a process)
            pid_to_worker = {}
            tracked_pids = {main_pid}
            tracked_pids.update(worker_pids.keys())
            for pid in list(tracked_pids):
                # Find which worker this PID belongs to
                worker_id = worker_pids.get(pid)
                descendants = self._get_all_descendant_pids(pid)
                tracked_pids.update(descendants)
                if worker_id:
                    for desc_pid in descendants:
                        pid_to_worker[desc_pid] = worker_id
            
            killed_count = 0
            for pid in tracked_pids:
                try:
                    proc = psutil.Process(pid)
                    rss_mb = proc.memory_info().rss / (1024 * 1024)
                    
                    if rss_mb > threshold_mb:
                        name = proc.name()
                        cmdline = ' '.join(proc.cmdline()[:3])  # First 3 args for brevity
                        print(f"[RESOURCE] Killing process {pid} ({name}) using {rss_mb:.1f}MB RAM (threshold: {threshold_mb}MB)", file=sys.stderr)
                        print(f"  Command: {cmdline}...", file=sys.stderr)
                        
                        # If process used >= 14GB RAM, report which test caused it
                        if rss_mb >= HIGH_MEMORY_REPORT_THRESHOLD_MB:
                            worker_id = pid_to_worker.get(pid)
                            if worker_id and worker_id in self.current_tests:
                                test_name = self.current_tests[worker_id]
                                print(f"  ⚠️  HIGH RAM USAGE: Process used {rss_mb:.1f}MB RAM while processing test: {test_name}", file=sys.stderr)
                            else:
                                print(f"  ⚠️  HIGH RAM USAGE: Process used {rss_mb:.1f}MB RAM (could not determine test)", file=sys.stderr)
                        
                        proc.kill()
                        killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, AttributeError):
                    pass
            
            if killed_count > 0:
                print(f"[RESOURCE] Killed {killed_count} process(es) exceeding {threshold_mb}MB RAM threshold", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Error killing high RAM processes: {e}", file=sys.stderr)
    
    def _handle_warning_resources(self):
        """Handle warning-level resource usage - just log CPU breakdown"""
        # Process killing already happens every cycle, no need to duplicate here
        pass
    
    def _get_all_descendant_pids(self, pid):
        """Recursively get all descendant PIDs of a process"""
        descendant_pids = set()
        try:
            proc = psutil.Process(pid)
            for child in proc.children(recursive=True):
                try:
                    descendant_pids.add(child.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return descendant_pids
    
    def _log_cpu_usage_by_process_type(self):
        """Log CPU usage breakdown by process type (typefuzz, z3, cvc5, python)"""
        try:
            main_pid = os.getpid()
            worker_pids = set()
            if hasattr(self, 'workers'):
                for w in self.workers:
                    try:
                        worker_pids.add(w.pid)
                    except (AttributeError, ValueError):
                        pass
            
            # Build set of all PIDs we should track (main, workers, and all their descendants)
            tracked_pids = {main_pid}
            tracked_pids.update(worker_pids)
            for pid in list(tracked_pids):
                tracked_pids.update(self._get_all_descendant_pids(pid))
            
            process_stats = {
                'typefuzz': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'z3': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'cvc5': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'python': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
                'other': {'count': 0, 'cpu_total': 0.0, 'memory_total_mb': 0.0},
            }
            
            # First pass: get CPU percent (need to call it once to initialize, then wait a bit)
            cpu_cache = {}
            for pid in tracked_pids:
                try:
                    proc = psutil.Process(pid)
                    proc.cpu_percent()  # Initialize CPU tracking
                    cpu_cache[pid] = proc
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Wait a short time for CPU percent to be calculated
            time.sleep(0.1)
            
            # Second pass: collect actual stats
            for pid in tracked_pids:
                try:
                    proc = cpu_cache.get(pid)
                    if not proc:
                        proc = psutil.Process(pid)
                    
                    proc_info = proc.as_dict(['name', 'memory_info', 'cmdline'])
                    
                    # Get CPU percent (now should have a value)
                    try:
                        cpu_pct = proc.cpu_percent(interval=None)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cpu_pct = 0.0
                    
                    rss_mb = proc_info.get('memory_info', {}).rss / (1024 * 1024) if proc_info.get('memory_info') else 0.0
                    cmdline = ' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else ''
                    name = (proc_info.get('name') or '').lower()
                    
                    # Categorize process
                    if 'typefuzz' in cmdline.lower() or 'typefuzz' in name:
                        process_stats['typefuzz']['count'] += 1
                        process_stats['typefuzz']['cpu_total'] += cpu_pct
                        process_stats['typefuzz']['memory_total_mb'] += rss_mb
                    elif 'z3' in cmdline.lower() or 'z3' in name:
                        process_stats['z3']['count'] += 1
                        process_stats['z3']['cpu_total'] += cpu_pct
                        process_stats['z3']['memory_total_mb'] += rss_mb
                    elif 'cvc5' in cmdline.lower() or 'cvc5' in name:
                        process_stats['cvc5']['count'] += 1
                        process_stats['cvc5']['cpu_total'] += cpu_pct
                        process_stats['cvc5']['memory_total_mb'] += rss_mb
                    elif 'python' in name or 'python' in cmdline.lower():
                        process_stats['python']['count'] += 1
                        process_stats['python']['cpu_total'] += cpu_pct
                        process_stats['python']['memory_total_mb'] += rss_mb
                    else:
                        process_stats['other']['count'] += 1
                        process_stats['other']['cpu_total'] += cpu_pct
                        process_stats['other']['memory_total_mb'] += rss_mb
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, AttributeError):
                    pass
            
            # Get system memory for comparison
            memory = psutil.virtual_memory()
            system_memory_used_gb = memory.used / (1024**3)
            tracked_memory_mb = sum(stats['memory_total_mb'] for stats in process_stats.values())
            
            # Log the breakdown
            print(f"[RESOURCE] CPU usage by process type:", file=sys.stderr)
            total_cpu = 0.0
            for proc_type, stats in process_stats.items():
                if stats['count'] > 0:
                    print(f"  {proc_type}: {stats['count']} process(es), {stats['cpu_total']:.1f}% CPU, {stats['memory_total_mb']:.1f} MB", file=sys.stderr)
                    total_cpu += stats['cpu_total']
            print(f"  Total tracked: {total_cpu:.1f}% CPU, {tracked_memory_mb:.1f} MB RAM", file=sys.stderr)
            print(f"  System total: {system_memory_used_gb:.2f} GB RAM used ({memory.percent:.1f}%)", file=sys.stderr)
            print(f"  RAM gap: {system_memory_used_gb * 1024 - tracked_memory_mb:.1f} MB not tracked (likely other system processes)", file=sys.stderr)
            
        except Exception as e:
            print(f"[WARN] Error logging CPU usage by process type: {e}", file=sys.stderr)
    
    def _handle_critical_resources(self, cpu_percent: List[float], max_cpu: float, avg_cpu: float, memory_percent: float, memory_available_gb: float, memory_total: int, memory_used: int):
        try:
            memory_total_gb = memory_total / (1024**3)
            memory_used_gb = memory_used / (1024**3)
            
            issues = []
            if avg_cpu >= self.RESOURCE_CONFIG['cpu_critical']:
                cpu_details = ", ".join([f"core{i+1}:{p:.1f}%" for i, p in enumerate(cpu_percent)])
                issues.append(f"CPU: {avg_cpu:.1f}% avg, {max_cpu:.1f}% max ({cpu_details}, critical: {self.RESOURCE_CONFIG['cpu_critical']}%)")
            if memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']:
                issues.append(f"RAM: {memory_available_gb:.2f}GB available (critical threshold: {self.RESOURCE_CONFIG['memory_critical_available_gb']}GB) - {memory_percent:.1f}% used ({memory_used_gb:.2f}GB / {memory_total_gb:.2f}GB)")
            
            if issues:
                print(f"[RESOURCE] Critical resource usage detected - {', '.join(issues)} - taking action", file=sys.stderr)
            else:
                print(f"[RESOURCE] Critical resource usage detected - CPU: {avg_cpu:.1f}% avg, {max_cpu:.1f}% max, RAM: {memory_available_gb:.2f}GB available ({memory_percent:.1f}% used, {memory_used_gb:.2f}GB / {memory_total_gb:.2f}GB) - taking action", file=sys.stderr)
            
            # Log CPU usage breakdown by process type
            self._log_cpu_usage_by_process_type()
        except Exception as e:
            print(f"[RESOURCE] Critical resource usage detected - CPU: {avg_cpu:.1f}% avg, RAM available: {memory_available_gb:.2f}GB - taking action (error formatting details: {e})", file=sys.stderr)
        
        # If RAM is critical (low available), stop immediately to preserve bugs
        if memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']:
            self._log_bugs_summary_and_stop()
            return
        
        with self.resource_lock:
            self.resource_state['paused'] = True
        
        try:
            gc.collect()
        except Exception:
            pass
        
        # Process killing already happens every cycle, no need to duplicate here
        # Just pause to let system recover
        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
        
        with self.resource_lock:
            self.resource_state['paused'] = False
    
    def _calculate_folder_size_mb(self, folder_path: Path) -> float:
        """Calculate total size of a folder in MB"""
        try:
            if folder_path.exists():
                size_bytes = sum(f.stat().st_size for f in folder_path.rglob('*') if f.is_file())
                return size_bytes / (1024 * 1024)
            else:
                return 0.0
        except Exception:
            return 0.0
    
    def _log_bugs_summary_and_stop(self):
        """Log bugs summary from all folders and stop gracefully"""
        print("\n" + "=" * 60, file=sys.stderr)
        print("CRITICAL RAM DETECTED - STOPPING TO PRESERVE BUGS", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        
        # Collect bugs from main bugs folder
        main_bugs = self._collect_bug_files(self.bugs_folder)
        main_bug_count = len(main_bugs)
        main_bugs_size_mb = self._calculate_folder_size_mb(self.bugs_folder)
        
        # Collect info from all worker folders
        total_worker_bugs = 0
        worker_folders_info = []
        for worker_id in range(1, self.num_workers + 1):
            worker_bugs_folder = self.bugs_folder / f"worker_{worker_id}"
            worker_bugs = self._collect_bug_files(worker_bugs_folder)
            worker_bug_count = len(worker_bugs)
            total_worker_bugs += worker_bug_count
            
            # Calculate sizes for all worker folders
            bugs_size_mb = self._calculate_folder_size_mb(worker_bugs_folder)
            scratch_folder = Path(f"scratch_{worker_id}")
            scratch_size_mb = self._calculate_folder_size_mb(scratch_folder)
            log_folder = Path(f"logs_{worker_id}")
            log_size_mb = self._calculate_folder_size_mb(log_folder)
            
            worker_folders_info.append({
                'id': worker_id,
                'bugs': worker_bug_count,
                'bugs_size_mb': bugs_size_mb,
                'scratch_size_mb': scratch_size_mb,
                'log_size_mb': log_size_mb,
                'total_size_mb': bugs_size_mb + scratch_size_mb + log_size_mb
            })
        
        total_bugs = main_bug_count + total_worker_bugs
        
        print(f"\nBUGS SUMMARY:", file=sys.stderr)
        print(f"  Total bugs found: {total_bugs}", file=sys.stderr)
        print(f"  Main bugs folder: {main_bug_count} bugs, {main_bugs_size_mb:.2f} MB disk space", file=sys.stderr)
        print(f"  Worker folders:", file=sys.stderr)
        for info in worker_folders_info:
            print(f"    worker_{info['id']}:", file=sys.stderr)
            print(f"      bugs: {info['bugs']} bugs, {info['bugs_size_mb']:.2f} MB disk space", file=sys.stderr)
            print(f"      scratch: {info['scratch_size_mb']:.2f} MB disk space", file=sys.stderr)
            print(f"      logs: {info['log_size_mb']:.2f} MB disk space", file=sys.stderr)
            print(f"      total: {info['total_size_mb']:.2f} MB disk space", file=sys.stderr)
        
        print(f"\nSTATISTICS:", file=sys.stderr)
        print(f"  Tests processed: {self.stats.get('tests_processed', 0)}", file=sys.stderr)
        print(f"  Bugs found: {self.stats.get('bugs_found', 0)}", file=sys.stderr)
        print(f"  Tests requeued (bugs found): {self.stats.get('tests_requeued', 0)}", file=sys.stderr)
        print(f"  Tests removed (unsupported): {self.stats.get('tests_removed_unsupported', 0)}", file=sys.stderr)
        print(f"  Tests removed (timeout): {self.stats.get('tests_removed_timeout', 0)}", file=sys.stderr)
        
        print("\n" + "=" * 60, file=sys.stderr)
        print("Stopping fuzzer to preserve found bugs...", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        
        # Stop all workers gracefully
        self.shutdown_event.set()
    
    def _check_resource_state(self) -> str:
        with self.resource_lock:
            return self.resource_state.get('status', 'normal')
    
    def _is_paused(self) -> bool:
        with self.resource_lock:
            return self.resource_state.get('paused', False)
    
    def _get_solver_clis(self) -> str:
        z3_memory_mb = self.RESOURCE_CONFIG['z3_memory_limit_mb']
        solvers = [f"{self.z3_path} smt.threads=1 memory_max_size={z3_memory_mb} model_validate=true"]
        # if self.z3_old_path:
        #     solvers.append(str(self.z3_old_path))
        # CVC5: No built-in memory limit - rely on our process killing mechanism (max_process_memory_mb)
        if self.cvc5_path:
            solvers.append(f"{self.cvc5_path} --check-models --check-proofs --strings-exp")
        # if self.cvc4_path:
        #     solvers.append(str(self.cvc4_path))
        return ";".join(solvers)
    
    def _compute_time_remaining(self, job_start_time: float, stop_buffer_minutes: int) -> int:
        GITHUB_TIMEOUT = 21600
        MIN_REMAINING = 600
        
        build_time = self.start_time - job_start_time
        stop_buffer_seconds = stop_buffer_minutes * 60
        available_time = GITHUB_TIMEOUT - build_time
        remaining = available_time - stop_buffer_seconds
        
        if remaining < MIN_REMAINING:
            print(f"[DEBUG] Computed remaining time ({remaining}s) is less than minimum ({MIN_REMAINING}s), using {MIN_REMAINING}s")
            remaining = MIN_REMAINING
        
        return int(remaining)
    
    def _get_time_remaining(self) -> float:
        if self.time_remaining is None:
            return float('inf')
        return max(0.0, self.time_remaining - (time.time() - self.start_time))
    
    def _is_time_expired(self) -> bool:
        return self.time_remaining is not None and self._get_time_remaining() <= 0
    
    def _collect_bug_files(self, folder: Path) -> List[Path]:
        if not folder.exists():
            return []
        return list(folder.glob("*.smt2")) + list(folder.glob("*.smt"))
    
    def _run_typefuzz(
        self,
        test_name: str,
        worker_id: int,
        per_test_timeout: Optional[float] = None,
    ) -> Tuple[int, List[Path], float]:
        test_path = self.tests_root / test_name
        if not test_path.exists():
            print(f"[WORKER {worker_id}] Error: Test file not found: {test_path}", file=sys.stderr)
            return (1, [], 0.0)
        
        bugs_folder = self.bugs_folder / f"worker_{worker_id}"
        scratch_folder = Path(f"scratch_{worker_id}")
        log_folder = Path(f"logs_{worker_id}")
        
        for folder in [scratch_folder, log_folder]:
            shutil.rmtree(folder, ignore_errors=True)
            folder.mkdir(parents=True, exist_ok=True)
        bugs_folder.mkdir(parents=True, exist_ok=True)
        
        solver_clis = self._get_solver_clis()
        
        cmd = [
            "typefuzz",
            "-i", str(self.iterations),
            "-m", str(self.modulo),
            "--seed", str(self.seed),
            "--timeout", "120",
            "--bugs", str(bugs_folder),
            "--scratch", str(scratch_folder),
            "--logfolder", str(log_folder),
            solver_clis,
            str(test_path),
        ]
        
        print(f"[WORKER {worker_id}] Running typefuzz on: {test_name} (timeout: {per_test_timeout}s)" if per_test_timeout else f"[WORKER {worker_id}] Running typefuzz on: {test_name}")
        
        start_time = time.time()
        
        try:
            if per_test_timeout and per_test_timeout > 0:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=per_test_timeout)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True)
            
            exit_code = result.returncode
            runtime = time.time() - start_time
            bug_files = self._collect_bug_files(bugs_folder)
            return (exit_code, bug_files, runtime)
            
        except subprocess.TimeoutExpired:
            runtime = time.time() - start_time
            return (124, [], runtime)
        except Exception:
            runtime = time.time() - start_time
            return (1, [], runtime)
        finally:
            for folder in [scratch_folder, log_folder]:
                shutil.rmtree(folder, ignore_errors=True)
    
    def _handle_exit_code(
        self,
        test_name: str,
        exit_code: int,
        bug_files: List[Path],
        runtime: float,
        worker_id: int,
    ) -> str:
        if exit_code == self.EXIT_CODE_BUGS_FOUND:
            if bug_files:
                print(f"[WORKER {worker_id}] ✓ Exit code 10: Found {len(bug_files)} bug(s) on {test_name}")
                with self.bugs_lock:
                    for bug_file in bug_files:
                        try:
                            dest = self.bugs_folder / bug_file.name
                            if dest.exists():
                                timestamp = int(time.time())
                                dest = self.bugs_folder / f"{bug_file.stem}_{timestamp}{bug_file.suffix}"
                            shutil.move(str(bug_file), str(dest))
                            self.stats['bugs_found'] += 1
                        except Exception as e:
                            print(f"[WORKER {worker_id}] Warning: Failed to move bug file {bug_file}: {e}", file=sys.stderr)
            else:
                print(f"[WORKER {worker_id}] Warning: Exit code 10 but no bugs found for {test_name}", file=sys.stderr)
            return 'requeue'
        
        elif exit_code == self.EXIT_CODE_UNSUPPORTED:
            print(f"[WORKER {worker_id}] ⚠ Exit code 3: {test_name} (unsupported operation - removing)")
            self.stats['tests_removed_unsupported'] += 1
            return 'remove'
        
        elif exit_code == self.EXIT_CODE_SUCCESS:
            if not bug_files:
                print(f"[WORKER {worker_id}] Exit code 0: No bugs found on {test_name} (runtime: {runtime:.1f}s) - requeuing for next cycle")
                # Always requeue to create ring/queue behavior - tests cycle continuously until time expires
                return 'requeue'
            else:
                print(f"[WORKER {worker_id}] Exit code 0: {test_name} (runtime: {runtime:.1f}s) - bugs found, requeuing")
                return 'requeue'
        
        else:
            return 'continue'
    
    def _worker_process(self, worker_id: int):
        print(f"[WORKER {worker_id}] Started")
        
        while not self.shutdown_event.is_set():
            try:
                if self._is_paused():
                    resource_status = self._check_resource_state()
                    print(f"[WORKER {worker_id}] Paused due to {resource_status} resource usage", file=sys.stderr)
                    time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                    continue
                
                try:
                    test_name = self.test_queue.get(timeout=1.0)
                except Exception:
                    if self.shutdown_event.is_set() or self._is_time_expired():
                        break
                    continue
                
                if self._is_time_expired():
                    try:
                        self.test_queue.put(test_name)
                    except Exception:
                        pass
                    break
                
                resource_status = self._check_resource_state()
                if resource_status == 'warning':
                    time.sleep(2)
                elif resource_status == 'critical':
                    try:
                        self.test_queue.put(test_name)
                    except Exception:
                        pass
                    time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                    continue
                
                # Track which test this worker is currently processing
                self.current_tests[worker_id] = test_name
                
                time_remaining = self._get_time_remaining()
                exit_code, bug_files, runtime = self._run_typefuzz(
                    test_name,
                    worker_id,
                    per_test_timeout=time_remaining if self.time_remaining and time_remaining > 0 else None,
                )
                
                # Clear test tracking after processing
                if worker_id in self.current_tests:
                    del self.current_tests[worker_id]
                
                action = self._handle_exit_code(test_name, exit_code, bug_files, runtime, worker_id)
                
                if action == 'requeue':
                    try:
                        self.test_queue.put(test_name)
                        self.stats['tests_requeued'] += 1
                    except Exception:
                        pass
                
                self.stats['tests_processed'] += 1
                
            except Exception as e:
                print(f"[WORKER {worker_id}] Error in worker: {e}", file=sys.stderr)
                continue
        
        print(f"[WORKER {worker_id}] Stopped")
    
    def run(self):
        if not self.tests:
            print(f"No tests provided{' for job ' + self.job_id if self.job_id else ''}")
            return
        
        print(f"Running fuzzer on {len(self.tests)} test(s){' for job ' + self.job_id if self.job_id else ''}")
        print(f"Tests root: {self.tests_root}")
        print(f"Timeout: {self.time_remaining}s ({self.time_remaining // 60} minutes)" if self.time_remaining else "No timeout")
        print(f"Iterations per test: {self.iterations}, Modulo: {self.modulo}")
        print(f"CPU cores: {self.cpu_count}")
        print(f"Workers: {self.num_workers}")
        z3_memory_mb = self.RESOURCE_CONFIG['z3_memory_limit_mb']
        z3_cmd = f"{self.z3_path} smt.threads=1 memory_max_size={z3_memory_mb} model_validate=true"
        cvc5_cmd = f"{self.cvc5_path} --check-models --check-proofs --strings-exp" if self.cvc5_path else "None"
        print(f"Solvers: z3={z3_cmd}, cvc5={cvc5_cmd}")
        print()
        
        for test in self.tests:
            self.test_queue.put(test)
        
        workers = []
        for worker_id in range(1, self.num_workers + 1):
            worker = multiprocessing.Process(target=self._worker_process, args=(worker_id,))
            worker.start()
            workers.append(worker)
        
        self.workers = workers
        
        monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        monitor_thread.start()
        print("[DEBUG] Resource monitoring started")
        
        def signal_handler(signum, frame):
            print("\n⏰ Shutdown signal received, stopping workers...")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            if self.time_remaining:
                end_time = self.start_time + self.time_remaining
                while time.time() < end_time and any(w.is_alive() for w in workers):
                    time.sleep(1)
                if time.time() >= end_time:
                    print("⏰ Timeout reached, stopping workers...")
                    self.shutdown_event.set()
            else:
                for worker in workers:
                    worker.join()
        except KeyboardInterrupt:
            print("\n⏰ Interrupted, stopping workers...")
            self.shutdown_event.set()
        
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker_pid = getattr(worker, 'pid', 'unknown')
                print(f"Warning: Worker {worker_pid} did not terminate, killing...")
                worker.terminate()
                worker.join(timeout=2)
                if worker.is_alive():
                    worker.kill()
        
        for worker_id in range(1, self.num_workers + 1):
            worker_bugs = self.bugs_folder / f"worker_{worker_id}"
            for bug_file in self._collect_bug_files(worker_bugs):
                try:
                    dest = self.bugs_folder / bug_file.name
                    if dest.exists():
                        timestamp = int(time.time())
                        dest = self.bugs_folder / f"{bug_file.stem}_{timestamp}{bug_file.suffix}"
                    shutil.move(str(bug_file), str(dest))
                except Exception:
                    pass
        
        print()
        print("=" * 60)
        print(f"FINAL BUG SUMMARY{' FOR JOB ' + self.job_id if self.job_id else ''}")
        print("=" * 60)
        
        bug_files = self._collect_bug_files(self.bugs_folder)
        if bug_files:
            print(f"\nFound {len(bug_files)} bug(s):")
            for i, bug_file in enumerate(bug_files, 1):
                print(f"\nBug #{i}: {bug_file}")
                print("-" * 60)
                try:
                    with open(bug_file, 'r') as f:
                        print(f.read())
                except Exception as e:
                    print(f"Error reading bug file: {e}")
                print("-" * 60)
        else:
            print("No bugs found.")
        
        print()
        print("Statistics:")
        print(f"  Tests processed: {self.stats.get('tests_processed', 0)}")
        print(f"  Bugs found: {self.stats.get('bugs_found', 0)}")
        print(f"  Tests requeued (bugs found): {self.stats.get('tests_requeued', 0)}")
        print(f"  Tests removed (unsupported): {self.stats.get('tests_removed_unsupported', 0)}")
        print(f"  Tests removed (timeout): {self.stats.get('tests_removed_timeout', 0)}")
        print("=" * 60)


def analyze_fuzzing_coverage(
    changed_functions: Path,
    build_dir: Path,
    output_statistics: Path,
    job_id: Optional[str] = None,
    commit_hash: Optional[str] = None,
):
    """Collect coverage with fastcov and analyze changed functions"""
    import tempfile
    
    # Debug: Check for .gcda files before running fastcov
    print(f"[DEBUG] Checking for coverage files in {build_dir}...")
    gcda_files = list(build_dir.rglob("*.gcda"))
    gcno_files = list(build_dir.rglob("*.gcno"))
    print(f"[DEBUG] Found {len(gcda_files)} .gcda files and {len(gcno_files)} .gcno files")
    if gcda_files:
        print(f"[DEBUG] Sample .gcda files (first 5):")
        for gcda in gcda_files[:5]:
            print(f"[DEBUG]   - {gcda}")
    else:
        print(f"[DEBUG] WARNING: No .gcda files found! Coverage data may not be available.")
        print(f"[DEBUG] This could mean:")
        print(f"[DEBUG]   1. The binary was not instrumented for coverage")
        print(f"[DEBUG]   2. The binary was not executed (no coverage data generated)")
        print(f"[DEBUG]   3. .gcda files are in a different location")
    
    # Run fastcov to collect coverage
    fastcov_output = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    fastcov_output.close()
    fastcov_path = Path(fastcov_output.name)
    
    try:
        print(f"[INFO] Running fastcov on {build_dir}...")
        print(f"[DEBUG] Working directory: {build_dir.parent}")
        print(f"[DEBUG] Sample .gcda file paths (first 3):")
        for gcda in gcda_files[:3]:
            print(f"[DEBUG]   - {gcda}")
        
        # Match cvc5 exactly: run from build_dir.parent with --search-directory as str(build_dir)
        # This works because both cvc5 and z3 workflows now use working-directory and relative paths
        result = subprocess.run([
            "fastcov", "--gcov", "gcov",
            "--search-directory", str(build_dir),
            "--output", str(fastcov_path),
            "--exclude", "/usr/include/*",
            "--exclude", "*/deps/*",
            "--jobs", "4"
        ], cwd=build_dir.parent, capture_output=True, text=True, check=False)
        
        # Debug: Check if fastcov produced a JSON file even if it failed
        if fastcov_path.exists():
            file_size = fastcov_path.stat().st_size
            print(f"[DEBUG] fastcov output file exists: {fastcov_path} (size: {file_size} bytes)")
            if file_size > 0:
                try:
                    with open(fastcov_path, 'r') as f:
                        fastcov_data = json.load(f)
                    print(f"[DEBUG] fastcov JSON structure: {list(fastcov_data.keys())}")
                    if 'sources' in fastcov_data:
                        print(f"[DEBUG] Found {len(fastcov_data['sources'])} source files in fastcov JSON")
                except Exception as e:
                    print(f"[DEBUG] Could not parse fastcov JSON: {e}")
        else:
            print(f"[DEBUG] fastcov output file does not exist")
        
        if result.returncode != 0:
            print(f"[ERROR] fastcov failed (exit code {result.returncode})", file=sys.stderr)
            print(f"[ERROR] fastcov stdout: {result.stdout}", file=sys.stderr)
            print(f"[ERROR] fastcov stderr: {result.stderr}", file=sys.stderr)
            # Create empty statistics
            stats = {
                "functions": []
            }
            if job_id:
                stats['job_id'] = job_id
            if commit_hash:
                stats['commit_hash'] = commit_hash
            with open(output_statistics, 'w') as f:
                json.dump(stats, f, indent=2)
            return
        
        # Verify fastcov JSON file is valid and has data
        if not fastcov_path.exists():
            print(f"[ERROR] fastcov succeeded but output file does not exist: {fastcov_path}", file=sys.stderr)
            stats = {
                "functions": []
            }
            if job_id:
                stats['job_id'] = job_id
            if commit_hash:
                stats['commit_hash'] = commit_hash
            with open(output_statistics, 'w') as f:
                json.dump(stats, f, indent=2)
            return
        
        # Try to load and validate the JSON
        try:
            with open(fastcov_path, 'r') as f:
                fastcov_data = json.load(f)
            if 'sources' not in fastcov_data or len(fastcov_data.get('sources', {})) == 0:
                print(f"[WARNING] fastcov JSON has no source files. Coverage data may be empty.", file=sys.stderr)
                print(f"[WARNING] This could mean no functions were executed during fuzzing.", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"[ERROR] fastcov produced invalid JSON: {e}", file=sys.stderr)
            stats = {
                "functions": []
            }
            if job_id:
                stats['job_id'] = job_id
            if commit_hash:
                stats['commit_hash'] = commit_hash
            with open(output_statistics, 'w') as f:
                json.dump(stats, f, indent=2)
            return
        
        # Run analyze script
        print(f"[INFO] Analyzing coverage...")
        script_dir = Path(__file__).parent
        analyze_script = script_dir / "analyze_fuzzing_coverage.py"
        
        if not analyze_script.exists():
            print(f"[ERROR] analyze_fuzzing_coverage.py not found at {analyze_script}", file=sys.stderr)
            sys.exit(1)
        
        cmd = [
            sys.executable, str(analyze_script),
            "--changed-functions", str(changed_functions),
            "--fastcov-json", str(fastcov_path),
            "--output", str(output_statistics),
            "--debug",  # Enable debug output to diagnose matching issues
        ]
        if job_id:
            cmd.extend(["--job-id", job_id])
        if commit_hash:
            cmd.extend(["--commit-hash", commit_hash])
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"[ERROR] Coverage analysis failed: {result.stderr}", file=sys.stderr)
            print(f"[ERROR] Coverage analysis stdout: {result.stdout}", file=sys.stderr)
        else:
            print(result.stdout)
    
    finally:
        # Clean up temp file
        try:
            fastcov_path.unlink()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Simple commit fuzzer that runs typefuzz on tests with multiple solvers"
    )
    parser.add_argument(
        "--tests-json",
        required=True,
        help="JSON array of test names (relative to --tests-root)",
    )
    parser.add_argument(
        "--job-id",
        help="Job identifier (optional, for logging)",
    )
    parser.add_argument(
        "--tests-root",
        default="test/regress/cli",
        help="Root directory for tests (default: test/regress/cli)",
    )
    parser.add_argument(
        "--time-remaining",
        type=int,
        help="Remaining time until job timeout in seconds (legacy, use --job-start-time instead)",
    )
    parser.add_argument(
        "--job-start-time",
        type=float,
        help="Unix timestamp when the job started (for automatic time calculation)",
    )
    parser.add_argument(
        "--stop-buffer-minutes",
        type=int,
        default=5,
        help="Minutes before timeout to stop (default: 5, can be set higher for testing)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=250,
        help="Number of iterations per test (default: 250)",
    )
    parser.add_argument(
        "--modulo",
        type=int,
        default=2,
        help="Modulo parameter for typefuzz -m flag (default: 2)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for typefuzz --seed flag (default: 42)",
    )
    parser.add_argument(
        "--z3-old-path",
        required=False,
        help="Path to z3-4.8.7 binary (not used, commented out)",
    )
    parser.add_argument(
        "--cvc4-path",
        required=False,
        help="Path to cvc4-1.6 binary (not used, commented out)",
    )
    parser.add_argument(
        "--z3-path",
        default="./build/z3",
        help="Path to z3 binary (default: ./build/z3)",
    )
    parser.add_argument(
        "--cvc5-path",
        help="Path to cvc5 binary (for oracle, optional)",
    )
    try:
        default_workers = psutil.cpu_count()
    except Exception:
        default_workers = 4
    
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help=f"Number of worker processes (default: {default_workers}, auto-detected from CPU cores). Each worker runs typefuzz with 4 solvers",
    )
    parser.add_argument(
        "--bugs-folder",
        default="bugs",
        help="Folder to store bugs (default: bugs)",
    )
    parser.add_argument(
        "--changed-functions",
        type=Path,
        help="JSON file with changed functions list (for coverage analysis)",
    )
    parser.add_argument(
        "--build-dir",
        default="./build",
        help="Build directory for coverage analysis (default: ./build)",
    )
    parser.add_argument(
        "--output-statistics",
        type=Path,
        help="Output statistics JSON file (for coverage analysis)",
    )
    parser.add_argument(
        "--commit-hash",
        help="Commit hash for statistics output",
    )
    parser.add_argument(
        "--fuzzing-duration-minutes",
        type=float,
        default=60.0,
        help="Fuzzing duration in minutes (default: 60.0)",
    )
    
    args = parser.parse_args()
    
    # Parse tests JSON
    try:
        tests = json.loads(args.tests_json)
        if not isinstance(tests, list):
            raise ValueError("tests-json must be a JSON array")
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in --tests-json: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Calculate time_remaining from fuzzing duration if not provided
    if args.time_remaining is None and args.job_start_time is None:
        # Set time_remaining to fuzzing duration in seconds
        args.time_remaining = int(args.fuzzing_duration_minutes * 60)
        print(f"[INFO] Setting fuzzing duration to {args.fuzzing_duration_minutes} minutes ({args.time_remaining} seconds)")
    
    # Create and run fuzzer
    try:
        fuzzer = SimpleCommitFuzzer(
            tests=tests,
            tests_root=args.tests_root,
            bugs_folder=args.bugs_folder,
            num_workers=args.workers,
            iterations=args.iterations,
            modulo=args.modulo,
            seed=args.seed,
            time_remaining=args.time_remaining,
            job_start_time=args.job_start_time,
            stop_buffer_minutes=args.stop_buffer_minutes,
            z3_old_path=args.z3_old_path,
            cvc4_path=args.cvc4_path,
            z3_path=args.z3_path,
            cvc5_path=args.cvc5_path,
            job_id=args.job_id,
        )
        
        # Clear coverage data before fuzzing
        if args.changed_functions and args.output_statistics:
            print("[INFO] Clearing existing .gcda files...")
            build_dir = Path(args.build_dir)
            if build_dir.exists():
                for gcda_file in build_dir.rglob("*.gcda"):
                    try:
                        gcda_file.unlink()
                    except Exception as e:
                        print(f"[WARN] Failed to delete {gcda_file}: {e}")
        
        fuzzer.run()
        
        # Collect and analyze coverage if requested
        if args.changed_functions and args.output_statistics:
            print("[INFO] Collecting coverage data...")
            analyze_fuzzing_coverage(
                changed_functions=args.changed_functions,
                build_dir=Path(args.build_dir),
                output_statistics=args.output_statistics,
                job_id=args.job_id,
                commit_hash=args.commit_hash,
            )
        
        # Always exit with success
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        # Still exit with success to not fail the workflow
        sys.exit(0)


if __name__ == "__main__":
    main()

