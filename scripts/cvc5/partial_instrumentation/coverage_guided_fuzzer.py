#!/usr/bin/env python3
"""
Coverage-Guided Fuzzer for CVC5
Runs typefuzz with coverage-guided multi-generation mutant management.
Based on simple_commit_fuzzer_sancov.py with coverage-guided enhancements.
"""

import argparse
import gc
import heapq
import json
import mmap
import multiprocessing
import os
import psutil
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# AFL-style coverage map size (64KB bitmap)
AFL_MAP_SIZE = 65536


class CoverageGuidedFuzzer:
    """Coverage-guided fuzzer with multi-generation mutant management."""
    
    EXIT_CODE_BUGS_FOUND = 10
    EXIT_CODE_UNSUPPORTED = 3
    EXIT_CODE_SUCCESS = 0
    
    RESOURCE_CONFIG = {
        'cpu_warning': 85.0,
        'cpu_critical': 95.0,
        'memory_warning_available_gb': 2.0,
        'memory_critical_available_gb': 0.5,
        'check_interval': 2,
        'pause_duration': 10,
        'max_process_memory_mb': 2048,
        'max_process_memory_mb_warning': 1536,
        'z3_memory_limit_mb': 2048,
    }
    
    def __init__(
        self,
        tests: List[str],
        tests_root: str,
        bugs_folder: str = "bugs",
        num_workers: int = 4,
        iterations: int = 1,  # For coverage-guided: 1 iteration per test
        modulo: int = 2,
        seed: int = 42,
        time_remaining: Optional[int] = None,
        job_start_time: Optional[float] = None,
        stop_buffer_minutes: int = 5,
        cvc5_path: str = "./build/bin/cvc5",
        job_id: Optional[str] = None,
        profraw_dir: str = "./profraw",
        profdata_merge_interval: int = 100,
        output_dir: str = "./output",
    ):
        self.tests = tests
        self.tests_root = Path(tests_root)
        self.bugs_folder = Path(bugs_folder)
        self.iterations = iterations
        self.modulo = modulo
        self.seed = seed
        self.job_id = job_id
        self.start_time = time.time()
        self.output_dir = Path(output_dir)
        
        try:
            self.cpu_count = psutil.cpu_count()
        except Exception:
            self.cpu_count = 4
        
        self.num_workers = min(num_workers, self.cpu_count) if num_workers > 0 else self.cpu_count
        if num_workers > self.cpu_count:
            print(f"[WARN] Requested {num_workers} workers but only {self.cpu_count} CPU cores available, using {self.num_workers} workers", file=sys.stderr)
        
        # Time calculation
        if job_start_time is not None:
            self.time_remaining = self._compute_time_remaining(job_start_time, stop_buffer_minutes)
            build_time = self.start_time - job_start_time
            print(f"[INFO] Timeout: {self.time_remaining}s ({self.time_remaining // 60}min), build took {build_time:.0f}s")
        elif time_remaining is not None:
            self.time_remaining = time_remaining
            print(f"[INFO] Timeout: {time_remaining}s ({time_remaining // 60}min)")
        else:
            self.time_remaining = None
            print("[INFO] No timeout (running indefinitely)")
        
        # Solvers: z3 + cvc5
        z3_memory_mb = self.RESOURCE_CONFIG['z3_memory_limit_mb']
        self.z3_cmd = f"z3 smt.threads=1 memory_max_size={z3_memory_mb} model_validate=true"
        self.cvc5_path = Path(cvc5_path)
        
        self._validate_solvers()
        self.bugs_folder.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Multiprocessing primitives
        self.manager = multiprocessing.Manager()
        
        # Priority queue: sorted by (runtime, generation, path)
        # Lower runtime = higher priority (fast tests first)
        self._priority_queue = self.manager.list()  # List for heapq operations
        self._queue_lock = multiprocessing.Lock()   # Protects queue operations
        self._queue_not_empty = multiprocessing.Condition(self._queue_lock)
        
        self.bugs_lock = multiprocessing.Lock()
        self.shutdown_event = multiprocessing.Event()
        
        self.resource_state = self.manager.dict({
            'cpu_percent': [0.0] * self.cpu_count,
            'memory_percent': 0.0,
            'status': 'normal',
            'paused': False,
            'last_update': time.time(),
        })
        self.resource_lock = multiprocessing.Lock()
        
        # Track which test each worker is currently processing (for idle detection)
        # worker_id -> test_name or None if idle
        self.worker_status = self.manager.dict()
        for i in range(1, num_workers + 1):
            self.worker_status[i] = None  # All start idle
        
        self.stats = self.manager.dict({
            'tests_processed': 0,
            'bugs_found': 0,
            'tests_removed_unsupported': 0,
            'tests_removed_timeout': 0,
            'mutants_created': 0,
            'mutants_with_new_coverage': 0,
            'total_new_edges': 0,
            'generations_completed': 0,
        })
        
        # Coverage-guided: Shared coverage map (shared across all workers)
        # Tracks which edges have been seen (0xFF = unseen, 0x00 = seen)
        # Created in run() using multiprocessing.Array
        # All workers atomically check/update it using a lock
        
        # Pending mutants folder - mutants waiting to be executed
        self.pending_mutants_dir = self.output_dir / "pending_mutants"
        self.pending_mutants_dir.mkdir(parents=True, exist_ok=True)
        
        # PGO profiling
        self.profraw_dir = Path(profraw_dir)
        self.profraw_dir.mkdir(parents=True, exist_ok=True)
        self.profdata_merge_interval = profdata_merge_interval
        self.profraw_merge_counter = multiprocessing.Value('i', 0)
        
    def _validate_solvers(self):
        z3_binary = self.z3_cmd.split()[0]
        if not shutil.which(z3_binary):
            raise ValueError(f"z3 not found in PATH")
        if not self.cvc5_path.exists():
            raise ValueError(f"cvc5 not found at: {self.cvc5_path}")
    
    # -------------------------------------------------------------------------
    # Priority Queue (sorted by runtime - fastest tests first)
    # -------------------------------------------------------------------------
    
    def _queue_push(self, item: tuple):
        """Push item to priority queue. Item is (runtime, generation, path)."""
        with self._queue_lock:
            # Insert maintaining heap order
            temp_list = list(self._priority_queue)
            heapq.heappush(temp_list, item)
            self._priority_queue[:] = temp_list
            self._queue_not_empty.notify()
    
    def _queue_push_batch(self, items: list):
        """Push multiple items efficiently (single lock acquisition)."""
        with self._queue_lock:
            temp_list = list(self._priority_queue)
            for item in items:
                heapq.heappush(temp_list, item)
            self._priority_queue[:] = temp_list
            self._queue_not_empty.notify_all()  # Wake all waiting workers
    
    def _queue_push_initial(self, test_name: str):
        """Push initial test with default priority."""
        # Initial tests get priority 0 (highest), generation 0
        self._queue_push((0.0, 0, test_name))
    
    def _queue_push_initial_batch(self, test_names: list):
        """Push multiple initial tests efficiently."""
        items = [(0.0, 0, name) for name in test_names]
        queue_size_before = self._queue_size()
        self._queue_push_batch(items)
        print(f"[QUEUE] Loaded {len(items)} initial tests (queue: {queue_size_before} -> {self._queue_size()})")
    
    def _queue_pop(self, timeout: float = 1.0) -> Optional[tuple]:
        """Pop highest priority item (lowest runtime). Returns None if timeout."""
        with self._queue_lock:
            deadline = time.time() + timeout
            while len(self._priority_queue) == 0:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                # Wait for notification or timeout
                self._queue_not_empty.wait(timeout=remaining)
                if self.shutdown_event.is_set():
                    return None
            
            # Pop from heap
            temp_list = list(self._priority_queue)
            item = heapq.heappop(temp_list)
            self._priority_queue[:] = temp_list
            return item
    
    def _queue_empty(self) -> bool:
        """Check if queue is empty (non-blocking check)."""
        # Avoid lock for quick check - may have race but that's OK
        return len(self._priority_queue) == 0
    
    def _queue_size(self) -> int:
        """Get queue size."""
        return len(self._priority_queue)
    
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
    
    # -------------------------------------------------------------------------
    # Resource Management (same as simple_commit_fuzzer_sancov.py)
    # -------------------------------------------------------------------------
    
    def _monitor_resources(self):
        while not self.shutdown_event.is_set():
            try:
                try:
                    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
                    memory = psutil.virtual_memory()
                    memory_percent = memory.percent
                    memory_available_gb = memory.available / (1024**3)
                    
                    max_cpu = max(cpu_percent) if cpu_percent else 0.0
                    avg_cpu = sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0.0
                    
                    status = 'normal'
                    
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
                    
                    threshold = (self.RESOURCE_CONFIG['max_process_memory_mb_warning'] 
                                if memory_available_gb < self.RESOURCE_CONFIG['memory_warning_available_gb']
                                else self.RESOURCE_CONFIG['max_process_memory_mb'])
                    self._kill_high_memory_processes(threshold_mb=threshold)
                    
                    if status == 'critical':
                        self._handle_critical_resources(cpu_percent, max_cpu, avg_cpu, memory_percent, memory_available_gb, memory.total, memory.used)
                    elif status == 'warning':
                        self._handle_warning_resources()
                        self._log_cpu_usage_by_process_type()
                    
                except (ImportError, AttributeError) as e:
                    print(f"[WARN] psutil not available, skipping resource monitoring: {e}", file=sys.stderr)
                    break
                
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
            except Exception as e:
                print(f"[WARN] Error in resource monitoring: {e}", file=sys.stderr)
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
    
    def _kill_high_memory_processes(self, threshold_mb: Optional[float] = None):
        if threshold_mb is None:
            threshold_mb = self.RESOURCE_CONFIG['max_process_memory_mb']
        
        HIGH_MEMORY_REPORT_THRESHOLD_MB = 14336
        
        try:
            main_pid = os.getpid()
            worker_pids = {}
            if hasattr(self, 'workers'):
                for worker_id, w in enumerate(self.workers, start=1):
                    try:
                        worker_pids[w.pid] = worker_id
                    except (AttributeError, ValueError):
                        pass
            
            pid_to_worker = {}
            tracked_pids = {main_pid}
            tracked_pids.update(worker_pids.keys())
            for pid in list(tracked_pids):
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
                        cmdline = ' '.join(proc.cmdline()[:3])
                        print(f"[RESOURCE] Killing process {pid} ({name}) using {rss_mb:.1f}MB RAM (threshold: {threshold_mb}MB)", file=sys.stderr)
                        print(f"  Command: {cmdline}...", file=sys.stderr)
                        
                        if rss_mb >= HIGH_MEMORY_REPORT_THRESHOLD_MB:
                            worker_id = pid_to_worker.get(pid)
                            if worker_id and self.worker_status.get(worker_id):
                                test_name = self.worker_status[worker_id]
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
        pass
    
    def _get_all_descendant_pids(self, pid):
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
        try:
            main_pid = os.getpid()
            worker_pids = set()
            if hasattr(self, 'workers'):
                for w in self.workers:
                    try:
                        worker_pids.add(w.pid)
                    except (AttributeError, ValueError):
                        pass
            
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
            
            cpu_cache = {}
            for pid in tracked_pids:
                try:
                    proc = psutil.Process(pid)
                    proc.cpu_percent()
                    cpu_cache[pid] = proc
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            time.sleep(0.1)
            
            for pid in tracked_pids:
                try:
                    proc = cpu_cache.get(pid)
                    if not proc:
                        proc = psutil.Process(pid)
                    
                    proc_info = proc.as_dict(['name', 'memory_info', 'cmdline'])
                    
                    try:
                        cpu_pct = proc.cpu_percent(interval=None)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cpu_pct = 0.0
                    
                    rss_mb = proc_info.get('memory_info', {}).rss / (1024 * 1024) if proc_info.get('memory_info') else 0.0
                    cmdline = ' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else ''
                    name = (proc_info.get('name') or '').lower()
                    
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
            
            memory = psutil.virtual_memory()
            system_memory_used_gb = memory.used / (1024**3)
            tracked_memory_mb = sum(stats['memory_total_mb'] for stats in process_stats.values())
            
            print(f"[RESOURCE] CPU usage by process type:", file=sys.stderr)
            total_cpu = 0.0
            for proc_type, stats in process_stats.items():
                if stats['count'] > 0:
                    print(f"  {proc_type}: {stats['count']} process(es), {stats['cpu_total']:.1f}% CPU, {stats['memory_total_mb']:.1f} MB", file=sys.stderr)
                    total_cpu += stats['cpu_total']
            print(f"  Total tracked: {total_cpu:.1f}% CPU, {tracked_memory_mb:.1f} MB RAM", file=sys.stderr)
            print(f"  System total: {system_memory_used_gb:.2f} GB RAM used ({memory.percent:.1f}%)", file=sys.stderr)
            
        except Exception as e:
            print(f"[WARN] Error logging CPU usage by process type: {e}", file=sys.stderr)
    
    def _handle_critical_resources(self, cpu_percent: List[float], max_cpu: float, avg_cpu: float, memory_percent: float, memory_available_gb: float, memory_total: int, memory_used: int):
        try:
            memory_total_gb = memory_total / (1024**3)
            memory_used_gb = memory_used / (1024**3)
            
            issues = []
            if avg_cpu >= self.RESOURCE_CONFIG['cpu_critical']:
                cpu_details = ", ".join([f"core{i+1}:{p:.1f}%" for i, p in enumerate(cpu_percent)])
                issues.append(f"CPU: {avg_cpu:.1f}% avg, {max_cpu:.1f}% max ({cpu_details})")
            if memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']:
                issues.append(f"RAM: {memory_available_gb:.2f}GB available ({memory_percent:.1f}% used)")
            
            if issues:
                print(f"[RESOURCE] Critical resource usage detected - {', '.join(issues)} - taking action", file=sys.stderr)
            
            self._log_cpu_usage_by_process_type()
        except Exception as e:
            print(f"[RESOURCE] Critical resource usage detected - error formatting details: {e}", file=sys.stderr)
        
        if memory_available_gb < self.RESOURCE_CONFIG['memory_critical_available_gb']:
            self._log_bugs_summary_and_stop()
            return
        
        with self.resource_lock:
            self.resource_state['paused'] = True
        
        try:
            gc.collect()
        except Exception:
            pass
        
        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
        
        with self.resource_lock:
            self.resource_state['paused'] = False
    
    def _calculate_folder_size_mb(self, folder_path: Path) -> float:
        try:
            if folder_path.exists():
                size_bytes = sum(f.stat().st_size for f in folder_path.rglob('*') if f.is_file())
                return size_bytes / (1024 * 1024)
            else:
                return 0.0
        except Exception:
            return 0.0
    
    def _log_bugs_summary_and_stop(self):
        print("\n" + "=" * 60, file=sys.stderr)
        print("CRITICAL RAM DETECTED - STOPPING TO PRESERVE BUGS", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        
        main_bugs = self._collect_bug_files(self.bugs_folder)
        main_bug_count = len(main_bugs)
        main_bugs_size_mb = self._calculate_folder_size_mb(self.bugs_folder)
        
        total_worker_bugs = 0
        worker_folders_info = []
        for worker_id in range(1, self.num_workers + 1):
            worker_bugs_folder = self.bugs_folder / f"worker_{worker_id}"
            worker_bugs = self._collect_bug_files(worker_bugs_folder)
            worker_bug_count = len(worker_bugs)
            total_worker_bugs += worker_bug_count
            
            bugs_size_mb = self._calculate_folder_size_mb(worker_bugs_folder)
            scratch_folder = self.output_dir / f"scratch_{worker_id}"
            scratch_size_mb = self._calculate_folder_size_mb(scratch_folder)
            log_folder = self.output_dir / f"logs_{worker_id}"
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
        print(f"  Main bugs folder: {main_bug_count} bugs, {main_bugs_size_mb:.2f} MB", file=sys.stderr)
        print(f"  Worker folders:", file=sys.stderr)
        for info in worker_folders_info:
            print(f"    worker_{info['id']}: {info['bugs']} bugs, {info['total_size_mb']:.2f} MB total", file=sys.stderr)
        
        print(f"\nSTATISTICS:", file=sys.stderr)
        print(f"  Tests processed: {self.stats.get('tests_processed', 0)}", file=sys.stderr)
        print(f"  Bugs found: {self.stats.get('bugs_found', 0)}", file=sys.stderr)
        print(f"  Mutants with new coverage: {self.stats.get('mutants_with_new_coverage', 0)}", file=sys.stderr)
        print(f"  Total new edges: {self.stats.get('total_new_edges', 0)}", file=sys.stderr)
        print(f"  Generations completed: {self.stats.get('generations_completed', 0)}", file=sys.stderr)
        
        print("\n" + "=" * 60, file=sys.stderr)
        print("Stopping fuzzer to preserve found bugs...", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        
        self.shutdown_event.set()
    
    def _check_resource_state(self) -> str:
        with self.resource_lock:
            return self.resource_state.get('status', 'normal')
    
    def _is_paused(self) -> bool:
        with self.resource_lock:
            return self.resource_state.get('paused', False)
    
    def _log_periodic_status(self, global_coverage_map=None):
        """Log periodic status summary for monitoring."""
        elapsed = time.time() - self.start_time
        remaining = self._get_time_remaining()
        
        # Gather worker status
        active_workers = []
        idle_workers = []
        for w_id in range(1, self.num_workers + 1):
            status = self.worker_status.get(w_id)
            if status:
                active_workers.append((w_id, status))
            else:
                idle_workers.append(w_id)
        
        # Queue stats
        queue_size = self._queue_size()
        
        # Coverage stats from shared map
        total_edges = 0
        if global_coverage_map is not None:
            try:
                total_edges = sum(1 for b in global_coverage_map if b == 0x00)
            except Exception:
                pass
        
        # Resource stats
        with self.resource_lock:
            cpu_avg = self.resource_state.get('avg_cpu', 0.0)
            mem_used_gb = self.resource_state.get('memory_used_gb', 0.0)
            mem_avail_gb = self.resource_state.get('memory_available_gb', 0.0)
            resource_status = self.resource_state.get('status', 'unknown')
        
        # Calculate rates
        tests_per_min = (self.stats.get('tests_processed', 0) / elapsed * 60) if elapsed > 0 else 0
        edges_per_min = (self.stats.get('total_new_edges', 0) / elapsed * 60) if elapsed > 0 else 0
        
        # Print status block
        print()
        print(f"[STATUS] ═══════════════════════════════════════════════════════")
        print(f"[STATUS] Time: {elapsed:.0f}s elapsed, {remaining:.0f}s remaining ({elapsed/60:.1f}m / {(elapsed+remaining)/60:.1f}m)")
        print(f"[STATUS] Resources: CPU {cpu_avg:.1f}%, Mem {mem_used_gb:.1f}GB used / {mem_avail_gb:.1f}GB avail [{resource_status}]")
        print(f"[STATUS] Queue: {queue_size} items pending")
        print(f"[STATUS] Workers: {len(active_workers)} active, {len(idle_workers)} idle")
        
        for w_id, test in active_workers:
            print(f"[STATUS]   Worker {w_id}: {test}")
        
        print(f"[STATUS] Coverage: {total_edges} total edges, {self.stats.get('total_new_edges', 0)} new this run")
        print(f"[STATUS] Mutants: {self.stats.get('mutants_created', 0)} created, {self.stats.get('mutants_with_new_coverage', 0)} with new coverage")
        print(f"[STATUS] Tests: {self.stats.get('tests_processed', 0)} processed, {self.stats.get('tests_removed_unsupported', 0)} unsupported, {self.stats.get('tests_removed_timeout', 0)} timeout")
        print(f"[STATUS] Generations: {self.stats.get('generations_completed', 0)} completed")
        print(f"[STATUS] Bugs: {self.stats.get('bugs_found', 0)} found")
        print(f"[STATUS] Rate: {tests_per_min:.1f} tests/min, {edges_per_min:.1f} new edges/min")
        print(f"[STATUS] ═══════════════════════════════════════════════════════")
        print()
    
    # -------------------------------------------------------------------------
    # AFL-style Coverage Tracking
    # -------------------------------------------------------------------------
    
    def _create_shared_memory(self, name: str) -> mmap.mmap:
        """Create a shared memory region for trace_bits (where CVC5 writes edge hits).
        
        This is the trace_bits buffer where coverage_agent.cpp writes edge hits.
        Initialize to 0x00 (no hits). Non-zero bytes after running = edges hit.
        
        Note: This is NOT the global_coverage_map. The global_coverage_map is shared
        across all workers and tracks which edges have ever been seen.
        """
        shm_path = f"/dev/shm/{name}"
        
        # Create the shared memory file
        fd = os.open(shm_path, os.O_CREAT | os.O_RDWR, 0o666)
        try:
            # Initialize to all 0x00 (no coverage yet)
            # coverage_agent.cpp increments bytes when edges are hit
            os.ftruncate(fd, AFL_MAP_SIZE)
            mm = mmap.mmap(fd, AFL_MAP_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
            mm.write(b'\x00' * AFL_MAP_SIZE)
            mm.seek(0)
            return mm
        finally:
            os.close(fd)
    
    def _read_shared_memory(self, name: str) -> Optional[bytes]:
        """Read coverage bitmap from shared memory."""
        shm_path = f"/dev/shm/{name}"
        try:
            fd = os.open(shm_path, os.O_RDONLY)
            try:
                mm = mmap.mmap(fd, AFL_MAP_SIZE, mmap.MAP_SHARED, mmap.PROT_READ)
                data = mm.read(AFL_MAP_SIZE)
                mm.close()
                return data
            finally:
                os.close(fd)
        except (OSError, ValueError) as e:
            return None
    
    def _cleanup_shared_memory(self, name: str):
        """Remove shared memory file."""
        shm_path = f"/dev/shm/{name}"
        try:
            os.unlink(shm_path)
        except OSError:
            pass
    
    def _has_new_bits(self, trace_bits: bytes, coverage_map: bytes) -> Tuple[bool, int, bytes]:
        """
        Check if trace_bits has any new coverage compared to coverage_map.
        Returns (has_new, new_edge_count, updated_coverage_map).
        
        coverage_map: 0xFF = edge not seen, 0x00 = edge seen
        trace_bits: 0x00 = edge not hit, non-zero = edge hit (count)
        """
        new_edges = 0
        updated = bytearray(coverage_map)
        
        for i in range(AFL_MAP_SIZE):
            if trace_bits[i] and coverage_map[i] == 0xff:
                # New edge found
                updated[i] = 0x00
                new_edges += 1
        
        return new_edges > 0, new_edges, bytes(updated)
    
    def _count_edges(self, coverage_map: bytes) -> int:
        """Count number of covered edges (0x00 bytes = seen edges)."""
        return sum(1 for b in coverage_map if b == 0x00)
    
    # -------------------------------------------------------------------------
    # Typefuzz Execution
    # -------------------------------------------------------------------------
    
    def _get_solver_clis(self) -> str:
        """Get solver CLI string for typefuzz (z3 + cvc5)."""
        solvers = [
            self.z3_cmd,
            f"{self.cvc5_path} --check-models --check-proofs --strings-exp"
        ]
        return ";".join(solvers)
    
    def _collect_bug_files(self, folder: Path) -> List[Path]:
        if not folder.exists():
            return []
        return list(folder.glob("*.smt2")) + list(folder.glob("*.smt"))
    
    def _run_typefuzz(
        self,
        test_path: Path,
        worker_id: int,
        scratch_folder: Path,
        log_folder: Path,
        bugs_folder: Path,
        shm_id: str,
        per_test_timeout: Optional[float] = None,
        keep_mutants: bool = True,
    ) -> Tuple[int, List[Path], float, List[Path]]:
        """
        Run typefuzz on a test file.
        Returns (exit_code, bug_files, runtime, mutant_files).
        """
        if not test_path.exists():
            print(f"[WORKER {worker_id}] Error: Test file not found: {test_path}", file=sys.stderr)
            return (1, [], 0.0, [])
        
        # Clean scratch/log folders but keep bugs
        for folder in [scratch_folder, log_folder]:
            shutil.rmtree(folder, ignore_errors=True)
            folder.mkdir(parents=True, exist_ok=True)
        bugs_folder.mkdir(parents=True, exist_ok=True)
        
        solver_clis = self._get_solver_clis()
        
        # typefuzz -i 1 -k (1 iteration, keep mutants)
        cmd = [
            "typefuzz",
            "-i", str(self.iterations),
            "-m", str(self.modulo),
            "--seed", str(self.seed),
            "--timeout", "120",
            "--bugs", str(bugs_folder),
            "--scratch", str(scratch_folder),
            "--logfolder", str(log_folder),
        ]
        if keep_mutants:
            cmd.append("-k")  # Keep mutants
        cmd.extend([solver_clis, str(test_path)])
        
        print(f"[WORKER {worker_id}] Running typefuzz on: {test_path.name} (timeout: {per_test_timeout:.0f}s)" if per_test_timeout else f"[WORKER {worker_id}] Running typefuzz on: {test_path.name}")
        
        start_time = time.time()
        
        try:
            env = os.environ.copy()
            # Set shared memory ID for coverage agent (afl_shm_{ID})
            env['__AFL_SHM_ID'] = shm_id
            # PGO profiling - use %p (pid) and %m (merge pool) for unique files per cvc5 invocation
            # typefuzz runs cvc5 multiple times, each needs its own profraw file
            profraw_pattern = self.profraw_dir / f"worker_{worker_id}_%p_%m.profraw"
            env['LLVM_PROFILE_FILE'] = str(profraw_pattern)
            # Disable ASAN leak detection
            env['ASAN_OPTIONS'] = 'abort_on_error=0:detect_leaks=0'
            
            if per_test_timeout and per_test_timeout > 0:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=per_test_timeout, env=env)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            
            exit_code = result.returncode
            runtime = time.time() - start_time
            bug_files = self._collect_bug_files(bugs_folder)
            
            # Collect mutant files from scratch folder
            mutant_files = list(scratch_folder.glob("*.smt2")) + list(scratch_folder.glob("*.smt"))
            
            return (exit_code, bug_files, runtime, mutant_files)
            
        except subprocess.TimeoutExpired:
            runtime = time.time() - start_time
            return (124, [], runtime, [])
        except Exception as e:
            print(f"[WORKER {worker_id}] Error running typefuzz: {e}", file=sys.stderr)
            runtime = time.time() - start_time
            return (1, [], runtime, [])
    
    def _handle_exit_code(
        self,
        test_name: str,
        exit_code: int,
        bug_files: List[Path],
        runtime: float,
        worker_id: int,
    ) -> str:
        """Handle typefuzz exit code. Returns action: 'requeue', 'remove', or 'continue'."""
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
            print(f"[WORKER {worker_id}] Exit code 0: {test_name} (runtime: {runtime:.1f}s)")
            return 'continue'
        
        elif exit_code == 124:
            print(f"[WORKER {worker_id}] ⏱ Timeout: {test_name}")
            self.stats['tests_removed_timeout'] += 1
            return 'remove'
        
        else:
            print(f"[WORKER {worker_id}] Exit code {exit_code}: {test_name}")
            return 'continue'
    
    # -------------------------------------------------------------------------
    # Worker Process
    # -------------------------------------------------------------------------
    
    def _worker_process(self, worker_id: int, global_coverage_map: multiprocessing.Array, 
                        coverage_map_lock: multiprocessing.Lock):
        """
        Worker process that processes tests and tracks coverage.
        Uses per-worker shared memory for trace_bits (where CVC5 writes edge hits).
        Uses SHARED global_coverage_map across all workers for tracking unique edges seen.
        
        global_coverage_map: 64KB array where 0xFF = edge not seen yet, 0x00 = edge seen
        
        Tests are fetched from self._priority_queue (sorted by runtime, fastest first).
        New mutants with coverage are pushed directly to the priority queue.
        """
        print(f"[WORKER {worker_id}] Started")
        
        # Create per-worker folders
        scratch_folder = self.output_dir / f"scratch_{worker_id}"
        log_folder = self.output_dir / f"logs_{worker_id}"
        bugs_folder = self.bugs_folder / f"worker_{worker_id}"
        
        for folder in [scratch_folder, log_folder, bugs_folder]:
            folder.mkdir(parents=True, exist_ok=True)
        
        # Create per-worker shared memory for coverage (trace_bits from CVC5)
        shm_id = f"{worker_id}"
        shm_name = f"afl_shm_{shm_id}"
        
        try:
            while not self.shutdown_event.is_set():
                try:
                    # Mark worker as idle while waiting for work
                    self.worker_status[worker_id] = None
                    
                    if self._is_paused():
                        resource_status = self._check_resource_state()
                        print(f"[WORKER {worker_id}] Paused due to {resource_status} resource usage", file=sys.stderr)
                        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                        continue
                    
                    # Get test from priority queue (sorted by runtime, fastest first)
                    test_item = self._queue_pop(timeout=1.0)
                    if test_item is None:
                        if self.shutdown_event.is_set() or self._is_time_expired():
                            break
                        continue
                    
                    if self._is_time_expired():
                        # Put back and exit
                        self._queue_push(test_item)
                        break
                    
                    # Check resource state
                    resource_status = self._check_resource_state()
                    if resource_status == 'warning':
                        time.sleep(2)
                    elif resource_status == 'critical':
                        self._queue_push(test_item)
                        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                        continue
                    
                    # Parse test item: (runtime, generation, test_path)
                    runtime_priority, generation, test_path = test_item
                    
                    # Handle string paths (initial tests) vs Path objects (mutants)
                    if isinstance(test_path, str):
                        test_path = self.tests_root / test_path
                    
                    test_name = test_path.name if isinstance(test_path, Path) else Path(test_path).name
                    is_mutant = generation > 0
                    
                    # Log test pickup
                    queue_size = self._queue_size()
                    test_type = f"mutant(gen:{generation})" if is_mutant else "seed"
                    print(f"[WORKER {worker_id}] [PICK] {test_type} {test_name} (priority:{runtime_priority:.2f}, queue:{queue_size})")
                    
                    # Mark worker as busy
                    self.worker_status[worker_id] = test_name
                    
                    # Create shared memory for this test (trace_bits - where CVC5 writes)
                    try:
                        shm = self._create_shared_memory(shm_name)
                    except Exception as e:
                        print(f"[WORKER {worker_id}] Error creating shared memory: {e}", file=sys.stderr)
                        continue
                    
                    try:
                        # Run typefuzz
                        time_remaining = self._get_time_remaining()
                        exit_code, bug_files, runtime, mutant_files = self._run_typefuzz(
                            test_path if isinstance(test_path, Path) else Path(test_path),
                            worker_id,
                            scratch_folder,
                            log_folder,
                            bugs_folder,
                            shm_id,
                            per_test_timeout=time_remaining if self.time_remaining and time_remaining > 0 else None,
                            keep_mutants=True,
                        )
                        
                        # Handle exit code
                        action = self._handle_exit_code(test_name, exit_code, bug_files, runtime, worker_id)
                        self.stats['tests_processed'] += 1
                        
                        # Read coverage from shared memory (trace_bits)
                        shm.seek(0)
                        trace_bits = shm.read(AFL_MAP_SIZE)
                        
                        # Count edges hit in this execution
                        edges_hit = sum(1 for b in trace_bits if b != 0)
                        
                        # Check for new coverage using SHARED global_coverage_map (with lock)
                        # This ensures all workers see the same global coverage state
                        has_new = False
                        new_edges = 0
                        total_edges_before = 0
                        
                        with coverage_map_lock:
                            # Read current coverage map
                            coverage_bytes = bytes(global_coverage_map[:])
                            total_edges_before = sum(1 for b in coverage_bytes if b == 0x00)
                            
                            # Check and update atomically
                            for i in range(AFL_MAP_SIZE):
                                if trace_bits[i] and coverage_bytes[i] == 0xff:
                                    # New edge found - mark as seen (0xFF → 0x00)
                                    global_coverage_map[i] = 0x00
                                    new_edges += 1
                                    has_new = True
                        
                        # Log coverage details
                        total_edges_after = total_edges_before + new_edges
                        print(f"[WORKER {worker_id}] [COV] Test: {test_name} | gen:{generation} | hit:{edges_hit} | new:{new_edges} | total:{total_edges_after}")
                        
                        if has_new:
                            self.stats['total_new_edges'] += new_edges
                            print(f"[WORKER {worker_id}] ✨ New coverage found: {new_edges} edges (total now: {total_edges_after})")
                            
                            # Process mutants: MOVE to pending folder (so they survive scratch cleanup)
                            mutants_to_queue = []
                            print(f"[WORKER {worker_id}] [MUTANT] Processing {len(mutant_files)} mutant(s) from {test_name} (gen {generation})")
                            for mutant_file in mutant_files:
                                try:
                                    # Move to pending folder with unique name
                                    pending_name = f"gen{generation+1}_w{worker_id}_{mutant_file.name}"
                                    pending_path = self.pending_mutants_dir / pending_name
                                    shutil.move(str(mutant_file), str(pending_path))
                                    mutants_to_queue.append((runtime, generation + 1, pending_path))
                                    self.stats['mutants_created'] += 1
                                except Exception as e:
                                    print(f"[WORKER {worker_id}] Warning: Failed to move mutant {mutant_file}: {e}", file=sys.stderr)
                            
                            if mutants_to_queue:
                                self.stats['mutants_with_new_coverage'] += 1
                                queue_size_before = self._queue_size()
                                # Add mutants directly to priority queue (sorted by runtime)
                                for mutant_item in mutants_to_queue:
                                    self._queue_push(mutant_item)
                                print(f"[WORKER {worker_id}] [QUEUE] Added {len(mutants_to_queue)} mutant(s) to queue (queue size: {queue_size_before} -> {self._queue_size()})")
                        else:
                            # No new coverage - delete mutants immediately
                            if mutant_files:
                                print(f"[WORKER {worker_id}] [MUTANT] No new coverage, discarding {len(mutant_files)} mutant(s)")
                            for mutant_file in mutant_files:
                                try:
                                    mutant_file.unlink()
                                except Exception:
                                    pass
                        
                        # Delete executed mutant if it's from pending folder
                        # (we've extracted its value, now clean up disk space)
                        test_path_obj = test_path if isinstance(test_path, Path) else Path(test_path)
                        if self.pending_mutants_dir in test_path_obj.parents or test_path_obj.parent == self.pending_mutants_dir:
                            try:
                                test_path_obj.unlink()
                            except Exception:
                                pass
                        
                        # Clear scratch folder (safe now - mutants were moved if needed)
                        shutil.rmtree(scratch_folder, ignore_errors=True)
                        scratch_folder.mkdir(parents=True, exist_ok=True)
                        
                        # Periodic profraw merge to save disk space
                        with self.profraw_merge_counter.get_lock():
                            self.profraw_merge_counter.value += 1
                            if self.profraw_merge_counter.value >= self.profdata_merge_interval:
                                self._periodic_profraw_merge()
                                self.profraw_merge_counter.value = 0
                        
                    finally:
                        # Cleanup shared memory
                        shm.close()
                        self._cleanup_shared_memory(shm_name)
                    
                except Exception as e:
                    print(f"[WORKER {worker_id}] Error in worker: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    continue
        
        finally:
            # Mark worker as stopped and cleanup
            self.worker_status[worker_id] = None
            for folder in [scratch_folder, log_folder]:
                shutil.rmtree(folder, ignore_errors=True)
        
        print(f"[WORKER {worker_id}] Stopped")
    
    # -------------------------------------------------------------------------
    # Main Run Loop
    # -------------------------------------------------------------------------
    
    def run(self):
        if not self.tests:
            print(f"No tests provided{' for job ' + self.job_id if self.job_id else ''}")
            return
        
        print(f"Running coverage-guided fuzzer on {len(self.tests)} test(s){' for job ' + self.job_id if self.job_id else ''}")
        print(f"Tests root: {self.tests_root}")
        print(f"Timeout: {self.time_remaining}s ({self.time_remaining // 60} minutes)" if self.time_remaining else "No timeout")
        print(f"Iterations per test: {self.iterations}, Modulo: {self.modulo}")
        print(f"CPU cores: {self.cpu_count}")
        print(f"Workers: {self.num_workers}")
        print(f"Solvers: z3={self.z3_cmd}, cvc5={self.cvc5_path}")
        print(f"Output directory: {self.output_dir}")
        print()
        
        # Initialize priority queue with initial tests (runtime=0 for initial tests)
        print(f"[INFO] Loading {len(self.tests)} initial tests into priority queue...")
        self._queue_push_initial_batch(self.tests)
        
        # SHARED global_coverage_map across all workers (0xFF = unseen, 0x00 = seen)
        # Using multiprocessing.Array for cross-process sharing
        # 'B' = unsigned char (1 byte), initialized to 255 (0xFF = not seen yet)
        global_coverage_map = multiprocessing.Array('B', [0xff] * AFL_MAP_SIZE)
        coverage_map_lock = multiprocessing.Lock()  # Protects coverage map updates
        
        # Start workers (no result_queue needed - workers push directly to priority queue)
        workers = []
        for worker_id in range(1, self.num_workers + 1):
            worker = multiprocessing.Process(
                target=self._worker_process,
                args=(worker_id, global_coverage_map, coverage_map_lock)
            )
            worker.start()
            workers.append(worker)
        
        self.workers = workers
        print(f"[INFO] Started {len(workers)} worker processes")
        
        # Start resource monitor
        monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        monitor_thread.start()
        print("[DEBUG] Resource monitoring started")
        
        # Log initial state
        print(f"[INFO] Initialization complete. Coverage bitmap: {AFL_MAP_SIZE} bytes ({AFL_MAP_SIZE // 1024}KB)")
        print(f"[INFO] Starting fuzzing loop...")
        
        # Signal handlers
        def signal_handler(signum, frame):
            print("\n⏰ Shutdown signal received, stopping workers...")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        # Main loop: monitor workers and refill queue when needed
        try:
            end_time = self.start_time + self.time_remaining if self.time_remaining else None
            last_refill_check = time.time()
            last_status_log = time.time()
            status_log_interval = 30  # Log status every 30 seconds
            
            while any(w.is_alive() for w in workers):
                if end_time and time.time() >= end_time:
                    print("⏰ Timeout reached, stopping workers...")
                    self.shutdown_event.set()
                    break
                
                current_time = time.time()
                
                # Periodic status logging
                if current_time - last_status_log >= status_log_interval:
                    self._log_periodic_status(global_coverage_map)
                    last_status_log = current_time
                
                # Refill when queue is empty AND at least one worker is idle
                # This prevents idle workers from waiting for slow tests to finish
                # Don't refill too frequently (min 2 seconds between checks)
                if current_time - last_refill_check >= 2.0:
                    idle_workers = sum(1 for w_id in range(1, self.num_workers + 1) 
                                      if self.worker_status.get(w_id) is None)
                    
                    if self._queue_empty() and idle_workers > 0:
                        gen = self.stats.get('generations_completed', 0) + 1
                        print(f"[INFO] Queue empty with {idle_workers} idle worker(s), refilling (generation {gen})...")
                        self._queue_push_initial_batch(self.tests)
                        self.stats['generations_completed'] += 1
                    
                    last_refill_check = current_time
                
                time.sleep(0.5)
        
        except KeyboardInterrupt:
            print("\n⏰ Interrupted, stopping workers...")
            self.shutdown_event.set()
        
        # Wait for workers to finish
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker_pid = getattr(worker, 'pid', 'unknown')
                print(f"Warning: Worker {worker_pid} did not terminate, killing...")
                worker.terminate()
                worker.join(timeout=2)
                if worker.is_alive():
                    worker.kill()
        
        # Collect bugs from worker folders
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
        
        # Final statistics - read from shared coverage map
        total_edges = self._count_edges(bytes(global_coverage_map[:]))
        
        print()
        print("=" * 60)
        print(f"COVERAGE-GUIDED FUZZING COMPLETE{' FOR JOB ' + self.job_id if self.job_id else ''}")
        print("=" * 60)
        
        bug_files = self._collect_bug_files(self.bugs_folder)
        if bug_files:
            print(f"\nFound {len(bug_files)} bug(s):")
            for i, bug_file in enumerate(bug_files[:10], 1):  # Show first 10
                print(f"  Bug #{i}: {bug_file.name}")
            if len(bug_files) > 10:
                print(f"  ... and {len(bug_files) - 10} more")
        else:
            print("\nNo bugs found.")
        
        print()
        print("Coverage Statistics:")
        print(f"  Total edges covered: {total_edges}")
        print(f"  Total new edges found: {self.stats.get('total_new_edges', 0)}")
        print(f"  Mutants with new coverage: {self.stats.get('mutants_with_new_coverage', 0)}")
        print(f"  Mutants created: {self.stats.get('mutants_created', 0)}")
        print(f"  Generations completed: {self.stats.get('generations_completed', 0)}")
        
        print()
        print("Fuzzing Statistics:")
        print(f"  Tests processed: {self.stats.get('tests_processed', 0)}")
        print(f"  Bugs found: {self.stats.get('bugs_found', 0)}")
        print(f"  Tests removed (unsupported): {self.stats.get('tests_removed_unsupported', 0)}")
        print(f"  Tests removed (timeout): {self.stats.get('tests_removed_timeout', 0)}")
        
        # Merge profdata if PGO was enabled
        self._merge_profdata()
        
        print("=" * 60)
        
        # Save coverage statistics to output file
        stats_output = self.output_dir / "coverage_stats.json"
        with open(stats_output, 'w') as f:
            json.dump({
                'total_edges': total_edges,
                'total_new_edges': self.stats.get('total_new_edges', 0),
                'mutants_with_new_coverage': self.stats.get('mutants_with_new_coverage', 0),
                'mutants_created': self.stats.get('mutants_created', 0),
                'generations_completed': self.stats.get('generations_completed', 0),
                'tests_processed': self.stats.get('tests_processed', 0),
                'bugs_found': self.stats.get('bugs_found', 0),
                'runtime_seconds': time.time() - self.start_time,
            }, f, indent=2)
        print(f"[INFO] Coverage statistics saved to: {stats_output}")
    
    def _periodic_profraw_merge(self):
        """Periodically merge profraw files to save disk space."""
        profraw_files = list(self.profraw_dir.glob("*.profraw"))
        if len(profraw_files) < 10:  # Don't bother if few files
            return
        
        accumulated_profdata = self.output_dir / "accumulated.profdata"
        temp_profdata = self.output_dir / "temp_merge.profdata"
        
        try:
            # Build merge command
            cmd = ["llvm-profdata", "merge", "-sparse", "-o", str(temp_profdata)]
            
            # Include existing accumulated profdata if it exists
            if accumulated_profdata.exists():
                cmd.append(str(accumulated_profdata))
            
            cmd.extend([str(f) for f in profraw_files])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                # Replace accumulated with new merged file
                if accumulated_profdata.exists():
                    accumulated_profdata.unlink()
                temp_profdata.rename(accumulated_profdata)
                
                # Delete merged profraw files to save disk space
                for f in profraw_files:
                    try:
                        f.unlink()
                    except Exception:
                        pass
                
                print(f"[INFO] Periodic merge: merged {len(profraw_files)} profraw files, disk space recovered")
            else:
                print(f"[WARN] Periodic profraw merge failed: {result.stderr}", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("[WARN] Periodic profraw merge timed out", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Error in periodic profraw merge: {e}", file=sys.stderr)
    
    def _merge_profdata(self):
        """Merge all .profraw files into a single .profdata file (final merge)."""
        profraw_files = list(self.profraw_dir.glob("*.profraw"))
        accumulated_profdata = self.output_dir / "accumulated.profdata"
        
        if not profraw_files and not accumulated_profdata.exists():
            print("[INFO] No profraw files to merge")
            return
        
        files_to_merge = []
        if accumulated_profdata.exists():
            files_to_merge.append(str(accumulated_profdata))
        files_to_merge.extend([str(f) for f in profraw_files])
        
        print(f"[INFO] Final merge: {len(files_to_merge)} files...")
        
        profdata_output = self.output_dir / "merged.profdata"
        
        try:
            cmd = ["llvm-profdata", "merge", "-sparse", "-o", str(profdata_output)]
            cmd.extend(files_to_merge)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[INFO] Merged profdata saved to: {profdata_output}")
            else:
                print(f"[WARN] Failed to merge profdata: {result.stderr}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Error merging profdata: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Coverage-guided fuzzer that runs typefuzz with AFL-style coverage tracking"
    )
    
    tests_group = parser.add_mutually_exclusive_group(required=True)
    tests_group.add_argument(
        "--tests-json",
        help="JSON array of test names (relative to --tests-root)",
    )
    tests_group.add_argument(
        "--tests-file",
        help="Path to JSON file containing array of test names",
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
        help="Remaining time until job timeout in seconds",
    )
    parser.add_argument(
        "--job-start-time",
        type=float,
        help="Unix timestamp when the job started",
    )
    parser.add_argument(
        "--stop-buffer-minutes",
        type=int,
        default=5,
        help="Minutes before timeout to stop (default: 5)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of iterations per test (default: 1 for coverage-guided)",
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
        "--cvc5-path",
        default="./build/bin/cvc5",
        help="Path to cvc5 binary (default: ./build/bin/cvc5)",
    )
    
    try:
        default_workers = psutil.cpu_count()
    except Exception:
        default_workers = 4
    
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help=f"Number of worker processes (default: {default_workers})",
    )
    parser.add_argument(
        "--bugs-folder",
        default="bugs",
        help="Folder to store bugs (default: bugs)",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Output directory for logs, scratch, and stats (default: ./output)",
    )
    parser.add_argument(
        "--profraw-dir",
        default="./profraw",
        help="Directory for profraw files (default: ./profraw)",
    )
    parser.add_argument(
        "--fuzzing-duration-minutes",
        type=float,
        default=60.0,
        help="Fuzzing duration in minutes (default: 60.0)",
    )
    
    args = parser.parse_args()
    
    # Parse tests
    try:
        if args.tests_file:
            with open(args.tests_file, 'r') as f:
                tests = json.load(f)
            print(f"[INFO] Loaded tests from file: {args.tests_file}")
        else:
            tests = json.loads(args.tests_json)
        if not isinstance(tests, list):
            raise ValueError("tests must be a JSON array")
    except FileNotFoundError as e:
        print(f"Error: Tests file not found: {args.tests_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Calculate time_remaining from fuzzing duration if not provided
    if args.time_remaining is None and args.job_start_time is None:
        args.time_remaining = int(args.fuzzing_duration_minutes * 60)
        print(f"[INFO] Setting fuzzing duration to {args.fuzzing_duration_minutes} minutes ({args.time_remaining} seconds)")
    
    try:
        fuzzer = CoverageGuidedFuzzer(
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
            cvc5_path=args.cvc5_path,
            job_id=args.job_id,
            profraw_dir=args.profraw_dir,
            output_dir=args.output_dir,
        )
        
        fuzzer.run()
        
        print("[INFO] Fuzzing complete, forcing exit", flush=True)
        os._exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        os._exit(1)


if __name__ == "__main__":
    main()
