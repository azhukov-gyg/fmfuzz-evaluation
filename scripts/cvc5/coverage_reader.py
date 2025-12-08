#!/usr/bin/env python3
"""
Python module to read coverage from shared memory.
Used by Python fuzzers to get coverage feedback from cvc5.

The coverage agent (libcov_agent.so) writes coverage data to shared memory,
and this module reads it.
"""

import mmap
import struct
import os
from typing import Set, Tuple, Optional
from pathlib import Path

MAX_COUNTERS = 65536
MAX_PCS = 65536

# Structure layout matches C++ CovShm:
# - atomic<uint32_t> pid (4 bytes + 4 padding)
# - atomic<uint32_t> counter_count (4 bytes + 4 padding)  
# - atomic<uint32_t> pc_table_size (4 bytes + 4 padding)
# - uint8_t counters[MAX_COUNTERS] (65536 bytes)
# - uintptr_t pc_table[MAX_PCS] (65536 * 8 bytes)
SHM_SIZE = 4 + 4 + 4 + 4 + 4 + 4 + MAX_COUNTERS + MAX_PCS * 8


class CoverageReader:
    """Read coverage from shared memory created by coverage agent"""
    
    def __init__(self, shm_name: str):
        self.shm_name = shm_name
        self.shm_fd = None
        self.shm_mmap = None
        self.shm_path = f"/dev/shm/{shm_name}"
    
    def open(self) -> bool:
        """Open shared memory segment"""
        try:
            if not os.path.exists(self.shm_path):
                return False
            
            file_size = os.path.getsize(self.shm_path)
            if file_size < SHM_SIZE:
                return False
            
            self.shm_fd = os.open(self.shm_path, os.O_RDONLY)
            self.shm_mmap = mmap.mmap(self.shm_fd, file_size, access=mmap.ACCESS_READ)
            
            # Verify counter_count > 0 (indicates data was written by agent)
            self.shm_mmap.seek(8)
            counter_count = struct.unpack('I', self.shm_mmap.read(4))[0]
            self.shm_mmap.seek(0)
            
            if counter_count == 0:
                self.close()
                return False
            
            return True
        except Exception:
            return False
    
    def close(self):
        """Close shared memory"""
        if self.shm_mmap:
            try:
                self.shm_mmap.close()
            except:
                pass
            self.shm_mmap = None
        if self.shm_fd is not None:
            try:
                os.close(self.shm_fd)
            except:
                pass
            self.shm_fd = None
    
    def cleanup(self):
        """Remove shared memory file"""
        self.close()
        try:
            if os.path.exists(self.shm_path):
                os.unlink(self.shm_path)
        except:
            pass
    
    def read_coverage(self) -> Tuple[Set[int], Set[int], int, int]:
        """
        Read coverage from shared memory.
        Returns: (covered_indices, pcs, counter_count, pc_table_size)
        
        covered_indices: set of counter indices with non-zero values
        pcs: set of program counter addresses
        """
        if not self.shm_mmap:
            return set(), set(), 0, 0
        
        self.shm_mmap.seek(0)
        
        # pid (atomic<uint32_t>) - offset 0, 4 bytes
        pid = struct.unpack('I', self.shm_mmap.read(4))[0]
        self.shm_mmap.read(4)  # Skip padding
        
        # counter_count (atomic<uint32_t>) - offset 8, 4 bytes
        counter_count = struct.unpack('I', self.shm_mmap.read(4))[0]
        self.shm_mmap.read(4)  # Skip padding
        
        # pc_table_size (atomic<uint32_t>) - offset 16, 4 bytes
        pc_table_size = struct.unpack('I', self.shm_mmap.read(4))[0]
        self.shm_mmap.read(4)  # Skip padding
        
        # counters array starts at offset 24
        counters = self.shm_mmap.read(MAX_COUNTERS)
        
        # PC table starts after counters
        pc_table_bytes = self.shm_mmap.read(MAX_PCS * 8)
        
        # Extract covered indices (counter indices with non-zero values)
        covered_indices = set()
        for i in range(min(counter_count, MAX_COUNTERS)):
            if counters[i] > 0:
                covered_indices.add(i)
        
        # Extract PCs
        pcs = set()
        for i in range(min(pc_table_size, MAX_PCS)):
            pc = struct.unpack('Q', pc_table_bytes[i*8:(i+1)*8])[0]
            if pc != 0:
                pcs.add(pc)
        
        return covered_indices, pcs, counter_count, pc_table_size
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_shm_name(prefix: str = "cvc5_cov") -> str:
    """Create a unique shared memory name"""
    import uuid
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

