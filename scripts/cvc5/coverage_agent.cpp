/*
 * Coverage agent for SanitizerCoverage using trace-pc-guard.
 * Tracks which edges (guards) were hit and writes to shared memory.
 * 
 * Build: clang++ -shared -fPIC -o libcov_agent.so coverage_agent.cpp -O2 -g -lrt
 * Usage: LD_PRELOAD=./libcov_agent.so COVERAGE_SHM_NAME=shm_name ./binary
 */

#include <atomic>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <unordered_set>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstdio>
#include <ctime>

constexpr size_t MAX_GUARDS = 65536;
constexpr size_t MAX_PCS = 65536;

struct CovShm {
    std::atomic<uint32_t> pid{0};
    std::atomic<uint32_t> guard_count{0};      // Total number of guards
    std::atomic<uint32_t> hit_guard_count{0}; // Number of guards that were hit
    std::atomic<uint32_t> pc_table_size{0};
    uint8_t hit_guards[MAX_GUARDS / 8];        // Bitmap: 1 bit per guard
    uintptr_t pc_table[MAX_PCS];
};

constexpr size_t SHM_SIZE = sizeof(CovShm);

static CovShm* g_shm = nullptr;
static uint32_t* g_guard_start = nullptr;
static uint32_t* g_guard_end = nullptr;
static std::unordered_set<uint32_t> g_hit_guards;  // Track which guards were hit
static const uintptr_t* g_pc_table_start = nullptr;
static const uintptr_t* g_pc_table_end = nullptr;
static int g_shm_fd = -1;

// Initialize shared memory
__attribute__((no_sanitize("coverage")))
static void init_shm(const char* shm_name) {
    if (g_shm) return;
    
    g_shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (g_shm_fd < 0) {
        return;
    }
    
    if (ftruncate(g_shm_fd, SHM_SIZE) < 0) {
        close(g_shm_fd);
        g_shm_fd = -1;
        return;
    }
    
    g_shm = (CovShm*)mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0);
    if (g_shm == MAP_FAILED) {
        close(g_shm_fd);
        g_shm_fd = -1;
        g_shm = nullptr;
        return;
    }
    
    // Initialize if first process
    uint32_t expected_pid = 0;
    if (g_shm->pid.compare_exchange_strong(expected_pid, getpid())) {
        memset(g_shm->hit_guards, 0, MAX_GUARDS / 8);
        memset(g_shm->pc_table, 0, MAX_PCS * sizeof(uintptr_t));
        g_shm->guard_count.store(0);
        g_shm->hit_guard_count.store(0);
        g_shm->pc_table_size.store(0);
    }
}

// Sanitizer callbacks for trace-pc-guard
extern "C" __attribute__((visibility("default"))) 
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    FILE* log = fopen("/tmp/coverage_agent.log", "a");
    if (log) {
        size_t count = (start && stop && stop > start) ? (stop - start) : 0;
        fprintf(log, "[AGENT] __sanitizer_cov_trace_pc_guard_init called! pid=%d, guard_count=%zu\n", 
                getpid(), count);
        fclose(log);
    }
    
    g_guard_start = start;
    g_guard_end = stop;
    
    if (start && stop && stop > start) {
        const char* shm_name = getenv("COVERAGE_SHM_NAME");
        if (shm_name && shm_name[0] != '\0') {
            init_shm(shm_name);
            if (g_shm) {
                size_t count = std::min(static_cast<size_t>(stop - start), MAX_GUARDS);
                g_shm->guard_count.store((uint32_t)count);
                
                log = fopen("/tmp/coverage_agent.log", "a");
                if (log) {
                    fprintf(log, "[AGENT] Guards initialized! pid=%d, shm_name=%s, guard_count=%zu\n",
                            getpid(), shm_name, count);
                    fclose(log);
                }
            }
        }
    }
}

extern "C" __attribute__((visibility("default"))) 
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    // Mark this guard as hit
    if (guard && g_guard_start && g_guard_end && 
        guard >= g_guard_start && guard < g_guard_end) {
        uint32_t guard_index = guard - g_guard_start;
        g_hit_guards.insert(guard_index);
    }
}

extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end) {
    g_pc_table_start = pcs_beg;
    g_pc_table_end = pcs_end;
}

// Constructor: initialize shared memory early
__attribute__((constructor(101)))
static void init_coverage_agent() {
    FILE* log = fopen("/tmp/coverage_agent.log", "a");
    if (log) {
        fprintf(log, "[AGENT] Loaded at %ld, pid=%d\n", time(nullptr), getpid());
        fclose(log);
    }
    
    const char* shm_name = getenv("COVERAGE_SHM_NAME");
    if (shm_name && shm_name[0] != '\0') {
        init_shm(shm_name);
    }
}

// Destructor: write hit guards to shared memory before exit (priority 200)
__attribute__((destructor(200)))
static void write_guards_before_cleanup() {
    if (!g_shm) {
        const char* shm_name = getenv("COVERAGE_SHM_NAME");
        if (shm_name && shm_name[0] != '\0') {
            init_shm(shm_name);
        }
        if (!g_shm) {
            return;
        }
    }
    
    // Write hit guards bitmap
    uint32_t guard_count = g_shm->guard_count.load();
    if (guard_count > 0 && !g_hit_guards.empty()) {
        // Clear bitmap
        memset(g_shm->hit_guards, 0, MAX_GUARDS / 8);
        
        // Set bits for hit guards
        for (uint32_t guard_idx : g_hit_guards) {
            if (guard_idx < guard_count && guard_idx < MAX_GUARDS) {
                size_t byte_idx = guard_idx / 8;
                size_t bit_idx = guard_idx % 8;
                g_shm->hit_guards[byte_idx] |= (1 << bit_idx);
            }
        }
        
        g_shm->hit_guard_count.store((uint32_t)g_hit_guards.size());
        
        FILE* log = fopen("/tmp/coverage_agent.log", "a");
        if (log) {
            fprintf(log, "[AGENT] Wrote %zu hit guards to shm! pid=%d\n",
                    g_hit_guards.size(), getpid());
            fclose(log);
        }
    }
    
    // Copy PC table
    if (g_pc_table_start && g_pc_table_end) {
        size_t pc_pairs = (g_pc_table_end - g_pc_table_start) / 2;
        size_t pcs_to_copy = std::min(pc_pairs, MAX_PCS);
        for (size_t i = 0; i < pcs_to_copy; i++) {
            g_shm->pc_table[i] = g_pc_table_start[i * 2];
        }
        g_shm->pc_table_size.store((uint32_t)pcs_to_copy);
    }
    
    __sync_synchronize();
}

// Destructor: cleanup (priority 300)
__attribute__((destructor(300)))
static void cleanup_coverage_agent() {
    if (g_shm_fd >= 0) {
        close(g_shm_fd);
        g_shm_fd = -1;
    }
}
