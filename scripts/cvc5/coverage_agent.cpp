/*
 * Coverage agent for SanitizerCoverage using inline-8bit-counters.
 * Writes coverage to shared memory for Python fuzzer to read.
 * 
 * Build: clang++ -shared -fPIC -o libcov_agent.so coverage_agent.cpp -O2 -g -lrt
 * Usage: LD_PRELOAD=./libcov_agent.so COVERAGE_SHM_NAME=shm_name ./binary
 */

#include <atomic>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>

constexpr size_t MAX_COUNTERS = 65536;
constexpr size_t MAX_PCS = 65536;

struct CovShm {
    std::atomic<uint32_t> pid{0};
    std::atomic<uint32_t> counter_count{0};
    std::atomic<uint32_t> pc_table_size{0};
    uint8_t counters[MAX_COUNTERS];
    uintptr_t pc_table[MAX_PCS];
};

constexpr size_t SHM_SIZE = sizeof(CovShm);

static CovShm* g_shm = nullptr;
static char* g_counters_start = nullptr;
static char* g_counters_end = nullptr;
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
        memset(g_shm->counters, 0, MAX_COUNTERS);
        memset(g_shm->pc_table, 0, MAX_PCS * sizeof(uintptr_t));
        g_shm->counter_count.store(0);
        g_shm->pc_table_size.store(0);
    }
}

// Sanitizer callbacks - these override weak symbols from compiler-rt
extern "C" void __sanitizer_cov_8bit_counters_init(char* start, char* stop) {
    g_counters_start = start;
    g_counters_end = stop;
    
    if (start && stop && stop > start) {
        const char* shm_name = getenv("COVERAGE_SHM_NAME");
        if (shm_name && shm_name[0] != '\0') {
            init_shm(shm_name);
            if (g_shm) {
                size_t count = std::min(static_cast<size_t>(stop - start), MAX_COUNTERS);
                g_shm->counter_count.store((uint32_t)count);
            }
        }
    }
}

extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end) {
    g_pc_table_start = pcs_beg;
    g_pc_table_end = pcs_end;
}

// Constructor: initialize shared memory early
__attribute__((constructor(101)))
static void init_coverage_agent() {
    const char* shm_name = getenv("COVERAGE_SHM_NAME");
    if (shm_name && shm_name[0] != '\0') {
        init_shm(shm_name);
    }
}

// Destructor: copy counters to shared memory before exit (priority 200)
__attribute__((destructor(200)))
static void copy_counters_before_cleanup() {
    if (!g_shm) {
        const char* shm_name = getenv("COVERAGE_SHM_NAME");
        if (shm_name && shm_name[0] != '\0') {
            init_shm(shm_name);
        }
        if (!g_shm) {
            return;
        }
    }
    
    // Copy counters
    uint32_t counter_count = g_shm->counter_count.load();
    if (g_counters_start && g_counters_end && (g_counters_end > g_counters_start)) {
        size_t count = std::min(static_cast<size_t>(g_counters_end - g_counters_start), MAX_COUNTERS);
        memcpy(g_shm->counters, g_counters_start, count);
        counter_count = (uint32_t)count;
        g_shm->counter_count.store(counter_count);
    }
    
    // Copy PC table: format is [PC, PCFlags] pairs, extract only PCs
    if (g_pc_table_start && g_pc_table_end) {
        size_t pc_pairs = (g_pc_table_end - g_pc_table_start) / 2;
        size_t pcs_to_copy = std::min(pc_pairs, MAX_PCS);
        for (size_t i = 0; i < pcs_to_copy; i++) {
            g_shm->pc_table[i] = g_pc_table_start[i * 2];
        }
        g_shm->pc_table_size.store((uint32_t)pcs_to_copy);
    } else {
        g_shm->pc_table_size.store(counter_count);
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

