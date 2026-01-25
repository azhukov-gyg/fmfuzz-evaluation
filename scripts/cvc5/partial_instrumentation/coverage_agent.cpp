/*
 * Minimal coverage agent for AFL++ fuzzing.
 * 
 * Only handles edge coverage via -fsanitize-coverage=trace-pc-guard.
 * Function call counts are handled by LLVM's PGO (-fprofile-instr-generate).
 *
 * Build: clang++ -c -o coverage_agent.o coverage_agent.cpp -O2 -g -std=c++17
 * Link: Statically link into target binary via CMAKE_EXE_LINKER_FLAGS
 */

#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstdio>
#include <cerrno>

// AFL-style bitmap for edge coverage (1KB)
constexpr size_t BITMAP_SIZE = 1024;

// Global state
static uint8_t* g_bitmap = nullptr;
static int g_shm_fd = -1;
static uint32_t g_total_edges = 0;  // Total instrumented edges

// Initialize shared memory bitmap
__attribute__((no_sanitize("coverage")))
static void init_shm(const char* shm_name) {
    if (g_bitmap) return;

    g_shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (g_shm_fd == -1) {
        if (getenv("COVERAGE_AGENT_DEBUG")) {
            fprintf(stderr, "[coverage_agent] ERROR: shm_open(%s) failed: %s (errno=%d)\n", 
                    shm_name, strerror(errno), errno);
        }
        return;
    }

    if (ftruncate(g_shm_fd, BITMAP_SIZE) == -1) {
        if (getenv("COVERAGE_AGENT_DEBUG")) {
            fprintf(stderr, "[coverage_agent] ERROR: ftruncate(%s) failed: %s (errno=%d)\n", 
                    shm_name, strerror(errno), errno);
        }
        close(g_shm_fd);
        g_shm_fd = -1;
        return;
    }

    g_bitmap = (uint8_t*)mmap(nullptr, BITMAP_SIZE, PROT_READ | PROT_WRITE,
                              MAP_SHARED, g_shm_fd, 0);
    if (g_bitmap == MAP_FAILED) {
        if (getenv("COVERAGE_AGENT_DEBUG")) {
            fprintf(stderr, "[coverage_agent] ERROR: mmap(%s) failed: %s (errno=%d)\n", 
                    shm_name, strerror(errno), errno);
        }
        close(g_shm_fd);
        g_shm_fd = -1;
        g_bitmap = nullptr;
    } else {
        if (getenv("COVERAGE_AGENT_DEBUG")) {
            fprintf(stderr, "[coverage_agent] SUCCESS: attached to shm %s, bitmap=%p\n", 
                    shm_name, (void*)g_bitmap);
        }
    }
}

// Sanitizer coverage: initialize guards
extern "C" __attribute__((visibility("default")))
void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
    static uint32_t guard_id = 0;

    if (start == stop || *start) return;

    for (uint32_t* x = start; x < stop; x++) {
        *x = ++guard_id;
    }
    
    // Update total edges count
    g_total_edges = guard_id;

    if (!g_bitmap) {
        // Try AFL++ shared memory first
        const char* shm_id = getenv("__AFL_SHM_ID");
        if (shm_id) {
            char shm_name[64];
            snprintf(shm_name, sizeof(shm_name), "/afl_shm_%s", shm_id);
            init_shm(shm_name);
        } else {
            // Fall back to custom shared memory name
            const char* shm_name = getenv("COVERAGE_SHM_NAME");
            if (shm_name) {
                init_shm(shm_name);
            }
        }
    }
}

// Sanitizer coverage: record edge hit (HOT PATH - keep minimal!)
extern "C" __attribute__((visibility("default")))
void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
    if (!g_bitmap || !guard || !*guard) return;

    // Set bit in bitmap (AFL++ style)
    uint32_t idx = *guard;
    g_bitmap[idx % BITMAP_SIZE]++;
}

// Constructor: initialize shared memory
__attribute__((constructor(101)))
static void init_coverage_agent() {
    if (!g_bitmap) {
        const char* shm_id = getenv("__AFL_SHM_ID");
        if (shm_id) {
            char shm_name[64];
            snprintf(shm_name, sizeof(shm_name), "/afl_shm_%s", shm_id);
            init_shm(shm_name);
        } else {
            const char* shm_name = getenv("COVERAGE_SHM_NAME");
            if (shm_name) {
                init_shm(shm_name);
            }
        }
    }
    
    // Debug output (set COVERAGE_AGENT_DEBUG=1 to see total edges)
    if (getenv("COVERAGE_AGENT_DEBUG")) {
        fprintf(stderr, "[coverage_agent] total_edges=%u, bitmap=%p, shm_fd=%d\n", 
                g_total_edges, (void*)g_bitmap, g_shm_fd);
        if (!g_bitmap) {
            fprintf(stderr, "[coverage_agent] WARNING: No shared memory attached - coverage will not be recorded!\n");
        }
    }
}

// Destructor: cleanup
__attribute__((destructor))
static void cleanup_coverage_agent() {
    if (g_bitmap && g_bitmap != MAP_FAILED) {
        munmap(g_bitmap, BITMAP_SIZE);
        g_bitmap = nullptr;
    }
    if (g_shm_fd >= 0) {
        close(g_shm_fd);
        g_shm_fd = -1;
    }
}
