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

// AFL++-style 64KB bitmap for edge coverage
constexpr size_t BITMAP_SIZE = 65536;

// Global state
static uint8_t* g_bitmap = nullptr;
static int g_shm_fd = -1;

// Initialize shared memory bitmap
__attribute__((no_sanitize("coverage")))
static void init_shm(const char* shm_name) {
    if (g_bitmap) return;

    g_shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (g_shm_fd == -1) return;

    if (ftruncate(g_shm_fd, BITMAP_SIZE) == -1) {
        close(g_shm_fd);
        g_shm_fd = -1;
        return;
    }

    g_bitmap = (uint8_t*)mmap(nullptr, BITMAP_SIZE, PROT_READ | PROT_WRITE,
                              MAP_SHARED, g_shm_fd, 0);
    if (g_bitmap == MAP_FAILED) {
        close(g_shm_fd);
        g_shm_fd = -1;
        g_bitmap = nullptr;
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
            // Debug: verify our coverage agent is being used (not LLVM's runtime)
            if (getenv("COVERAGE_AGENT_DEBUG")) {
                fprintf(stderr, "[coverage_agent] Initialized SHM: %s (bitmap=%p)\n", 
                        shm_name, (void*)g_bitmap);
            }
        } else {
            const char* shm_name = getenv("COVERAGE_SHM_NAME");
            if (shm_name) {
                init_shm(shm_name);
                if (getenv("COVERAGE_AGENT_DEBUG")) {
                    fprintf(stderr, "[coverage_agent] Initialized custom SHM: %s (bitmap=%p)\n",
                            shm_name, (void*)g_bitmap);
                }
            } else if (getenv("COVERAGE_AGENT_DEBUG")) {
                fprintf(stderr, "[coverage_agent] No SHM configured (__AFL_SHM_ID or COVERAGE_SHM_NAME not set)\n");
            }
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
