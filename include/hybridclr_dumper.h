#ifndef HYBRIDCLR_DUMPER_H
#define HYBRIDCLR_DUMPER_H

#include <stdint.h>

#define HYBRIDCLR_DUMPER_ABI_VERSION 2u
#define HYBRIDCLR_DUMPER_EXPORT __attribute__((visibility("default")))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HybridClrDumpOptions {
    uint32_t struct_size;
    uint32_t abi_version;
    /* All settings and target function RVAs are read from this absolute path. */
    const char* config_path;
    /* The caller must keep a real loading/lifetime gate held until completion. */
    uint32_t stable_window_confirmed;
} HybridClrDumpOptions;

enum HybridClrDumpResult {
    HYBRIDCLR_DUMP_OK = 0,
    HYBRIDCLR_DUMP_INCOMPLETE = 1,
    HYBRIDCLR_DUMP_INVALID_OPTIONS = -1,
    HYBRIDCLR_DUMP_BUSY = -2,
    HYBRIDCLR_DUMP_ERROR = -3,
    HYBRIDCLR_DUMP_CANCELLED = -4
};

enum HybridClrDumpState {
    HYBRIDCLR_DUMP_IDLE = 0,
    HYBRIDCLR_DUMP_RUNNING = 1,
    HYBRIDCLR_DUMP_FINISHED = 2
};

/* Synchronous entry for an application-controlled stable window. */
HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_run(const HybridClrDumpOptions* options);
/* Loads/copies the configuration and starts a dedicated native thread. */
HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_start(const HybridClrDumpOptions* options);
HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_state(void);
HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_result(void);
/* Cooperative cancellation only; does not interrupt a native runtime call. */
HYBRIDCLR_DUMPER_EXPORT void hybridclr_dump_cancel(void);

#ifdef __cplusplus
}
#endif

#endif
