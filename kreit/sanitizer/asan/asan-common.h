#ifndef __ASAN_COMMON_H__
#define __ASAN_COMMON_H__

#include "qemu/osdep.h"
#include "kreit/instrument/app.h"
#include "kreit/kreit.h"
#include "qemu/thread.h"
#include "qemu/timer.h"

typedef enum AsanHookType {
    ASAN_HOOK_TYPE_INVALID,
    ASAN_HOOK_ALLOC_KMEM_CACHE,
    ASAN_HOOK_ALLOC_SIZE_IN_REGS,
    ASAN_HOOK_ALLOC_BULK,
    ASAN_HOOK_KSIZE,
    ASAN_HOOK_FREE,
    ASAN_HOOK_FREE_BULK,
    ASAN_HOOK_WHITELIST,
    ASAN_HOOK_PREP_COMPOUND_PAGE,
    ASAN_HOOK_CLEAR_PAGE_REP,
    ASAN_HOOK_HANDLE_MM_PAGE_FAULT,
    ASAN_HOOK_QNX_SREALLOC,
    ASAN_HOOK_TYPE_END,
} AsanHookType;

typedef struct KreitAsanInstrInfo {
    AsanHookType type;
    int param_order;
    vaddr addr;
} KreitAsanInstrInfo;

typedef struct AsanAllocatedInfo {
    bool in_use;

    // AsanHookType hook_type;
    int pid;
    vaddr asan_chunk_start;
    size_t request_size;
    size_t chunk_size;
    size_t redzone_size;
    vaddr allocated_at;

    vaddr free_at;
    int free_pid;
} AsanAllocatedInfo;

typedef struct KreitAsanState KreitAsanState;
typedef struct AsanThreadInfo AsanThreadInfo;
typedef struct KreitPendingHook KreitPendingHook;

typedef struct AsanThreadInfo {
    int pid;
    bool asan_enabled;
    char process_name[PROCESS_NAME_LENGTH];

    // context info

    // for kmem_cache_alloc
    bool in_kmem_cache_alloc;
    bool need_retry_alloc;
    vaddr last_allocated_addr;
    vaddr last_last_allocated_addr;
    int alloc_count;
    AsanAllocatedInfo *kmem_cache_allocated_info;
    void *storaged_regs;
    size_t align_size;
} AsanThreadInfo;

typedef struct KreitPendingHook {
    // hook info
    KreitAsanInstrInfo* hook_info;

    // context info
    AsanThreadInfo *thread_info;
    vaddr ret_addr;
    vaddr stack_ptr;
    int cpl;

    bool staged_asan_state;
    void (*trace_start)(KreitAsanState *appdata, CPUArchState *env, KreitPendingHook *thread_info);
    void (*trace_finished)(KreitAsanState *appdata, CPUArchState *env, KreitPendingHook *thread_info);

    AsanAllocatedInfo *allocated_info;

    // ksize info
    vaddr ksize_ptr;

    // bulk info
    size_t nr_bulk;
    vaddr bulk_array;

    // qnx assistance info
    size_t qnx_old_size;
    size_t qnx_new_size;
} KreitPendingHook;

typedef struct KreitAsanState {
    /*< private >*/
    KreitAppState parent_obj;

    /*< public >*/
    KreitAsanInstrInfo *asan_hook;
    size_t nr_asan_hook;
    size_t size_offset;
    size_t align_offset;

    void *shadow_base;

    // per-run data
    QemuSpin asan_threadinfo_lock;
    GHashTable *asan_threadinfo;

    QemuSpin asan_allocated_info_lock;
    GHashTable *asan_allocated_info;

    vaddr alloc_range_start;
    vaddr alloc_range_end;

    GHashTable *pending_hooks; // KreitPendingHook
    QemuSpin pending_hooks_lock;
    size_t nr_pending_hooks;
} KreitAsanState;

typedef struct KreitAsanOps {
    void * (*get_shadow_addr)(vaddr addr);
    bool (*check_range)(vaddr addr);
} KreitAsanOps;

extern KreitAsanOps asan_ops;
extern KreitAsanState *asan_state;

#define REDZONE_SIZE 128

static inline void *get_shadow_addr(vaddr addr)
{
    return (void *) ((addr - asan_state->alloc_range_start) >> 3) + (vaddr) asan_state->shadow_base;
}

static inline bool asan_check_range(vaddr addr)
{
    return (addr < asan_state->alloc_range_end && addr >= asan_state->alloc_range_start);
}

size_t asan_allocator_aligned_size(size_t size);
// AsanThreadInfo *asan_get_thread_info(void);
AsanAllocatedInfo *asan_get_allocated_info(vaddr addr);

void asan_poison_region(vaddr ptr, size_t n, uint8_t poison_byte);
void asan_unpoison_region(vaddr ptr, size_t n);
int asan_giovese_report_and_crash(int access_type, vaddr addr, size_t n,
                                  CPUArchState *env);

int asan_giovese_load1(vaddr ptr);
int asan_giovese_load2(vaddr ptr);
int asan_giovese_load4(vaddr ptr);
int asan_giovese_load8(vaddr ptr);
int asan_giovese_load16(vaddr ptr);
int asan_giovese_store1(vaddr ptr);
int asan_giovese_store2(vaddr ptr);
int asan_giovese_store4(vaddr ptr);
int asan_giovese_store8(vaddr ptr);
int asan_giovese_store16(vaddr ptr);

/* shadow map byte values */
#define ASAN_VALID 0x00
#define ASAN_PARTIAL1 0x01
#define ASAN_PARTIAL2 0x02
#define ASAN_PARTIAL3 0x03
#define ASAN_PARTIAL4 0x04
#define ASAN_PARTIAL5 0x05
#define ASAN_PARTIAL6 0x06
#define ASAN_PARTIAL7 0x07
#define ASAN_ARRAY_COOKIE 0xac
#define ASAN_STACK_RZ 0xf0
#define ASAN_STACK_LEFT_RZ 0xf1
#define ASAN_STACK_MID_RZ 0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED 0xf5
#define ASAN_STACK_OOSCOPE 0xf8
#define ASAN_GLOBAL_RZ 0xf9
#define ASAN_HEAP_RZ 0xe9
#define ASAN_USER 0xf7
#define ASAN_HEAP_LEFT_RZ 0xfa
#define ASAN_HEAP_RIGHT_RZ 0xfb
#define ASAN_HEAP_FREED 0xfd

enum {
    ACCESS_TYPE_LOAD,
    ACCESS_TYPE_STORE,
    ACCESS_TYPE_DOUBLE_FREE,
};

static inline gpointer thread_info_hash_key(int pid, int cpu_index)
{
    switch (kcont.target) {
    case TRACE_TARGET_LINUX:
        if (pid == 0)
            return (gpointer) (((uint64_t) cpu_index << 32) | ((uint64_t) pid & 0xffffffff));
        else
            return GUINT_TO_POINTER(pid);
    case TRACE_TARGET_QNX:
        if (pid == 1)
            return (gpointer) (((uint64_t) cpu_index << 32) | ((uint64_t) pid & 0xffffffff));
        else
            return GUINT_TO_POINTER(pid);
    default:
        return 0;
    }
}

#endif // __ASAN_COMMON_H__
