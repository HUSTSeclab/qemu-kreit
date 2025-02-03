#include "kreit/instrument/app.h"
#include "kreit/kreit.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qstring.h"
#include "qapi/visitor.h"
#include "qemu/log.h"
#include "kreit_target.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "tcg/tcg.h"
#include "exec/helper-proto-common.h"
#include "exec/helper-gen-common.h"
#include "asan-common.h"

#define KREIT_ASAN_APPNAME "asan"
#define TYPE_KREIT_ASAN KREITAPP_CLASS_NAME(KREIT_ASAN_APPNAME)

DECLARE_INSTANCE_CHECKER(KreitAsanState, KREIT_ASAN_STATE,
                         TYPE_KREIT_ASAN)

static inline AsanAllocatedInfo *alloc_asan_allocated_info(void)
{
    AsanAllocatedInfo *ret = g_malloc0(sizeof(AsanAllocatedInfo));
    ret->stack_record = g_malloc(sizeof(uint64_t) * asan_state->stack_record_len);
    return ret;
}

static inline void free_asan_allocated_info(AsanAllocatedInfo *info)
{
    g_free(info->stack_record);
    g_free(info);
}

static void g_free_asan_allocated_info(gpointer ptr)
{
    AsanAllocatedInfo *info = ptr;
    free_asan_allocated_info(info);
}

static void copy_stack_to_allocated_info(CPUArchState *env, AsanAllocatedInfo *info)
{
    CPUState *cpu = env_cpu(env);
    vaddr rsp = kreit_get_stack_ptr(env);

    for (int i = 0; i < asan_state->stack_record_len; i++) {
        info->stack_record[i] = kreit_cpu_ldq(cpu, rsp + 8 * i);
    }
}

static inline gpointer pending_hook_hash_key(vaddr ret_addr, vaddr stack_ptr)
{
    return (gpointer) ((ret_addr << 32) | (stack_ptr & 0xffffffff));
}

static void app_asan_insert_asan_helper(void *instr_data, void *userdata)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(userdata);
    target_ulong this_pc = (target_ulong) instr_data;
    TCGv_i32 hook_index;

    for (int i = 0; i < kas->nr_asan_hook; i++) {
        if (this_pc == kas->asan_hook[i].addr) {
            hook_index = tcg_constant_i32(i);
            gen_helper_kreit_trace_asan_hook(cpu_env, hook_index);
            break;
        }
    }
}

static size_t get_linux_alloc_size(KreitAsanState* kas,
    CPUArchState *env, KreitAsanInstrInfo *hook)
{
    vaddr kmem_cache_ptr;

    switch (hook->type) {
        case ASAN_HOOK_ALLOC_KMEM_CACHE:
        case ASAN_HOOK_ALLOC_BULK:
            kmem_cache_ptr = kreit_get_abi_param(env, 1);
            return kreit_cpu_ldl(env_cpu(env), kmem_cache_ptr + kas->size_offset);
        case ASAN_HOOK_ALLOC_SIZE_IN_REGS:
            return kreit_get_abi_param(env, hook->param_order);
        default:
            return 0;
    }
}

static size_t get_linux_cache_align(KreitAsanState* kas, CPUArchState *env)
{
    vaddr kmem_cache_ptr;
    kmem_cache_ptr = kreit_get_abi_param(env, 1);
    return kreit_cpu_ldl(env_cpu(env), kmem_cache_ptr + kas->align_offset);
}

static void insert_allocated_info(AsanAllocatedInfo *allocated_info)
{
    AsanAllocatedInfo *res;
    vaddr chunk = allocated_info->data_start;

    res = g_hash_table_lookup(asan_state->asan_allocated_info, (gpointer) chunk);
    if (res) {
        if (res->in_use && kreitapp_get_verbose(OBJECT(asan_state)) >= 1)
            qemu_log("warn: insert existing in use chunk %#018lx\n", chunk);
        g_hash_table_remove(asan_state->asan_allocated_info, (gpointer) chunk);
    }
    g_hash_table_insert(asan_state->asan_allocated_info, (gpointer) chunk, allocated_info);
}

static inline void sanitizer_state_stash_push(AsanThreadInfo *thread_info,
    KreitPendingHook *pending_hook)
{
    // disable kasan before returning
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    pending_hook->staged_msan_state = thread_info->msan_enabled;
    thread_info->asan_enabled = false;
    thread_info->msan_enabled = false;
}

static inline void sanitizer_state_stash_pop(AsanThreadInfo *thread_info,
    KreitPendingHook *pending_hook)
{
    thread_info->asan_enabled = pending_hook->staged_asan_state;
    thread_info->msan_enabled = pending_hook->staged_msan_state;
}

static void asan_trace_linux_size_in_regs(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    size_t request_size;
    int gfp_flag;
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    request_size = get_linux_alloc_size(appdata, env, pending_hook->hook_info);
    gfp_flag = kreit_get_abi_param(env, pending_hook->hook_info->flag_order);
    if (gfp_flag & __GFP_ZERO)
        pending_hook->value_initialized = true;

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: size_in_regs) size: %ld, ret addr: %#018lx, rsp: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            request_size,
            pending_hook->ret_addr, pending_hook->stack_ptr);
    }

    allocated_info = alloc_asan_allocated_info();
    allocated_info->pid = pid;
    allocated_info->allocated_at =
        kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
    copy_stack_to_allocated_info(env, allocated_info);

    if (request_size + REDZONE_SIZE <= 2097152) {
        // The max cache size of __kmalloc is 2097152
        // So do not add redzone while request size is too large
        allocated_info->chunk_size =
            asan_allocator_aligned_size(request_size + REDZONE_SIZE);
        g_assert(allocated_info->chunk_size);
        allocated_info->redzone_size =
            allocated_info->chunk_size - ROUND_UP(request_size, 8);
        allocated_info->request_size = request_size;

        // request a larger chunk
        kreit_set_abi_reg_param(env,
            pending_hook->hook_info->param_order,
            allocated_info->chunk_size);
    } else {
        allocated_info->chunk_size = request_size;
        g_assert(allocated_info->chunk_size);
        allocated_info->redzone_size = 0;
        allocated_info->request_size = request_size;
    }

    // store the unmature allocated_info
    pending_hook->allocated_info = allocated_info;
}

static void asan_trace_linux_size_in_regs_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info = pending_hook->allocated_info;
    vaddr redzone_start;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    allocated_info->data_start = kreit_get_return_value(env);
    allocated_info->in_use = true;

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: size_in_regs) finished, return value: %#018lx, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            allocated_info->data_start,
            kreit_get_pc(env),
            kreit_get_stack_ptr(env) - 8);
    }

    asan_unpoison_region(allocated_info->data_start,
        allocated_info->chunk_size);

    if (pending_hook->staged_msan_state && !pending_hook->value_initialized)
        asan_poison_region(allocated_info->data_start,
            allocated_info->chunk_size, MSAN_UNINITILIZED);
    redzone_start = allocated_info->data_start +
        allocated_info->chunk_size - allocated_info->redzone_size;
    asan_poison_region(redzone_start,
        allocated_info->redzone_size, ASAN_HEAP_RIGHT_RZ);

    qemu_spin_lock(&appdata->asan_allocated_info_lock);
    insert_allocated_info(allocated_info);
    qemu_spin_unlock(&appdata->asan_allocated_info_lock);
}

static void asan_trace_linux_kmem_cache_create(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    unsigned int request_size;
    unsigned int new_size;
    unsigned int align;
    vaddr ctor;
    AsanCacheInfo *cache_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    request_size = (unsigned int) kreit_get_abi_param(env, 2);
    align = (unsigned int) kreit_get_abi_param(env, 3);
    ctor = kreit_get_abi_param(env, 5);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: kmem_cache_create with size: %d, align: %d\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            request_size, align);
    }

    cache_info = g_malloc0(sizeof(AsanCacheInfo));
    cache_info->request_size = request_size;
    // Reset the cache size with redzone
    if (align == 0)
        align = 8;
    if (ctor)
        cache_info->has_ctor = true;
    new_size = ROUND_UP(request_size, align) * 2;
    cache_info->redzone_size = ROUND_UP(request_size, align);
    pending_hook->cache_info = cache_info;

    // qemu_log("new request size %d\n", new_size);
    kreit_set_abi_reg_param(env, 2, (uint64_t) new_size);
}

static void asan_trace_linux_kmem_cache_create_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanCacheInfo *cache_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    cache_info = pending_hook->cache_info;
    cache_info->cache_addr = kreit_get_return_value(env);

    cache_info->size = kreit_cpu_ldl(env_cpu(env), cache_info->cache_addr + appdata->size_offset);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: kmem_cache_create finished, return value: %#018lx, cache size: %ld\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            cache_info->cache_addr, cache_info->size);
    }

    qemu_spin_lock(&appdata->asan_kmem_cache_lock);
    g_hash_table_insert(appdata->asan_kmem_cache, (gpointer) cache_info->cache_addr, cache_info);
    qemu_spin_unlock(&appdata->asan_kmem_cache_lock);
}

static void asan_trace_linux_kmem_cache_alloc(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    size_t request_size;
    size_t align_size;
    vaddr cache_addr;
    int gfp_flag;
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info;
    AsanCacheInfo *cache_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    request_size = get_linux_alloc_size(appdata, env, pending_hook->hook_info);
    align_size = get_linux_cache_align(appdata, env);
    cache_addr = kreit_get_abi_param(env, 1);
    gfp_flag = kreit_get_abi_param(env, pending_hook->hook_info->flag_order);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: kmem_cache) size: %ld, align: %ld, ret addr: %#018lx, rsp: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            request_size, align_size,
            pending_hook->ret_addr, pending_hook->stack_ptr);
    }

    qemu_spin_lock(&appdata->asan_kmem_cache_lock);
    cache_info = g_hash_table_lookup(appdata->asan_kmem_cache, (gpointer) cache_addr);
    qemu_spin_unlock(&appdata->asan_kmem_cache_lock);

    allocated_info = alloc_asan_allocated_info();
    allocated_info->pid = pid;
    allocated_info->allocated_at =
        kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
    copy_stack_to_allocated_info(env, allocated_info);

    if (cache_info) {
        allocated_info->chunk_size = cache_info->size;
        allocated_info->request_size = cache_info->request_size;
        allocated_info->redzone_size = cache_info->redzone_size;

        if ((gfp_flag & __GFP_ZERO) || cache_info->has_ctor)
            pending_hook->value_initialized = true;
    } else {
        // qemu_log("qkasan: warning: cannot find cache_info!\n");
        allocated_info->chunk_size = request_size;
        allocated_info->redzone_size = 0;
        allocated_info->request_size = request_size;

        if (gfp_flag & __GFP_ZERO)
            pending_hook->value_initialized = true;
    }

    // store the unmature allocated_info
    pending_hook->allocated_info = allocated_info;
}

static void asan_trace_linux_kmem_cache_alloc_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info = pending_hook->allocated_info;
    vaddr redzone_start;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    allocated_info->data_start = kreit_get_return_value(env);
    allocated_info->in_use = true;

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: kmem_cache) finished, return value: %#018lx, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            allocated_info->data_start,
            kreit_get_pc(env),
            kreit_get_stack_ptr(env) - 8);
    }

    asan_unpoison_region(allocated_info->data_start,
        allocated_info->chunk_size);

    if (pending_hook->staged_msan_state && !pending_hook->value_initialized)
        asan_poison_region(allocated_info->data_start,
            allocated_info->chunk_size, MSAN_UNINITILIZED);
    redzone_start = allocated_info->data_start +
        allocated_info->chunk_size - allocated_info->redzone_size;
    asan_poison_region(redzone_start,
        allocated_info->redzone_size, ASAN_HEAP_RIGHT_RZ);

    qemu_spin_lock(&appdata->asan_allocated_info_lock);
    insert_allocated_info(allocated_info);
    qemu_spin_unlock(&appdata->asan_allocated_info_lock);
}

static void asan_trace_linux_bulk_alloc(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    pending_hook->nr_bulk = kreit_get_abi_param(env, 3);
    pending_hook->bulk_array = kreit_get_abi_param(env, 4);

    allocated_info = alloc_asan_allocated_info();

    allocated_info->request_size =
        get_linux_alloc_size(appdata, env, pending_hook->hook_info);
    allocated_info->chunk_size = allocated_info->request_size;
    allocated_info->pid = pid;
    allocated_info->allocated_at =
        kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
    copy_stack_to_allocated_info(env, allocated_info);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: bulk_alloc) size: %ld, nr_bulk: %ld, ret addr: %#018lx, rsp: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            allocated_info->request_size, pending_hook->nr_bulk,
            pending_hook->ret_addr, pending_hook->stack_ptr);
    }

    // store the unmature allocated_info
    pending_hook->allocated_info = allocated_info;
}

static void asan_trace_linux_bulk_alloc_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    size_t nr_bulk;
    size_t allocated_addr;
    AsanAllocatedInfo *common_allocated_info = pending_hook->allocated_info;
    AsanAllocatedInfo *bulk_allocated_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    nr_bulk = kreit_get_return_value(env);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: bulk_alloc) finished, return value: %ld, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            nr_bulk,
            kreit_get_pc(env), kreit_get_stack_ptr(env) - 8);
    }

    for (int i = 0; i < nr_bulk; i++) {
        allocated_addr = kreit_cpu_ldq(env_cpu(env),
            pending_hook->bulk_array + 8 * i);

        if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
            qemu_log("\tbulk info %d: allocated address: %#018lx\n", i, allocated_addr);

        asan_unpoison_region(allocated_addr, common_allocated_info->chunk_size);
        bulk_allocated_info = alloc_asan_allocated_info();

        bulk_allocated_info->in_use = true;
        bulk_allocated_info->request_size = common_allocated_info->request_size;
        bulk_allocated_info->chunk_size = common_allocated_info->chunk_size;
        bulk_allocated_info->pid = common_allocated_info->pid;
        bulk_allocated_info->allocated_at = common_allocated_info->allocated_at;
        bulk_allocated_info->data_start = allocated_addr;
        qemu_spin_lock(&appdata->asan_allocated_info_lock);
        insert_allocated_info(bulk_allocated_info);
        qemu_spin_unlock(&appdata->asan_allocated_info_lock);
    }

    free_asan_allocated_info(common_allocated_info);
}

static void asan_trace_linux_ksize(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    pending_hook->ksize_ptr = kreit_get_abi_param(env, 1);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: ksize param %#018lx\n", pending_hook->ksize_ptr);
    }
}

static void asan_trace_linux_ksize_finished(KreitAsanState *appdata,
    CPUArchState* env,KreitPendingHook *pending_hook)
{
    size_t ksize = kreit_get_return_value(env);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: ksize return value %ld\n", ksize);
    }

    if (ksize)
        asan_unpoison_region(pending_hook->ksize_ptr, ksize);
}

static void asan_trace_linux_free(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    int param_order = pending_hook->hook_info->param_order;
    vaddr free_addr;
    AsanAllocatedInfo *allocated_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    free_addr = kreit_get_abi_param(env, param_order);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: free ptr: %#018lx, ret addr: %#018lx, rsp: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            free_addr,
            pending_hook->ret_addr, pending_hook->stack_ptr);
    }

    qemu_spin_lock(&appdata->asan_allocated_info_lock);
    allocated_info = g_hash_table_lookup(appdata->asan_allocated_info, (gpointer) free_addr);
    qemu_spin_unlock(&appdata->asan_allocated_info_lock);

    if (!allocated_info)
        return;

    if (allocated_info->in_use) {
        asan_poison_region(free_addr, allocated_info->chunk_size, ASAN_HEAP_FREED);
        allocated_info->in_use = false;
        allocated_info->free_at = kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
        allocated_info->free_pid = pid;
    } else {
        if (*((uint8_t *) get_shadow_addr(allocated_info->data_start)) & ASAN_POISONED) {
            // Some chunk may be unpoison by clear_page but still marked
            // as not in use.
            asan_giovese_report_and_crash(ACCESS_TYPE_DOUBLE_FREE,
                allocated_info->data_start,
                1, env);
        }
    }
}

static void asan_trace_linux_free_finished(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: free finished, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            kreit_get_pc(env), kreit_get_stack_ptr(env) - 8);
    }
}

static void asan_trace_linux_free_bulk(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    vaddr free_addr;
    vaddr bulk_array_addr;
    size_t bulk_nr;
    AsanAllocatedInfo *bulk_allocated_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    bulk_array_addr = kreit_get_abi_param(env, 3);
    bulk_nr = kreit_get_abi_param(env, 2);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: free_bulk: bulk_nr: %ld, ret addr: %#018lx, rsp: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            bulk_nr,
            pending_hook->ret_addr, pending_hook->stack_ptr);
    }

    for (int i = 0; i < bulk_nr; i++) {
        free_addr = kreit_cpu_ldq(env_cpu(env), bulk_array_addr + 8 * i);

        if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
            qemu_log("\tbulk info %d: free address: %#018lx\n", i, free_addr);

        qemu_spin_lock(&appdata->asan_allocated_info_lock);
        bulk_allocated_info = g_hash_table_lookup(appdata->asan_allocated_info,
            (gpointer) free_addr);
        qemu_spin_unlock(&appdata->asan_allocated_info_lock);

        if (!bulk_allocated_info)
            continue;
        asan_poison_region(free_addr,
            bulk_allocated_info->chunk_size, ASAN_HEAP_FREED);
        bulk_allocated_info->in_use = false;
    }
}

static void asan_trace_linux_free_bulk_finished(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: free_bulk finished, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            kreit_get_pc(env), kreit_get_stack_ptr(env) - 8);
    }
}

static void asan_trace_memcpy(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    vaddr dest;
    vaddr src;
    size_t count;
    void *dest_shadow;
    void *src_shadow;
    size_t shadow_count;
    uint8_t shadow_byte;

    dest = kreit_get_abi_param(env, 1);
    src = kreit_get_abi_param(env, 2);
    count = kreit_get_abi_param(env, 3);

    sanitizer_state_stash_push(thread_info, pending_hook);
    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: memcpy dest: %#018lx src: %#018lx count: %ld\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            dest, src, count);
    }

    shadow_count = count >> 3;
    if (asan_check_range(dest)) {
        dest_shadow = get_shadow_addr(dest);
        for (int i = 0; i < shadow_count; i++) {
            shadow_byte = *((uint8_t *)(dest_shadow + i));
            if (shadow_byte & ASAN_POISONED) {
                asan_access_poisoned(env, dest + (i << 3), 8, ACCESS_TYPE_STORE);
            }
            if (shadow_byte & MSAN_UNINITILIZED) {
                msan_store_uninitialized(env, dest + (i << 3), 8);
            }
        }
    }

    if (asan_check_range(src)) {
        src_shadow = get_shadow_addr(src);

        for (int i = 0; i < shadow_count; i++) {
            shadow_byte = *((uint8_t *)(src_shadow + i));
            if (shadow_byte & ASAN_POISONED) {
                asan_access_poisoned(env, src + (i << 3), 8, ACCESS_TYPE_LOAD);
            }
            if (shadow_byte & MSAN_UNINITILIZED) {
                msan_load_uninitialized(env, src + (i << 3), 8);
            }
        }
    }

}

static void asan_trace_memcpy_finished(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    vaddr memcpy_ret;

    sanitizer_state_stash_pop(thread_info, pending_hook);
    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        memcpy_ret = kreit_get_return_value(env);
        qemu_log("memcpy return: %#018lx\n", memcpy_ret);
    }
}

static void asan_trace_qnx_srealloc(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    vaddr addr;
    size_t old_size;
    size_t new_size;
    AsanAllocatedInfo *old_allocated_info = NULL;
    AsanAllocatedInfo *new_allocated_info = NULL;
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    addr = kreit_get_abi_param(env, 1);
    old_size = kreit_get_abi_param(env, 2);
    new_size = kreit_get_abi_param(env, 3);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: srealloc addr %#018lx, old_size: %ld, new_size: %ld, ret addr: %#018lx rsp: %#018lx, rax: %#018lx, r8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            addr, old_size, new_size,
            pending_hook->ret_addr, pending_hook->stack_ptr,
            env->regs[R_EAX], env->regs[R_R8]);
    }


    if (old_size) {
        // do free
        qemu_spin_lock(&appdata->asan_allocated_info_lock);
        old_allocated_info = g_hash_table_lookup(appdata->asan_allocated_info, (gpointer) addr);
        qemu_spin_unlock(&appdata->asan_allocated_info_lock);

        if (old_allocated_info) {
            asan_poison_region(addr, old_allocated_info->chunk_size, ASAN_HEAP_FREED);
            if (!old_allocated_info->in_use)
                asan_giovese_report_and_crash(ACCESS_TYPE_DOUBLE_FREE, addr, 1, env);

            old_allocated_info->in_use = false;
        } else {
            if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
                qemu_log("qkasan: no allocated info found for address %#018lx when free\n", addr);
        }
    }

    if (new_size) {
        // do alloc
        // Extent the allocated size and set redzone
        new_allocated_info = alloc_asan_allocated_info();

        // new_allocated_info->hook_type = hook->type;

        new_allocated_info->request_size = new_size;
        new_allocated_info->chunk_size = ROUND_UP(new_size, 8) + REDZONE_SIZE;
        new_allocated_info->redzone_size = REDZONE_SIZE;

        kreit_set_abi_reg_param(env, 3, new_allocated_info->chunk_size);
    }

    if (new_allocated_info) {
        new_allocated_info->pid = pid;
        new_allocated_info->allocated_at = kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
        copy_stack_to_allocated_info(env, new_allocated_info);
    }

    pending_hook->allocated_info = new_allocated_info;
    pending_hook->qnx_old_size = old_size;
    pending_hook->qnx_new_size = new_size;
}

static void asan_trace_qnx_srealloc_finished(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    vaddr ret_ptr;
    vaddr prev_stack_ptr;
    vaddr curr_pc;
    AsanAllocatedInfo *allocated_info = NULL;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    curr_pc = kreit_get_pc(env);
    prev_stack_ptr = kreit_get_stack_ptr(env) - 8;
    ret_ptr = kreit_get_return_value(env);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: srealloc finished, return value: %#018lx, current eip: %#018lx rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            ret_ptr, curr_pc, prev_stack_ptr);
    }

    if (pending_hook->qnx_old_size) {
        // free ops of kasan has been done in asan_trace_qnx_srealloc
    }

    if (pending_hook->qnx_new_size) {
        allocated_info = pending_hook->allocated_info;

        if (ret_ptr) {
            allocated_info->data_start = ret_ptr;
            allocated_info->in_use = true;
            asan_unpoison_region(ret_ptr, allocated_info->chunk_size);

            vaddr redzone_start = ret_ptr + allocated_info->chunk_size - allocated_info->redzone_size;
            asan_poison_region(redzone_start, allocated_info->redzone_size, ASAN_HEAP_RIGHT_RZ);

            qemu_spin_lock(&appdata->asan_allocated_info_lock);
            insert_allocated_info(allocated_info);
            qemu_spin_unlock(&appdata->asan_allocated_info_lock);
        } else {
            // qemu_log("\tsrealloc alloc memory failed.\n");
            free_asan_allocated_info(allocated_info);
        }

        pending_hook->allocated_info = NULL;
    }
}

static void app_asan_trace_whitelist(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_push(thread_info, pending_hook);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
        qemu_log("whitelist function at %#018lx\n", kreit_get_pc(env));
}

static void app_asan_trace_whitelist_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
        qemu_log("whitelist function end at %#018lx\n", kreit_get_pc(env));
}

static inline vaddr linux_page_address(vaddr page)
{
    // refer to the kernel's page_address() macro.
    return (((page - 0xffffea0000000000) << 6) + 0xffff888000000000);
}

static void app_asan_trace_prep_compound_page(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    vaddr page_addr;
    unsigned int order;

    sanitizer_state_stash_push(thread_info, pending_hook);

    page_addr = linux_page_address(kreit_get_abi_param(env, 1));
    order = kreit_get_abi_param(env, 2);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
        qemu_log("prep_compound_page at %#018lx, order: %d\n", page_addr, order);

    if (page_addr >= appdata->alloc_range_start && page_addr <= appdata->alloc_range_end)
        asan_unpoison_region(page_addr, 4096 * (1 << order));
}

static void app_asan_trace_prep_compound_page_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);
}

static void app_asan_trace_post_alloc_hook(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    vaddr page_addr;
    unsigned int nr_pages;

    sanitizer_state_stash_push(thread_info, pending_hook);

    page_addr = linux_page_address(kreit_get_abi_param(env, 1));
    nr_pages = 1 << kreit_get_abi_param(env, 2);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
        qemu_log("post_alloc_hook at %#018lx, nr_pages: %d\n", page_addr, nr_pages);

    if (page_addr >= appdata->alloc_range_start && page_addr <= appdata->alloc_range_end)
        asan_unpoison_region(page_addr, 4096 * nr_pages);
}

static void app_asan_trace_post_alloc_hook_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);
}

static void app_asan_trace_clear_page_rep(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    vaddr page;

    sanitizer_state_stash_push(thread_info, pending_hook);

    page = kreit_get_abi_param(env, 1);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
        qemu_log("clear_page_rep at %#018lx\n", page);

    // asan_unpoison_region(page, 4096);
}

static void app_asan_trace_clear_page_rep_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    sanitizer_state_stash_pop(thread_info, pending_hook);
}

static void app_asan_trace_hook(void *instr_data, void *userdata)
{
    KreitAsanHookData *hook_data = instr_data;
    CPUArchState *env = hook_data->env;
    KreitAsanState *appdata = userdata;
    KreitPendingHook *pending_hook;
    AsanThreadInfo *thread_info;

    pending_hook = g_malloc0(sizeof(KreitPendingHook));
    pending_hook->hook_info = &appdata->asan_hook[hook_data->hook_index];
    pending_hook->ret_addr = kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env));
    pending_hook->stack_ptr = kreit_get_stack_ptr(env);
    pending_hook->cpl = get_cpu_privilege(env);

    thread_info = curr_cpu_thread_info();
    thread_info->hook_func_not_return = true;
    pending_hook->thread_info = thread_info;

    qemu_spin_lock(&appdata->pending_hooks_lock);
    bool find = g_hash_table_lookup(appdata->pending_hooks, pending_hook_hash_key(pending_hook->ret_addr, pending_hook->stack_ptr));
    if (find) {
        if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
            qemu_log("qkasan: repeated hook at %#018lx, rsp: %#018lx, cpl: %d, rax: %#018lx, r8: %#018lx\n",
                pending_hook->ret_addr, pending_hook->stack_ptr, pending_hook->cpl,
                env->regs[R_EAX], env->regs[R_R8]);
        }
        qemu_spin_unlock(&appdata->pending_hooks_lock);
        return;
    }
    g_hash_table_insert(appdata->pending_hooks, pending_hook_hash_key(pending_hook->ret_addr, pending_hook->stack_ptr), pending_hook);
    appdata->nr_pending_hooks++;
    qemu_spin_unlock(&appdata->pending_hooks_lock);

    switch (pending_hook->hook_info->type) {
        case ASAN_HOOK_ALLOC_SIZE_IN_REGS:
            pending_hook->trace_start = asan_trace_linux_size_in_regs;
            pending_hook->trace_finished = asan_trace_linux_size_in_regs_finished;
            break;
        case ASAN_HOOK_KMEM_CACHE_CREATE:
            pending_hook->trace_start = asan_trace_linux_kmem_cache_create;
            pending_hook->trace_finished = asan_trace_linux_kmem_cache_create_finished;
            break;
        case ASAN_HOOK_ALLOC_KMEM_CACHE:
            pending_hook->trace_start = asan_trace_linux_kmem_cache_alloc;
            pending_hook->trace_finished = asan_trace_linux_kmem_cache_alloc_finished;
            break;
        case ASAN_HOOK_ALLOC_BULK:
            pending_hook->trace_start = asan_trace_linux_bulk_alloc;
            pending_hook->trace_finished = asan_trace_linux_bulk_alloc_finished;
            break;
        case ASAN_HOOK_KSIZE:
            pending_hook->trace_start = asan_trace_linux_ksize;
            pending_hook->trace_finished = asan_trace_linux_ksize_finished;
            break;
        case ASAN_HOOK_FREE:
            pending_hook->trace_start = asan_trace_linux_free;
            pending_hook->trace_finished = asan_trace_linux_free_finished;
            break;
        case ASAN_HOOK_FREE_BULK:
            pending_hook->trace_start = asan_trace_linux_free_bulk;
            pending_hook->trace_finished = asan_trace_linux_free_bulk_finished;
            break;
        case ASAN_HOOK_WHITELIST:
            // do nothing to ignore these funcs
            pending_hook->trace_start = app_asan_trace_whitelist;
            pending_hook->trace_finished = app_asan_trace_whitelist_finished;
            break;
        case ASAN_HOOK_PREP_COMPOUND_PAGE:
            pending_hook->trace_start = app_asan_trace_prep_compound_page;
            pending_hook->trace_finished = app_asan_trace_prep_compound_page_finished;
            break;
        case ASAN_HOOK_POST_ALLOC_HOOK:
            pending_hook->trace_start = app_asan_trace_post_alloc_hook;
            pending_hook->trace_finished = app_asan_trace_post_alloc_hook_finished;
            break;
        case ASAN_HOOK_CLEAR_PAGE_REP:
            pending_hook->trace_start = app_asan_trace_clear_page_rep;
            pending_hook->trace_finished = app_asan_trace_clear_page_rep_finished;
            break;
        case ASAN_HOOK_HANDLE_MM_PAGE_FAULT:
            break;
        case ASAN_HOOK_MEMCPY:
            pending_hook->trace_start = asan_trace_memcpy;
            pending_hook->trace_finished = asan_trace_memcpy_finished;
            break;
        case ASAN_HOOK_QNX_SREALLOC:
            pending_hook->trace_start = asan_trace_qnx_srealloc;
            pending_hook->trace_finished = asan_trace_qnx_srealloc_finished;
            break;
        default:
            g_assert(0 && "Unknown asan hook type");
    }

    if (pending_hook->trace_start)
        pending_hook->trace_start(appdata, env, pending_hook);
}

static void app_asan_trace_tb_start(void *instr_data, void *userdata)
{
    const KreitEnvPC *envpc = instr_data;
    CPUArchState *env = envpc->env;
    KreitAsanState *appdata = userdata;
    KreitPendingHook *pending_hook;
    AsanThreadInfo *thread_info;
    int pid = *curr_cpu_data(current_pid);
    vaddr curr_pc;
    vaddr prev_stack_ptr;

    // {
    //     static bool start_trace = false;
    //     if (start_trace)
    //         qemu_log("pc: %#018lx\n", env->eip);
    //     if (strstr(*curr_cpu_data(current_thread_name), "syz-executor"))
    //         start_trace = true;
    // }

    if (likely(qatomic_read(&appdata->nr_pending_hooks) == 0))
        return;

    curr_pc = kreit_get_pc(env);
    prev_stack_ptr = kreit_get_stack_ptr(env) - 8;

    qemu_spin_lock(&appdata->pending_hooks_lock);
    pending_hook = g_hash_table_lookup(appdata->pending_hooks, pending_hook_hash_key(curr_pc, prev_stack_ptr));
    qemu_spin_unlock(&appdata->pending_hooks_lock);

    if (!pending_hook)
        return;
    if (pending_hook->cpl != get_cpu_privilege(env))
        return;

    thread_info = pending_hook->thread_info;
    thread_info->hook_func_not_return = false;
    if (thread_info->pid != pid) {
        // qemu_log("function finished in different thread.\n");
        // qemu_log("\talloc in thread %d, finished in thread %d\n", thread_info->pid, pid);
        /// TODO: Check why crash here in qnx.
        // g_assert(0);
    }

    if (pending_hook->trace_finished)
        pending_hook->trace_finished(appdata, env, pending_hook);

    qemu_spin_lock(&appdata->pending_hooks_lock);
    g_hash_table_remove(appdata->pending_hooks, pending_hook_hash_key(curr_pc, prev_stack_ptr));
    appdata->nr_pending_hooks--;
    qemu_spin_unlock(&appdata->pending_hooks_lock);
}

static void app_asan_trace_context_switch(void *instr_data, void *userdata)
{
    KreitAsanState *appdata = userdata;
    const KreitSwitchPair *spair = instr_data;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&appdata->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(appdata->asan_threadinfo, thread_info_hash_key(spair->next, current_cpu->cpu_index));
    if (!thread_info) {
        // insert new thread info
        thread_info = g_malloc0(sizeof(AsanThreadInfo));
        thread_info->pid = spair->next;
        thread_info->asan_enabled = true;
        thread_info->msan_enabled = false;
        strncpy(thread_info->process_name, spair->next_name, PROCESS_NAME_LENGTH);
        g_hash_table_insert(appdata->asan_threadinfo,
            thread_info_hash_key(spair->next, current_cpu->cpu_index), thread_info);
    }

    strncpy(thread_info->process_name, spair->next_name, PROCESS_NAME_LENGTH);
    if (strstr(spair->next_name, "poc") && !thread_info->hook_func_not_return)
        thread_info->msan_enabled = appdata->msan;
    appdata->cpu_thread_info[current_cpu->cpu_index] = thread_info;
    qemu_spin_unlock(&appdata->asan_threadinfo_lock);
}

static int asan_app_init_userdata(Object *obj)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);
    AsanThreadInfo *new_thread_info;

    kas->asan_threadinfo = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    switch (kcont.target) {
    case TRACE_TARGET_LINUX:
        for (int i = 0; i < kcont.nr_cpus; i++) {
            new_thread_info = g_malloc0(sizeof(AsanThreadInfo));
            new_thread_info->pid = 0;
            kas->cpu_thread_info[i] = new_thread_info;
            g_hash_table_insert(kas->asan_threadinfo, thread_info_hash_key(0, i), new_thread_info);
        }
        break;
    case TRACE_TARGET_QNX:
        new_thread_info = g_malloc0(sizeof(AsanThreadInfo));
        new_thread_info->pid = 0;
        new_thread_info->asan_enabled = true;
        new_thread_info->msan_enabled = false;
        g_hash_table_insert(kas->asan_threadinfo, thread_info_hash_key(0, 0), new_thread_info);
        for (int i = 0; i < kcont.nr_cpus; i++) {
            new_thread_info = g_malloc0(sizeof(AsanThreadInfo));
            new_thread_info->pid = 1;
            new_thread_info->asan_enabled = true;
            new_thread_info->msan_enabled = false;
            kas->cpu_thread_info[i] = new_thread_info;
            g_hash_table_insert(kas->asan_threadinfo, thread_info_hash_key(1, i), new_thread_info);
        }
        break;
    default:
        break;
    }

    kas->asan_allocated_info = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free_asan_allocated_info);
    kas->asan_kmem_cache = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    kas->pending_hooks = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    kas->nr_pending_hooks = 0;
    return 0;
}

static void asan_app_destroy_userdata(Object *obj)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);

    g_hash_table_destroy(kas->asan_threadinfo);
    g_hash_table_destroy(kas->asan_allocated_info);
    g_hash_table_destroy(kas->pending_hooks);
    kas->nr_pending_hooks = 0;
}

static void get_asan_kernel_info(KreitAsanState *kas)
{
    QList *asan_hook;
    QListEntry *entry;
    QDict *entry_dict;
    int i = 0;

    if (!qdict_haskey(kcont.kernel_info, "asan-hook")) {
        qemu_log("kreit: no asan hook config provided\n");
        g_assert(0);
    }
    asan_hook = qdict_get_qlist(kcont.kernel_info, "asan-hook");
    kas->nr_asan_hook = qlist_size(asan_hook);
    kas->asan_hook = g_malloc0(sizeof(KreitAsanInstrInfo) * kas->nr_asan_hook);
    QLIST_FOREACH_ENTRY(asan_hook, entry) {
        entry_dict = qobject_to(QDict, qlist_entry_obj(entry));

        if (!qdict_haskey(entry_dict, "type")) {
            qemu_log("Asan hook does not provide \"type\"\n");
            g_assert(0);
        }
        const char *hook_type = qdict_get_str(entry_dict, "type");
        if (strcmp(hook_type, "kmem_cache") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_ALLOC_KMEM_CACHE;
        } else if (strcmp(hook_type, "kmem_cache_create") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_KMEM_CACHE_CREATE;
        } else if (strcmp(hook_type, "size-in-regs") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_ALLOC_SIZE_IN_REGS;
        } else if (strcmp(hook_type, "alloc_bulk") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_ALLOC_BULK;
        } else if (strcmp(hook_type, "ksize") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_KSIZE;
        } else if (strcmp(hook_type, "free") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_FREE;
        } else if (strcmp(hook_type, "free_bulk") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_FREE_BULK;
        } else if (strcmp(hook_type, "whitelist") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_WHITELIST;
        } else if (strcmp(hook_type, "prep_compound_page") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_PREP_COMPOUND_PAGE;
        } else if (strcmp(hook_type, "post_alloc_hook") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_POST_ALLOC_HOOK;
        } else if (strcmp(hook_type, "clear_page_rep") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_CLEAR_PAGE_REP;
        } else if (strcmp(hook_type, "handle_mm_fault") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_HANDLE_MM_PAGE_FAULT;
        } else if (strcmp(hook_type, "memcpy") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_MEMCPY;
        } else if (strcmp(hook_type, "qnx-srealloc") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_QNX_SREALLOC;
        } else {
            g_assert(0 && "Unkonw hook type");
        }

        if (!qdict_haskey(entry_dict, "addr")) {
            qemu_log("Asan hook does not provide hook address\n");
            g_assert(0);
        }
        const char *addr_str = qdict_get_str(entry_dict, "addr");
        kas->asan_hook[i].addr = strtoull(addr_str, NULL, 16);
        kas->asan_hook[i].param_order = qdict_get_try_int(entry_dict, "order", 0);
        kas->asan_hook[i].flag_order = qdict_get_try_int(entry_dict, "flag-order", 0);

        i++;
    }

    if (kcont.target == TRACE_TARGET_LINUX) {
        if (!qdict_haskey(kcont.kernel_info, "offsetof(struct kmem_cache, size)")) {
            qemu_log("kreit: no offsetof(struct kmem_cache, size) config provided\n");
            g_assert(0);
        }
        kas->size_offset = qdict_get_int(kcont.kernel_info, "offsetof(struct kmem_cache, size)");

        if (!qdict_haskey(kcont.kernel_info, "offsetof(struct kmem_cache, align)")) {
            qemu_log("kreit: no offsetof(struct kmem_cache, align) config provided\n");
            g_assert(0);
        }
        kas->align_offset = qdict_get_int(kcont.kernel_info, "offsetof(struct kmem_cache, align)");
    }
}

static void kreit_asan_instance_init(Object *obj)
{
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);

    get_asan_kernel_info(kas);

    qemu_spin_init(&kas->asan_threadinfo_lock);
    qemu_spin_init(&kas->asan_allocated_info_lock);
    qemu_spin_init(&kas->asan_kmem_cache_lock);
    qemu_spin_init(&kas->pending_hooks_lock);
    // TODO: better shadow memory allocator
    kas->shadow_base = mmap(NULL, kcont.mem_size >> 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!kas->shadow_base) {
        qemu_log("asan: cannot allocate shadow memory, disabling asan\n");
        return;
    }
    qemu_log("asan: mmap shadow memory base: %#018lx\n", (uintptr_t) kas->shadow_base);

    switch (kcont.target) {
        case TRACE_TARGET_LINUX:
            kas->alloc_range_start = 0xffff888000000000;
            kas->alloc_range_end = 0xffffc88000000000;
            break;
        case TRACE_TARGET_QNX:
            kas->alloc_range_start = 0xffff8000000f0000;
            kas->alloc_range_end = 0xffff800005000000;
            break;
        default:
            g_assert(0 && "unknown trace target");
    }

    kas->cpu_thread_info = g_malloc0(sizeof(void *) * kcont.nr_cpus);

    kac->register_instr(obj, KREIT_INSTR_TB_START_ADDR, app_asan_trace_tb_start);
    kac->register_instr(obj, KREIT_INSTR_GEN_TB_START, app_asan_insert_asan_helper);
    kac->register_instr(obj, KREIT_INSTR_ASAN_HOOK, app_asan_trace_hook);
    kac->register_instr(obj, KREIT_INSTR_TRACE_CONTEXT_SWITCH, app_asan_trace_context_switch);

    // default value
    kas->stack_record_len = 32;

    asan_state = kas;
}

static void kreit_asan_instance_finalize(Object *obj)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);

    g_free(kas->asan_hook);
    munmap(kas->shadow_base, kcont.mem_size >> 3);
}

static void kreitapp_set_stack_record_len(Object *obj, Visitor *v,
                                          const char *name, void *opaque,
                                          Error **errp)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }

    kas->stack_record_len = ROUND_UP(value, 4);
}

static void kreitapp_set_msan(Object *obj, bool value, Error **errp)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);

    kas->msan = value;
}

static void kreit_asan_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);
    kac->name = KREIT_ASAN_APPNAME;
    kac->start_hook = asan_app_init_userdata;
    kac->stop_hook = asan_app_destroy_userdata;
    kreitapp_add_dependency(kac, "tbstart");
    kreitapp_add_dependency(kac, "context-switch");

    object_class_property_add(klass, "stack-record-len", "int",
        NULL, kreitapp_set_stack_record_len,
        NULL, NULL);
    object_class_property_add_bool(klass, "msan", NULL, kreitapp_set_msan);
}

static const TypeInfo kreit_asan_type = {
    .name = TYPE_KREIT_ASAN,
    .parent = TYPE_KREITAPP,
    .instance_init = kreit_asan_instance_init,
    .instance_finalize = kreit_asan_instance_finalize,
    .class_init = kreit_asan_class_init,
    .instance_size = sizeof(KreitAsanState),
};

static void kreit_asan_type_init(void)
{
    type_register_static(&kreit_asan_type);
}

type_init(kreit_asan_type_init);
