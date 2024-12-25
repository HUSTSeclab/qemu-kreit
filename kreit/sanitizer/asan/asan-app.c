#include "kreit/instrument/app.h"
#include "kreit/kreit.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qstring.h"
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

static void asan_trace_linux_size_in_regs(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    size_t request_size;
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info;

    // disable kasan before returning
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;

    request_size = get_linux_alloc_size(appdata, env, pending_hook->hook_info);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: size_in_regs) size: %ld, ret addr: %#018lx, rsp: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            request_size,
            pending_hook->ret_addr, pending_hook->stack_ptr);
    }

    allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
    allocated_info->chunk_size =
        asan_allocator_aligned_size(request_size + REDZONE_SIZE);
    g_assert(allocated_info->chunk_size);
    allocated_info->redzone_size =
        allocated_info->chunk_size - ROUND_UP(request_size, 8);
    allocated_info->request_size = request_size;
    allocated_info->pid = pid;
    allocated_info->allocated_at =
        kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;

    // request a larger chunk
    kreit_set_abi_reg_param(env,
        pending_hook->hook_info->param_order,
        allocated_info->chunk_size);

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

    // restore the asan state
    thread_info->asan_enabled = pending_hook->staged_asan_state;

    allocated_info->asan_chunk_start = kreit_get_return_value(env);
    allocated_info->in_use = true;

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: size_in_regs) finished, return value: %#018lx, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            allocated_info->asan_chunk_start,
            kreit_get_pc(env),
            kreit_get_stack_ptr(env) - 8);
    }

    asan_unpoison_region(allocated_info->asan_chunk_start,
        allocated_info->chunk_size);
    redzone_start = allocated_info->asan_chunk_start +
        allocated_info->chunk_size - allocated_info->redzone_size;
    asan_poison_region(redzone_start,
        allocated_info->redzone_size, ASAN_HEAP_RIGHT_RZ);

    qemu_spin_lock(&appdata->asan_allocated_info_lock);
    g_hash_table_insert(appdata->asan_allocated_info,
        (gpointer) allocated_info->asan_chunk_start,
        allocated_info);
    qemu_spin_unlock(&appdata->asan_allocated_info_lock);
}

static void asan_trace_linux_kmem_cache_alloc(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    size_t request_size;
    size_t align_size;
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info;
    vaddr stack_ptr;
    KreitPendingHook *new_pending_hook;

    // disable kasan before returning
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;

    if (!thread_info->in_kmem_cache_alloc) {
        request_size = get_linux_alloc_size(appdata, env, pending_hook->hook_info);
        align_size = get_linux_cache_align(appdata, env);

        if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
            qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: kmem_cache) size: %ld, align: %ld, ret addr: %#018lx, rsp: %#018lx\n",
                current_cpu->cpu_index, pid, get_cpu_privilege(env),
                request_size, align_size,
                pending_hook->ret_addr, pending_hook->stack_ptr);
        }

        thread_info->in_kmem_cache_alloc = true;
        thread_info->need_retry_alloc = true;
        thread_info->last_allocated_addr = 0;
        thread_info->storaged_regs = kreit_get_regular_register_buf(env);
        thread_info->align_size = align_size;

        allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
        allocated_info->chunk_size = 2 * request_size;
        allocated_info->redzone_size = request_size;
        allocated_info->pid = pid;
        allocated_info->request_size = request_size;
        allocated_info->allocated_at =
            kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
        // store the unmature allocated_info
        thread_info->kmem_cache_allocated_info = allocated_info;
    }

    kreit_set_regular_register_buf(env, thread_info->storaged_regs);
    if (thread_info->need_retry_alloc) {
        // prepare the next kmem_cache_alloc
        // rsp = rsp - 8
        stack_ptr = kreit_get_stack_ptr(env);
        stack_ptr = stack_ptr - 8;
        kreit_set_stack_ptr(env, stack_ptr);
        // [rsp] = address of kmem_cache
        kreit_cpu_stq(env_cpu(env), stack_ptr, kreit_get_pc(env));

        // modify the pending hook info
        qemu_spin_lock(&appdata->pending_hooks_lock);
        new_pending_hook = g_malloc0(sizeof(KreitPendingHook));
        *new_pending_hook = *pending_hook;
        g_hash_table_remove(appdata->pending_hooks,
            pending_hook_hash_key(pending_hook->ret_addr, pending_hook->stack_ptr));
        new_pending_hook->ret_addr = kreit_get_pc(env);
        new_pending_hook->stack_ptr = stack_ptr;
        g_hash_table_insert(appdata->pending_hooks,
            pending_hook_hash_key(new_pending_hook->ret_addr, new_pending_hook->stack_ptr),
            new_pending_hook);
        qemu_spin_unlock(&appdata->pending_hooks_lock);

        if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
            qemu_log("\ttrying kmem_cache_alloc, pending ret addr %#018lx, stack ptr %#018lx\n",
                new_pending_hook->ret_addr,
                new_pending_hook->stack_ptr);
        }
    }
}

static void asan_trace_linux_kmem_cache_alloc_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info = thread_info->kmem_cache_allocated_info;
    vaddr alloc_ret_val;
    size_t asan_aligned_size;

    // restore the asan state
    thread_info->asan_enabled = pending_hook->staged_asan_state;

    alloc_ret_val = kreit_get_return_value(env);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: alloc (type: kmem_cache) finished, return value: %#018lx, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            alloc_ret_val,
            kreit_get_pc(env),
            kreit_get_stack_ptr(env) - 8);
    }

    if (!thread_info->need_retry_alloc) {
        // final return to normal execution
        kreit_set_return_value(env, allocated_info->asan_chunk_start);
        thread_info->in_kmem_cache_alloc = false;
        g_free(thread_info->storaged_regs);
        thread_info->storaged_regs = NULL;
        return;
    }

    asan_aligned_size = ROUND_UP(allocated_info->request_size, thread_info->align_size);
    if (alloc_ret_val - thread_info->last_allocated_addr ==
        asan_aligned_size) {
        thread_info->need_retry_alloc = false;
        allocated_info->asan_chunk_start = thread_info->last_allocated_addr;
        allocated_info->in_use = true;

        asan_unpoison_region(allocated_info->asan_chunk_start,
            allocated_info->chunk_size);
        asan_poison_region(alloc_ret_val, allocated_info->redzone_size, ASAN_HEAP_RIGHT_RZ);
        qemu_spin_lock(&appdata->asan_allocated_info_lock);
        g_hash_table_insert(appdata->asan_allocated_info,
            (gpointer) allocated_info->asan_chunk_start,
            allocated_info);
        qemu_spin_unlock(&appdata->asan_allocated_info_lock);
    } else {
        thread_info->last_allocated_addr = alloc_ret_val;
    }
}

static void asan_trace_linux_bulk_alloc(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;
    AsanAllocatedInfo *allocated_info;

    // disable kasan before returning
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;

    pending_hook->nr_bulk = kreit_get_abi_param(env, 3);
    pending_hook->bulk_array = kreit_get_abi_param(env, 4);

    allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
    allocated_info->request_size =
        get_linux_alloc_size(appdata, env, pending_hook->hook_info);
    allocated_info->chunk_size = allocated_info->request_size;
    allocated_info->pid = pid;
    allocated_info->allocated_at =
        kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;

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

    // restore the asan state
    thread_info->asan_enabled = pending_hook->staged_asan_state;

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
        bulk_allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
        bulk_allocated_info->in_use = true;
        *bulk_allocated_info = *common_allocated_info;
        bulk_allocated_info->asan_chunk_start = allocated_addr;
        qemu_spin_lock(&appdata->asan_allocated_info_lock);
        g_hash_table_insert(appdata->asan_allocated_info,
            (gpointer) allocated_addr,
            bulk_allocated_info);
        qemu_spin_unlock(&appdata->asan_allocated_info_lock);
    }

    g_free(common_allocated_info);
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

    // disable kasan before returning
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;

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
    } else {
        asan_giovese_report_and_crash(ACCESS_TYPE_DOUBLE_FREE,
            allocated_info->asan_chunk_start,
            1, env);
    }
}

static void asan_trace_linux_free_finished(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    // restore the asan state
    thread_info->asan_enabled = pending_hook->staged_asan_state;

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

    // disable kasan before returning
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;

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

    // restore the asan state
    thread_info->asan_enabled = pending_hook->staged_asan_state;

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: free_bulk finished, current eip: %#018lx, rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            kreit_get_pc(env), kreit_get_stack_ptr(env) - 8);
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

    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;

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
        new_allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
        // new_allocated_info->hook_type = hook->type;

        new_allocated_info->request_size = new_size;
        new_allocated_info->chunk_size = ROUND_UP(new_size, 8) + REDZONE_SIZE;
        new_allocated_info->redzone_size = REDZONE_SIZE;

        kreit_set_abi_reg_param(env, 3, new_allocated_info->chunk_size);
    }

    if (new_allocated_info) {
        new_allocated_info->pid = pid;
        new_allocated_info->allocated_at = kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
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

    curr_pc = kreit_get_pc(env);
    prev_stack_ptr = kreit_get_stack_ptr(env) - 8;
    ret_ptr = kreit_get_return_value(env);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qkasan: cpu %d pid %d cpl %d: srealloc finished, return value: %#018lx, current eip: %#018lx rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            ret_ptr, curr_pc, prev_stack_ptr);
    }

    if (!thread_info)
        return;
    thread_info->asan_enabled = pending_hook->staged_asan_state;

    if (pending_hook->qnx_old_size) {
        // free ops of kasan has been done in asan_trace_qnx_srealloc
    }

    if (pending_hook->qnx_new_size) {
        allocated_info = pending_hook->allocated_info;

        if (allocated_info) {
            allocated_info->asan_chunk_start = ret_ptr;
            allocated_info->allocated_at = ret_ptr;
            allocated_info->in_use = true;
            asan_unpoison_region(ret_ptr, allocated_info->chunk_size);

            vaddr redzone_start = ret_ptr + allocated_info->chunk_size - allocated_info->redzone_size;
            asan_poison_region(redzone_start, allocated_info->redzone_size, ASAN_HEAP_RIGHT_RZ);

            qemu_spin_lock(&appdata->asan_allocated_info_lock);
            g_hash_table_insert(appdata->asan_allocated_info, (gpointer) ret_ptr, allocated_info);
            qemu_spin_unlock(&appdata->asan_allocated_info_lock);
        }

        pending_hook->allocated_info = NULL;
    }
}

static void app_asan_trace_whitelist(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    // disable kasan before returning
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
        qemu_log("whitelist function at %#018lx\n", kreit_get_pc(env));
}

static void app_asan_trace_whitelist_finished(KreitAsanState *appdata,
    CPUArchState* env, KreitPendingHook *pending_hook)
{
    AsanThreadInfo *thread_info = pending_hook->thread_info;

    // restore the asan state
    thread_info->asan_enabled = pending_hook->staged_asan_state;
}

static void app_asan_trace_hook(void *instr_data, void *userdata)
{
    KreitAsanHookData *hook_data = instr_data;
    CPUArchState *env = hook_data->env;
    KreitAsanState *appdata = userdata;
    KreitPendingHook *pending_hook;
    AsanThreadInfo *thread_info;
    int pid = *curr_cpu_data(current_pid);

    pending_hook = g_malloc0(sizeof(KreitPendingHook));
    pending_hook->hook_info = &appdata->asan_hook[hook_data->hook_index];
    pending_hook->ret_addr = kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env));
    pending_hook->stack_ptr = kreit_get_stack_ptr(env);
    pending_hook->cpl = get_cpu_privilege(env);

    qemu_spin_lock(&appdata->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(appdata->asan_threadinfo, thread_info_hash_key(pid, current_cpu->cpu_index));
    qemu_spin_unlock(&appdata->asan_threadinfo_lock);
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
        case ASAN_HOOK_CLEAR_PAGE_REP:
        case ASAN_HOOK_HANDLE_MM_PAGE_FAULT:
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
    //     if (env->eip == 0xffffffff81271290)
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
    if (thread_info->pid != pid) {
        qemu_log("function finished in different thread.\n");
        qemu_log("\talloc in thread %d, finished in thread %d\n", thread_info->pid, pid);
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
    if (thread_info) {
        strncpy(thread_info->process_name, spair->next_name, PROCESS_NAME_LENGTH);
        qemu_spin_unlock(&appdata->asan_threadinfo_lock);
        return;
    }

    thread_info = g_malloc0(sizeof(AsanThreadInfo));
    thread_info->pid = spair->next;
    thread_info->asan_enabled = true;
    strncpy(thread_info->process_name, spair->next_name, PROCESS_NAME_LENGTH);

    g_hash_table_insert(appdata->asan_threadinfo, thread_info_hash_key(spair->next, current_cpu->cpu_index), thread_info);
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

            g_hash_table_insert(kas->asan_threadinfo, thread_info_hash_key(0, i), new_thread_info);
        }
        break;
    case TRACE_TARGET_QNX:
        new_thread_info = g_malloc0(sizeof(AsanThreadInfo));
        new_thread_info->pid = 0;
        g_hash_table_insert(kas->asan_threadinfo, thread_info_hash_key(0, 0), new_thread_info);
        for (int i = 0; i < kcont.nr_cpus; i++) {
            new_thread_info = g_malloc0(sizeof(AsanThreadInfo));
            new_thread_info->pid = 1;

            g_hash_table_insert(kas->asan_threadinfo, thread_info_hash_key(1, i), new_thread_info);
        }
        break;
    default:
        break;
    }

    kas->asan_allocated_info = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
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
        } else if (strcmp(hook_type, "clear_page_rep") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_CLEAR_PAGE_REP;
        } else if (strcmp(hook_type, "handle_mm_fault") == 0) {
            kas->asan_hook[i].type = ASAN_HOOK_HANDLE_MM_PAGE_FAULT;
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

    kac->register_instr(obj, KREIT_INSTR_TB_START_ADDR, app_asan_trace_tb_start);
    kac->register_instr(obj, KREIT_INSTR_GEN_TB_START, app_asan_insert_asan_helper);
    kac->register_instr(obj, KREIT_INSTR_ASAN_HOOK, app_asan_trace_hook);
    kac->register_instr(obj, KREIT_INSTR_TRACE_CONTEXT_SWITCH, app_asan_trace_context_switch);

    asan_state = kas;
}

static void kreit_asan_instance_finalize(Object *obj)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);

    g_free(kas->asan_hook);
    munmap(kas->shadow_base, kcont.mem_size >> 3);
}

static void kreit_asan_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);
    kac->name = KREIT_ASAN_APPNAME;
    kac->start_hook = asan_app_init_userdata;
    kac->stop_hook = asan_app_destroy_userdata;
    kreitapp_add_dependency(kac, "tbstart");
    kreitapp_add_dependency(kac, "context-switch");
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
