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

static size_t get_alloc_size(KreitAsanState* kas, KreitAsanInstrInfo *hook)
{
    CPUArchState *env = hook->env;
    vaddr kmem_cache_ptr;

    switch (hook->type) {
        case ASAN_HOOK_ALLOC_KMEM_CACHE:
        case ASAN_HOOK_ALLOC_BULK:
            kmem_cache_ptr = kreit_get_abi_param(env, 1);
            return kreit_cpu_ldl(env_cpu(env), kmem_cache_ptr + kas->object_size_offset);
        case ASAN_HOOK_ALLOC_SIZE_IN_REGS:
            return kreit_get_abi_param(env, hook->param_order);
        default:
            return 0;
    }
}

/*static void app_asan_trace_alloc(KreitAsanState *appdata, AsanThreadInfo *thread_info)
{
    KreitAsanInstrInfo *hook = &thread_info->pending_hook;
    CPUArchState *env = hook->env;
    int pid = *curr_cpu_data(current_pid);
    size_t request_size;
    size_t chunk_size;
    AsanAllocatedInfo *allocated_info;

    thread_info->asan_enabled = false;

    g_assert(thread_info->pending_allocated_info == NULL);

    request_size = get_alloc_size(appdata, hook);

    allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
    allocated_info->hook_type = hook->type;
    // Extent the allocated size and set redzone
    // only do for __kmalloc now
    if (hook->type == ASAN_HOOK_ALLOC_SIZE_IN_REGS && hook->param_order == 1) {
        chunk_size = asan_allocator_aligned_size(request_size + REDZONE_SIZE);
        g_assert(chunk_size);
        allocated_info->redzone_size = chunk_size - ROUND_UP(request_size, 8);
        allocated_info->need_poison = true; // tmp hack
        kreit_set_abi_reg_param(env, 1, chunk_size);
    } else {
        chunk_size = request_size;
        allocated_info->redzone_size = 0;
        allocated_info->need_poison = false; // tmp hack
    }
    allocated_info->request_size = request_size;
    allocated_info->chunk_size = chunk_size;

    if (hook->type == ASAN_HOOK_ALLOC_BULK) {
        allocated_info->bulk_nr = kreit_get_abi_param(env, 3);
        allocated_info->bulk_array_addr = kreit_get_abi_param(env, 4);
    }

    allocated_info->pid = pid;
    allocated_info->allocated_at = kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env)) - 5;
    thread_info->pending_allocated_info = allocated_info;

    qemu_log("cpu: %d, request size: %ld, pid: %d, ret addr: %#018lx\n", current_cpu->cpu_index, request_size, *curr_cpu_data(current_pid), allocated_info->allocated_at);
    qemu_log("\tpoison: %d, allocator type: %d\n", allocated_info->need_poison, hook->type);
}

static void asan_trace_alloc_finished(KreitAsanState *appdata, AsanThreadInfo *thread_info)
{
    KreitAsanInstrInfo *hook = &thread_info->pending_hook;
    CPUArchState *env = hook->env;
    int pid = *curr_cpu_data(current_pid);
    vaddr allocated_addr;
    AsanAllocatedInfo *allocated_info;
    AsanAllocatedInfo *bulk_allocated_info;
    size_t bulk_nr;

    allocated_info = thread_info->pending_allocated_info;

    if (allocated_info->hook_type == ASAN_HOOK_ALLOC_BULK) {
        bulk_nr = kreit_get_return_value(env);
        for (int i = 0; i < bulk_nr; i++) {
            allocated_addr = kreit_cpu_ldq(env_cpu(env), allocated_info->bulk_array_addr + 8 * i);
            qemu_log("bulk info %d: cpu %d: addr: %#018lx, pid: %d, allocated address: %#018lx\n", i, current_cpu->cpu_index, env->eip, pid, allocated_addr);
            asan_unpoison_region(allocated_addr, allocated_info->chunk_size);
            bulk_allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
            *bulk_allocated_info = *allocated_info;
            bulk_allocated_info->asan_chunk_start = allocated_addr;
            qemu_spin_lock(&appdata->asan_allocated_info_lock);
            g_hash_table_insert(appdata->asan_allocated_info, (gpointer) allocated_addr, bulk_allocated_info);
            qemu_spin_unlock(&appdata->asan_allocated_info_lock);
        }
    } else {
        allocated_addr = kreit_get_return_value(env);
        qemu_log("cpu %d: addr: %#018lx, pid: %d, allocated address: %#018lx\n", current_cpu->cpu_index, env->eip, pid, allocated_addr);

        allocated_info->asan_chunk_start = allocated_addr;

        asan_unpoison_region(allocated_addr, allocated_info->chunk_size);

        // tmp hack
        if (allocated_info->need_poison) {
            vaddr redzone_start = allocated_addr + allocated_info->chunk_size - allocated_info->redzone_size;
            asan_poison_region(redzone_start, allocated_info->redzone_size, ASAN_HEAP_RIGHT_RZ);
        }

        qemu_spin_lock(&appdata->asan_allocated_info_lock);
        g_hash_table_insert(appdata->asan_allocated_info, (gpointer) allocated_addr, allocated_info);
        qemu_spin_unlock(&appdata->asan_allocated_info_lock);
    }

    thread_info->pending_allocated_info = NULL;
}

static void app_asan_trace_free(KreitAsanState *appdata, AsanThreadInfo *thread_info)
{
    KreitAsanInstrInfo *hook = &thread_info->pending_hook;
    CPUArchState *env = hook->env;
    vaddr free_addr;
    AsanAllocatedInfo *allocated_info;

    thread_info->asan_enabled = false;

    free_addr = kreit_get_abi_param(env, hook->param_order);

    qemu_spin_lock(&appdata->asan_allocated_info_lock);
    allocated_info = g_hash_table_lookup(appdata->asan_allocated_info, (gpointer) free_addr);
    qemu_spin_unlock(&appdata->asan_allocated_info_lock);

    if (!allocated_info)
        return;

    qemu_log("cpu %d: try to free address %#018lx, pc %#018lx\n", current_cpu->cpu_index, free_addr, env->eip);
    asan_poison_region(free_addr, allocated_info->chunk_size, ASAN_HEAP_FREED);

    qemu_spin_lock(&appdata->asan_allocated_info_lock);
    g_hash_table_remove(appdata->asan_allocated_info, (gpointer) free_addr);
    qemu_spin_unlock(&appdata->asan_allocated_info_lock);
}

static void asan_trace_free_finished(KreitAsanState *appdata, AsanThreadInfo *thread_info)
{
    KreitAsanInstrInfo *hook = &thread_info->pending_hook;
    CPUArchState *env = hook->env;

    qemu_log("cpu %d: free finished at pc: %#018lx\n", current_cpu->cpu_index, kreit_get_pc(env));

    thread_info->asan_enabled = true;
}

static void asan_trace_page_level_ops(KreitAsanState *appdata, AsanThreadInfo *thread_info)
{
    KreitAsanInstrInfo *hook = &thread_info->pending_hook;
    CPUArchState *env = hook->env;
    vaddr page_addr;
    int nr_pages = 1;

    thread_info->asan_enabled = false;

    if (hook->type == ASAN_HOOK_HANDLE_MM_PAGE_FAULT)
        page_addr = kreit_get_abi_param(env, 2);
    else
        page_addr = kreit_get_abi_param(env, 1);

    if (!asan_check_range(page_addr))
        return;

    if (hook->type == ASAN_HOOK_PREP_COMPOUND_PAGE)
        nr_pages = 1 << kreit_get_abi_param(env, 2);

    qemu_log("page level unpoison: addr %#018lx, nr_pages %d\n", page_addr, nr_pages);
    asan_unpoison_region(page_addr, 4096 * nr_pages);
}

static void asan_trace_page_level_ops_finished(KreitAsanState *appdata, AsanThreadInfo *thread_info)
{
    thread_info->asan_enabled = true;
}*/

static void asan_trace_qnx_srealloc(KreitAsanState *appdata, CPUArchState* env, KreitPendingHook *pending_hook)
{
    int pid = *curr_cpu_data(current_pid);
    vaddr addr;
    size_t old_size;
    size_t new_size;
    AsanAllocatedInfo *old_allocated_info = NULL;
    AsanAllocatedInfo *new_allocated_info = NULL;
    AsanThreadInfo *thread_info;

    addr = kreit_get_abi_param(env, 1);
    old_size = kreit_get_abi_param(env, 2);
    new_size = kreit_get_abi_param(env, 3);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qnxkasan: cpu %d pid %d cpl %d: srealloc addr %#018lx, old_size: %ld, new_size: %ld, ret addr: %#018lx rsp: %#018lx, rax: %#018lx, r8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            addr, old_size, new_size,
            pending_hook->ret_addr, pending_hook->stack_ptr,
            env->regs[R_EAX], env->regs[R_R8]);
    }

    qemu_spin_lock(&appdata->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(appdata->asan_threadinfo, thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info) {
        qemu_spin_unlock(&appdata->asan_threadinfo_lock);
        return;
    }
    pending_hook->staged_asan_state = thread_info->asan_enabled;
    thread_info->asan_enabled = false;
    qemu_spin_unlock(&appdata->asan_threadinfo_lock);

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
                qemu_log("qnxkasan: no allocated info found for address %#018lx when free\n", addr);
        }
    }

    if (new_size) {
        // do alloc
        // Extent the allocated size and set redzone
        new_allocated_info = g_malloc0(sizeof(AsanAllocatedInfo));
        // new_allocated_info->hook_type = hook->type;
        new_allocated_info->need_poison = true; // tmp hack

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
    AsanThreadInfo *thread_info;
    vaddr ret_ptr;
    vaddr prev_stack_ptr;
    vaddr curr_pc;
    AsanAllocatedInfo *allocated_info = NULL;

    curr_pc = kreit_get_pc(env);
    prev_stack_ptr = kreit_get_stack_ptr(env) - 8;
    ret_ptr = kreit_get_return_value(env);

    if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
        qemu_log("qnxkasan: cpu %d pid %d cpl %d: srealloc finished, return value: %#018lx, current eip: %#018lx rsp - 8: %#018lx\n",
            current_cpu->cpu_index, pid, get_cpu_privilege(env),
            ret_ptr, curr_pc, prev_stack_ptr);
    }

    qemu_spin_lock(&appdata->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(appdata->asan_threadinfo, thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info) {
        qemu_spin_unlock(&appdata->asan_threadinfo_lock);
        return;
    }
    thread_info->asan_enabled = pending_hook->staged_asan_state;
    qemu_spin_unlock(&appdata->asan_threadinfo_lock);

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

static void app_asan_trace_hook(void *instr_data, void *userdata)
{
    KreitAsanInstrInfo *hook = instr_data;
    CPUArchState *env = hook->env;
    KreitAsanState *appdata = userdata;
    KreitPendingHook *pending_hook;

    pending_hook = g_malloc0(sizeof(KreitPendingHook));
    pending_hook->ret_addr = kreit_cpu_ldq(env_cpu(env), kreit_get_stack_ptr(env));
    pending_hook->stack_ptr = kreit_get_stack_ptr(env);
    pending_hook->cpl = get_cpu_privilege(env);

    qemu_spin_lock(&appdata->pending_hooks_lock);
    bool find = g_hash_table_lookup(appdata->pending_hooks, pending_hook_hash_key(pending_hook->ret_addr, pending_hook->stack_ptr));
    if (find) {
        if (kreitapp_get_verbose(OBJECT(appdata)) >= 1) {
            qemu_log("qnxkasan: repeated hook at %#018lx, rsp: %#018lx, cpl: %d, rax: %#018lx, r8: %#018lx\n",
                pending_hook->ret_addr, pending_hook->stack_ptr, pending_hook->cpl,
                env->regs[R_EAX], env->regs[R_R8]);
        }
        qemu_spin_unlock(&appdata->pending_hooks_lock);
        return;
    }
    g_hash_table_insert(appdata->pending_hooks, pending_hook_hash_key(pending_hook->ret_addr, pending_hook->stack_ptr), pending_hook);
    appdata->nr_pending_hooks++;
    qemu_spin_unlock(&appdata->pending_hooks_lock);

    switch (hook->type) {
        case ASAN_HOOK_ALLOC_SIZE_IN_REGS:
        case ASAN_HOOK_ALLOC_KMEM_CACHE:
        case ASAN_HOOK_ALLOC_BULK:
            break;
        case ASAN_HOOK_FREE:
        case ASAN_HOOK_FREE_BULK:
            break;
        case ASAN_HOOK_WHITELIST:
            // do nothing to ignore these funcs
            if (kreitapp_get_verbose(OBJECT(appdata)) >= 1)
                qemu_log("whitelist function at %#018lx\n", kreit_get_pc(env));
            break;
        case ASAN_HOOK_PREP_COMPOUND_PAGE:
        case ASAN_HOOK_CLEAR_PAGE_REP:
        case ASAN_HOOK_HANDLE_MM_PAGE_FAULT:
            break;
        case ASAN_HOOK_QNX_SREALLOC:
            asan_trace_qnx_srealloc(appdata, env, pending_hook);
            pending_hook->trace_finished = asan_trace_qnx_srealloc_finished;
            break;
        default:
            g_assert(0 && "Unknown asan hook type");
    }
}

static void app_asan_trace_tb_start(void *instr_data, void *userdata)
{
    const KreitEnvPC *envpc = instr_data;
    CPUArchState *env = envpc->env;
    KreitAsanState *appdata = userdata;
    // AsanThreadInfo *thread_info;
    KreitPendingHook *pending_hook;
    vaddr curr_pc;
    vaddr prev_stack_ptr;

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
    thread_info->asan_enabled = true;
    strncpy(thread_info->process_name, spair->next_name, PROCESS_NAME_LENGTH);

    g_hash_table_insert(appdata->asan_threadinfo, thread_info_hash_key(spair->next, current_cpu->cpu_index), thread_info);
    qemu_spin_unlock(&appdata->asan_threadinfo_lock);
}

static int asan_app_init_userdata(Object *obj)
{
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);

    kas->asan_threadinfo = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
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

static void kreit_asan_instance_init(Object *obj)
{
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);
    KreitAsanState *kas = KREIT_ASAN_STATE(obj);
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

    kac->register_instr(obj, KREIT_INSTR_GEN_TB_START, app_asan_insert_asan_helper);
    kac->register_instr(obj, KREIT_INSTR_ASAN_HOOK, app_asan_trace_hook);
    kac->register_instr(obj, KREIT_INSTR_TB_START_ADDR, app_asan_trace_tb_start);
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
