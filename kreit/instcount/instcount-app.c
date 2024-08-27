#include "instcount-app.h"

#include "kreit/kreit.h"
#include "qemu/log.h"
#include "kreit_target.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include <stdio.h>

#define KREIT_INSTCOUNT_APPNAME "instcount"
#define TYPE_KREIT_INSTCOUNT KREITAPP_CLASS_NAME(KREIT_INSTCOUNT_APPNAME)

typedef struct AppPercpuDataStruct {
    size_t tbcount_cache_user;
    size_t tbcount_cache_kernel;
    int64_t time_cache;
} AppPercpuDataStruct;

typedef struct KreitInstcountState {
    /*< private >*/
    KreitAppState parent_obj;

    /*< public >*/
    AppPercpuDataStruct *percpu_data;
    int last_cpl;
} KreitInstcountState;

DECLARE_INSTANCE_CHECKER(KreitInstcountState, KREIT_INSTCOUNT_STATE,
                         TYPE_KREIT_INSTCOUNT)

#define app_percpu_data(container, datafeild) (&container->percpu_data[current_cpu->cpu_index].datafeild)

GHashTable *kreit_instcount_threads;
QemuSpin kreit_instcount_threads_lock;

static KreitInstCountThread *insert_new_thread(int pid, const char *name)
{
    KreitInstCountThread *new_thread;

    new_thread = g_malloc0(sizeof(KreitInstCountThread));
    new_thread->pid = pid;
    strncpy(new_thread->name, name, PROCESS_NAME_LENGTH - 1);
    new_thread->percpu_data = g_malloc0(kcont.nr_cpus * sizeof(KreitThreadPercpuData));
    g_hash_table_insert(kreit_instcount_threads, GINT_TO_POINTER(new_thread->pid), new_thread);
    return new_thread;
}

static void destroy_thread(gpointer value)
{
    KreitInstCountThread *thread = (KreitInstCountThread *)value;
    g_free(thread->percpu_data);
    g_free(thread);
}

static int instcount_app_init_userdata(Object *obj)
{
    KreitInstcountState *app = KREIT_INSTCOUNT_STATE(obj);

    kreit_instcount_threads = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, destroy_thread);
    app->percpu_data = g_malloc0(sizeof(AppPercpuDataStruct) * kcont.nr_cpus);

    insert_new_thread(0, "unknown-zero");
    return 0;
}

static void instcount_app_destroy_userdata(Object *obj)
{
    KreitInstcountState *app = KREIT_INSTCOUNT_STATE(obj);

    g_hash_table_destroy(kreit_instcount_threads);
    g_free(app->percpu_data);
}

static void app_instcount_trace_context_switch(void *instr_data, void *userdata)
{
    KreitInstCountThread *curr_thread;
    KreitInstCountThread *new_thread;
    const KreitSwitchPair *spair = instr_data;
    KreitInstcountState *app = userdata;
    int curr_pid = spair->prev;
    int new_pid = spair->next;
    int64_t curr_time;

    // First process the cached tb count
    curr_thread = g_hash_table_lookup(kreit_instcount_threads, GINT_TO_POINTER(curr_pid));
    if (!curr_thread) {
        curr_thread = insert_new_thread(curr_pid, spair->prev_name);
    }

    strncpy(curr_thread->name, spair->prev_name, PROCESS_NAME_LENGTH);

    *app_percpu_data(curr_thread, bbcount_user) += *app_percpu_data(app, tbcount_cache_user);
    *app_percpu_data(app, tbcount_cache_user) = 0;
    *app_percpu_data(curr_thread, bbcount_kernel) += *app_percpu_data(app, tbcount_cache_kernel);
    *app_percpu_data(app, tbcount_cache_kernel) = 0;

    // Then calculate the clock ticks
    curr_time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (is_cpu_kernel_mode(app->last_cpl)) {
        *app_percpu_data(curr_thread, time_kernel) += curr_time - *app_percpu_data(app, time_cache);
    }
    else {
        *app_percpu_data(curr_thread, time_user) += curr_time - *app_percpu_data(app, time_cache);
    }
    *app_percpu_data(app, time_cache) = curr_time;

    // Last if needed, create a new thread recorder
    new_thread = g_hash_table_lookup(kreit_instcount_threads, GINT_TO_POINTER(new_pid));
    if (new_thread) {
        strncpy(new_thread->name, spair->next_name, PROCESS_NAME_LENGTH);
        return;
    }

    qemu_spin_lock(&kreit_instcount_threads_lock);
    insert_new_thread(new_pid, spair->next_name);
    qemu_spin_unlock(&kreit_instcount_threads_lock);
}

static void record_cpl_changed(KreitInstcountState *app)
{
    int64_t curr_time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    KreitInstCountThread *curr_thread;

    // Note that app_data->cpl has not been changed now
    curr_thread = g_hash_table_lookup(kreit_instcount_threads, GINT_TO_POINTER(*curr_cpu_data(current_pid)));
    if (!curr_thread) {
        qemu_log("instcount: Thread %d not found\n", *curr_cpu_data(current_pid));
        *app_percpu_data(app, time_cache) = curr_time;
        return;
    }
    if (is_cpu_kernel_mode(app->last_cpl)) {
        *app_percpu_data(curr_thread, time_kernel) += curr_time - *app_percpu_data(app, time_cache);
    }
    else {
        *app_percpu_data(curr_thread, time_user) += curr_time - *app_percpu_data(app, time_cache);
    }
    *app_percpu_data(app, time_cache) = curr_time;
}

static void app_instcount_trace_tb_start(void *instr_data, void *userdata)
{
    const KreitEnvPC *envpc = instr_data;
    KreitInstcountState *app = userdata;
    int cpl = get_cpu_privilege(envpc->env);

        // app_data->tbcount_cache_kernel[current_cpu->cpu_index]++ ;
    if (is_cpu_kernel_mode(cpl))
        (*app_percpu_data(app, tbcount_cache_kernel))++;
    else
        (*app_percpu_data(app, tbcount_cache_user))++;

    if (is_cpu_kernel_mode(cpl) ^ is_cpu_kernel_mode(app->last_cpl))
        record_cpl_changed(app);
    app->last_cpl = cpl;
}

static void kreit_instcount_instance_init(Object *obj)
{
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);

    qemu_spin_init(&kreit_instcount_threads_lock);
    kac->register_instr(obj, KREIT_INSTR_TRACE_CONTEXT_SWITCH, app_instcount_trace_context_switch);
    kac->register_instr(obj, KREIT_INSTR_TB_START_ADDR, app_instcount_trace_tb_start);
}

static void kreit_instcount_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);
    kac->name = KREIT_INSTCOUNT_APPNAME;
    kac->start_hook = instcount_app_init_userdata;
    kac->stop_hook = instcount_app_destroy_userdata;
    kreitapp_add_dependency(kac, "tbstart");
    kreitapp_add_dependency(kac, "context-switch");
}

static const TypeInfo kreit_instcount_type = {
    .name = TYPE_KREIT_INSTCOUNT,
    .parent = TYPE_KREITAPP,
    .instance_init = kreit_instcount_instance_init,
    .class_init = kreit_instcount_class_init,
    .instance_size = sizeof(KreitInstcountState),
};

static void kreit_instcount_type_init(void)
{
    type_register_static(&kreit_instcount_type);
}

type_init(kreit_instcount_type_init);
