#include "kreit/coverage/coverage-app-common.h"

#include "qemu/osdep.h"
#include "exec/cpu-defs.h"
#include "qemu/log.h"
#include "kreit/kreit.h"

KreitCoverageQapiData kreit_coverage_qapi_data;

static inline KreitCoverageThread *init_new_thread(int pid)
{
    KreitCoverageThread *new_thread;
    new_thread = g_malloc0(sizeof(KreitCoverageThread));
    new_thread->pid = pid;
    new_thread->tb_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    new_thread->edge_map = g_hash_table_new(g_direct_hash, g_direct_equal);

    return new_thread;
}

static inline void gfunc_destroy_coverage_thread(void *_thread)
{
    KreitCoverageThread *thread = _thread;

    g_hash_table_destroy(thread->tb_map);
    g_hash_table_destroy(thread->edge_map);
    g_free(thread);
}

static int coverage_app_init_userdata(Object *obj)
{
    KreitCoverageState *app = KREIT_COVERAGE_STATE(obj);
    KreitCoverageThread *boot_thread;

    app->threads = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                         NULL, gfunc_destroy_coverage_thread);

    boot_thread = init_new_thread(0);
    g_hash_table_insert(app->threads, GUINT_TO_POINTER(0), boot_thread);

    for (int i = 0; i < kcont.nr_cpus; i++) {
        app->percpu[i].tb_addrs_idx = 0;
        app->percpu[i].trans_tb_idx = 0;
    }

    return 0;
}

static void coverage_app_destroy_userdata(Object *obj)
{
    KreitCoverageState *app = KREIT_COVERAGE_STATE(obj);

    qemu_spin_lock(&app->threads_lock);
    g_hash_table_destroy(app->threads);
    qemu_spin_unlock(&app->threads_lock);
}

static inline void report_new_edge_coverage(int pid, target_ulong edge)
{
    KreitEdgeCoverage *new_cov;
    new_cov = g_malloc(sizeof(KreitEdgeCoverage));
    new_cov->pid = pid;
    new_cov->edge = edge;
    // qemu_log("pid %d: new coverage edge %#018lx\n", pid, edge);
    QAPI_LIST_PREPEND(kreit_coverage_qapi_data.edge_cov_list.next, new_cov);
}

static inline void report_new_block_coverage(int pid, target_ulong pc, size_t size)
{
    KreitBlockCoverage *new_cov;
    new_cov = g_malloc(sizeof(KreitBlockCoverage));
    new_cov->pid = pid;
    new_cov->pc = pc;
    new_cov->size = size;
    // qemu_log("pid %d: new coverage at %#018lx, size %ld\n", pid, pc, size);
    QAPI_LIST_PREPEND(kreit_coverage_qapi_data.block_cov_list.next, new_cov);
}

static void process_edge_coverage(KreitCoverageState *app, KreitCoverageThread *thread)
{
    target_ulong last_addr;
    target_ulong edge_xor;
    AppPerCpuData *pcpudata = &app->percpu[current_cpu->cpu_index];

    last_addr = pcpudata->tb_addrs[0];

    qemu_spin_lock(&kreit_coverage_qapi_data.edge_cov_lock);
    for (size_t i = 1; i < pcpudata->tb_addrs_idx; i++) {
        edge_xor = last_addr ^ pcpudata->tb_addrs[i];
        if (g_hash_table_insert(thread->edge_map, GUINT_TO_POINTER(edge_xor), NULL))
            report_new_edge_coverage(thread->pid, edge_xor);
        last_addr = pcpudata->tb_addrs[i];
    }
    qemu_spin_unlock(&kreit_coverage_qapi_data.edge_cov_lock);

    pcpudata->tb_addrs_idx = 0;
}

static void process_block_coverage(KreitCoverageState *app, KreitCoverageThread *thread)
{
    AppPerCpuData *pcpudata = &app->percpu[current_cpu->cpu_index];
    AppTB *this_tb;
    gpointer res;

    qemu_spin_lock(&kreit_coverage_qapi_data.block_cov_lock);
    for (size_t i = 0; i < pcpudata->trans_tb_idx; i++) {
        this_tb = &pcpudata->trans_tb[i];
        res = g_hash_table_lookup(thread->tb_map, (gpointer)this_tb->pc);
        if (!(res && (size_t)res >= this_tb->size)) {
            g_hash_table_insert(thread->tb_map, (gpointer)this_tb->pc, (gpointer)this_tb->size);
            report_new_block_coverage(thread->pid, this_tb->pc, this_tb->size);
        }
    }
    qemu_spin_unlock(&kreit_coverage_qapi_data.block_cov_lock);

    pcpudata->trans_tb_idx = 0;
}

static void app_coverage_trace_context_switch(void *instr_data, void *userdata)
{
    void *res;
    KreitCoverageThread *curr_thread;
    KreitCoverageThread *new_thread;
    const KreitSwitchPair *spair = instr_data;
    KreitCoverageState *app = userdata;
    int curr_pid = spair->prev;
    int new_pid = spair->next;

    qemu_spin_lock(&app->threads_lock);

    curr_thread = g_hash_table_lookup(app->threads, GUINT_TO_POINTER(curr_pid));
    if (curr_thread == NULL) {
        curr_thread = init_new_thread(curr_pid);
        g_hash_table_insert(app->threads, GUINT_TO_POINTER(curr_pid), curr_thread);
    }

    process_edge_coverage(app, curr_thread);
    process_block_coverage(app, curr_thread);

    res = g_hash_table_lookup(app->threads, GUINT_TO_POINTER(new_pid));
    if (!res) {
        new_thread = init_new_thread(new_pid);
        g_hash_table_insert(app->threads, GUINT_TO_POINTER(new_pid), new_thread);
    }
    qemu_spin_unlock(&app->threads_lock);
}

static void app_coverage_trace_tb_start(void *instr_data, void *userdata)
{
    const KreitEnvPC *envpc = instr_data;
    KreitCoverageState *app = userdata;
    KreitCoverageThread *this_thread;
    int this_pid = *curr_cpu_data(current_pid);
    AppPerCpuData *pcpudata = &app->percpu[current_cpu->cpu_index];

    if (!app->edge_coverage)
        return;

    pcpudata->tb_addrs[pcpudata->tb_addrs_idx] = envpc->pc;
    pcpudata->tb_addrs_idx++;

    if (unlikely(pcpudata->tb_addrs_idx == KREIT_START_TB_BUFF_SIZE)) {
        if (pcpudata->tb_addrs_idx <= 1)
            return;

        qemu_spin_lock(&app->threads_lock);
        this_thread = g_hash_table_lookup(app->threads, GUINT_TO_POINTER(this_pid));
        if (this_thread == NULL) {
            this_thread = init_new_thread(this_pid);
            g_hash_table_insert(app->threads, GUINT_TO_POINTER(this_pid), this_thread);
        }
        qemu_spin_unlock(&app->threads_lock);

        process_edge_coverage(app, this_thread);
    }
}

static void app_coverage_trace_tb_translate(void *instr_data, void *userdata)
{
    const KreitTBTranslateData *trans_data = instr_data;
    KreitCoverageState *app = userdata;
    AppPerCpuData *pcpudata = &app->percpu[current_cpu->cpu_index];
    KreitCoverageThread *this_thread;
    int this_pid = *curr_cpu_data(current_pid);

    if (!app->block_coverage)
        return;

    pcpudata->trans_tb[pcpudata->trans_tb_idx] = (AppTB) {
        .pc = trans_data->pc,
        .size = trans_data->size
    };
    pcpudata->trans_tb_idx++;

    if (unlikely(pcpudata->trans_tb_idx == KREIT_TRANSLATE_BUFF_SIZE)) {
        if (pcpudata->trans_tb_idx <= 1)
            return;

        qemu_spin_lock(&app->threads_lock);
        this_thread = g_hash_table_lookup(app->threads, GUINT_TO_POINTER(*curr_cpu_data(current_pid)));
        if (this_thread == NULL) {
            this_thread = init_new_thread(this_pid);
            g_hash_table_insert(app->threads, GUINT_TO_POINTER(this_pid), this_thread);
        }
        qemu_spin_unlock(&app->threads_lock);

        process_block_coverage(app, this_thread);
    }
}

static void kreit_coverage_instance_init(Object *obj)
{
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);
    KreitCoverageState *app = KREIT_COVERAGE_STATE(obj);

    qemu_spin_init(&app->threads_lock);
    qemu_spin_init(&kreit_coverage_qapi_data.block_cov_lock);
    qemu_spin_init(&kreit_coverage_qapi_data.edge_cov_lock);

    app->block_coverage = true;
    app->edge_coverage = true;

    app->percpu = g_malloc0(sizeof(AppPerCpuData) * kcont.nr_cpus);
    for (int i = 0; i < kcont.nr_cpus; i++) {
        app->percpu[i].tb_addrs = g_malloc(KREIT_START_TB_BUFF_SIZE * sizeof(target_ulong));
        app->percpu[i].trans_tb = g_malloc(KREIT_TRANSLATE_BUFF_SIZE * sizeof(AppTB));
    }

    kac->register_instr(obj, KREIT_INSTR_TRACE_CONTEXT_SWITCH, app_coverage_trace_context_switch);
    kac->register_instr(obj, KREIT_INSTR_TB_TRANSLATE, app_coverage_trace_tb_translate);
    kac->register_instr(obj, KREIT_INSTR_TB_START_ADDR, app_coverage_trace_tb_start);
}

static void kreit_coverage_instance_finalize(Object *obj)
{
    KreitCoverageState *app = KREIT_COVERAGE_STATE(obj);

    for (int i = 0; i < kcont.nr_cpus; i++) {
        g_free(app->percpu[i].tb_addrs);
        g_free(app->percpu[i].trans_tb);
    }
    g_free(app->percpu);
}

static void app_set_block_coverage(Object *obj, bool value, Error **errp)
{
    KreitCoverageState *kas = KREIT_COVERAGE_STATE(obj);

    kas->block_coverage = value;
}

static void app_set_edge_coverage(Object *obj, bool value, Error **errp)
{
    KreitCoverageState *kas = KREIT_COVERAGE_STATE(obj);

    kas->edge_coverage = value;
}

static void kreit_coverage_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);
    kac->name = KREIT_COVERAGE_APPNAME;
    kac->start_hook = coverage_app_init_userdata;
    kac->stop_hook = coverage_app_destroy_userdata;
    kreitapp_add_dependency(kac, "tbstart");
    kreitapp_add_dependency(kac, "context-switch");

    object_class_property_add_bool(klass, "block-coverage", NULL, app_set_block_coverage);
    object_class_property_add_bool(klass, "edge-coverage", NULL, app_set_edge_coverage);
}

static const TypeInfo kreit_coverage_type = {
    .name = TYPE_KREIT_COVERAGE,
    .parent = TYPE_KREITAPP,
    .instance_init = kreit_coverage_instance_init,
    .instance_finalize = kreit_coverage_instance_finalize,
    .class_init = kreit_coverage_class_init,
    .instance_size = sizeof(KreitCoverageState),
};

static void kreit_coverage_type_init(void)
{
    type_register_static(&kreit_coverage_type);
}

type_init(kreit_coverage_type_init);
