#include "qemu/osdep.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qobject.h"
#include "exec/cpu-defs.h"
#include "kreit/instrument/app.h"
#include "context-switch-common.h"
#include "kreit/instrument/instrument.h"
#include "hw/core/cpu.h"
#include "tcg/tcg.h"
#include "exec/helper-proto-common.h"
#include "exec/helper-gen-common.h"
#include "hw/boards.h"
#include "qemu/log.h"

#define KREIT_CONTEXT_SWITCH_APPNAME "context-switch"
#define TYPE_KREIT_CONTEXT_SWITCH KREITAPP_CLASS_NAME(KREIT_CONTEXT_SWITCH_APPNAME)

typedef struct KreitContextSwitchState {
    /*< private >*/
    KreitAppState parent_obj;

    /*< public >*/
    QemuSpin switch_lock;
    size_t switch_index;

    bool trace_kvm;

    vaddr addr_context_switch;
} KreitContextSwitchState;

DECLARE_INSTANCE_CHECKER(KreitContextSwitchState, KREIT_CONTEXT_SWITCH_STATE,
                         TYPE_KREIT_CONTEXT_SWITCH)

static void app_func_insert_context_switch_instr(void *instr_data, void *userdata)
{
    target_ulong this_pc = (target_ulong) instr_data;

    if (this_pc == switch_conf.addr_context_switch)
        gen_helper_kreit_trace_context_switch(cpu_env);
}

static void app_func_update_cpu_current_pid(void *instr_data, void *userdata)
{
    KreitContextSwitchState *app = KREIT_CONTEXT_SWITCH_STATE(userdata);
    const KreitSwitchPair *spair = instr_data;

    *curr_cpu_data(current_pid) = spair->next;
    strncpy(*curr_cpu_data(current_thread_name), spair->next_name, PROCESS_NAME_LENGTH);
    qatomic_inc(&app->switch_index);

    if (kreitapp_get_verbose(OBJECT(app)) >= 1)
        kreit_log_context_switch(spair);

    // if (app->switch_index % 1000 == 0)
    //     fprintf(stderr, "# context switch: %ld\n", app->switch_index);
}

static void app_func_trace_bp_context_switch(void *instr_data, void *userdata)
{
    CPUState *cpu = (CPUState *)instr_data;
    KreitSwitchPair spair;

    kreit_fill_switch_pair(cpu, &spair, false);
    kreit_trace_context_switch(&spair);
    _skip_next_tcg_instr[cpu->cpu_index] = true;
}

static int context_switch_start_hook(Object *obj)
{
    return 0;
}

static void context_switch_stop_hook(Object *obj)
{
}

static void kreit_context_switch_instance_init(Object *obj)
{
    KreitContextSwitchState *app = KREIT_CONTEXT_SWITCH_STATE(obj);
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);
    MachineState *machine = MACHINE(qdev_get_machine());

    if (!(qdict_haskey(kcont.kernel_info, "context-switch-addr") &&
        qdict_haskey(kcont.kernel_info, "pname-offset") &&
        qdict_haskey(kcont.kernel_info, "pid-offset"))) {
        qemu_log("kreit: context-switch app init failed\n");
        g_assert(0);
    }

    const char *addr_str = qdict_get_str(kcont.kernel_info, "context-switch-addr");
    switch_conf.addr_context_switch = strtoull(addr_str, NULL, 16);
    switch_conf.pid_offset = qdict_get_int(kcont.kernel_info, "pid-offset");
    switch_conf.pname_offset = qdict_get_int(kcont.kernel_info, "pname-offset");

    qemu_spin_init(&app->switch_lock);
    kac->register_instr(obj, KREIT_INSTR_GEN_TB_START, app_func_insert_context_switch_instr);
    kac->register_instr(obj, KREIT_INSTR_TRACE_CONTEXT_SWITCH, app_func_update_cpu_current_pid);
    app->switch_index = 0;

    _skip_next_tcg_instr = g_malloc0(machine->smp.max_cpus * sizeof(bool));

    app->trace_kvm = true;
}

static void kreit_context_switch_instance_finalize(Object *obj)
{
    g_free(_skip_next_tcg_instr);
    _skip_next_tcg_instr = NULL;
}

static void app_set_trace_kvm(Object *obj, bool value, Error **errp)
{
    KreitContextSwitchState *kas = KREIT_CONTEXT_SWITCH_STATE(obj);

    kas->trace_kvm = value;
}

static void kreit_context_switch_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);

    kac->name = KREIT_CONTEXT_SWITCH_APPNAME;
    kac->start_hook = context_switch_start_hook;
    kac->stop_hook = context_switch_stop_hook;

    object_class_property_add_bool(klass, "trace-kvm", NULL, app_set_trace_kvm);
}

static const TypeInfo kreit_context_switch_type = {
    .name = TYPE_KREIT_CONTEXT_SWITCH,
    .parent = TYPE_KREITAPP,
    .instance_init = kreit_context_switch_instance_init,
    .instance_finalize = kreit_context_switch_instance_finalize,
    .class_init = kreit_context_switch_class_init,
    .instance_size = sizeof(KreitContextSwitchState),
};

static void kreit_context_switch_type_init(void)
{
    type_register_static(&kreit_context_switch_type);
}

type_init(kreit_context_switch_type_init);
