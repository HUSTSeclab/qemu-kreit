#include "kreit/instrument/app.h"
#include "kreit/kreit.h"
#include "qemu/log.h"
#include "kreit_target.h"
#include "qemu/thread.h"
#include "circ_buf.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-dump.h"
#include "qapi/qmp/qdict.h"
#include "qapi/visitor.h"
#include "sysemu/runstate.h"

#define KREIT_INSTRACE_APPNAME "instrace"
#define TYPE_KREIT_INSTRACE KREITAPP_CLASS_NAME(KREIT_INSTRACE_APPNAME)

typedef struct AppPercpuDataStruct {
    bool thread_interesting;
} AppPercpuDataStruct;

typedef struct KreitInstraceState {
    /*< private >*/
    KreitAppState parent_obj;

    /*< public >*/
    AppPercpuDataStruct *percpu_data;

    QemuSpin last_int_regs_lock;
    KreitRegisters last_int_regs;

    // char *regs_buff;
    uint64_t ringbuffer_size;
    circ_buf inst_trace_buff;
    size_t instcount;
} KreitInstraceState;

DECLARE_INSTANCE_CHECKER(KreitInstraceState, KREIT_INSTRACE_STATE,
                         TYPE_KREIT_INSTRACE)

#define app_percpu_data(container, datafeild) (&container->percpu_data[current_cpu->cpu_index].datafeild)

static void dump_trace_core(KreitInstraceState *app)
{
    char dir_template[] = "./kreit-dump.XXXXXX";
    char *dir_name;
    char *file_name;
    char *commands;
    FILE *file;
    size_t index;
    target_ulong *pos;
    uint32_t addr_data;
    size_t res;
    int ret;
    Error *err = NULL;

    dir_name = mkdtemp(dir_template);
    if (dir_name == NULL) {
        qemu_log("create tempdir failed: %s\n", strerror(errno));
    }

    file_name = g_strdup_printf("file:%s/%s", dir_name, "memorydump.elf");
    vm_stop(RUN_STATE_PAUSED);
    qmp_dump_guest_memory(false, file_name, true, false,
                          false, 0, false, 0, true,
                          DUMP_GUEST_MEMORY_FORMAT_ELF, &err);
    g_free(file_name);
    vm_start();

    file_name = g_strdup_printf("%s/%s", dir_name, "instrace.bin");
    file = fopen(file_name, "wb");
    g_free(file_name);
    if (!file) {
        qemu_log("Could not open file %s: %s\n", file_name, strerror(errno));
        return;
    }
    circ_buf_for_each_entry(index, pos, &app->inst_trace_buff, target_ulong) {
        addr_data = *pos & 0xffffffff;
        res = fwrite(&addr_data, sizeof(uint32_t), 1, file);
        if (res != 1) {
            qemu_log("write instrace failed: %s\n", strerror(errno));
            fclose(file);
            return;
        }
    }
    qemu_log("instcount: %ld\n", app->instcount);
    fclose(file);

    file_name = g_strdup_printf("%s/%s", dir_name, "registers.bin");
    file = fopen(file_name, "wb");
    g_free(file_name);
    if (!file) {
        qemu_log("Could not open file %s: %s\n", file_name, strerror(errno));
        return;
    }
    res = fwrite(&app->last_int_regs, sizeof(KreitRegisters), 1, file);
    if (res != 1) {
        qemu_log("write register failed: %s\n", strerror(errno));
        fclose(file);
        return;
    }
    fclose(file);

    commands = g_strdup_printf("tar -C %s -caf kreit-dump.tar.gz ./", dir_name);
    ret = system(commands);
    if (ret) {
        qemu_log("run tar command error: %d\n", ret);
        return;
    }
    g_free(commands);

    commands = g_strdup_printf("rm -rf %s", dir_name);
    ret = system(commands);
    if (ret) {
        qemu_log("run rm command error: %d\n", ret);
    }
    g_free(commands);
}

static void app_instrace_trace_context_switch(void *instr_data, void *userdata)
{
    const KreitSwitchPair *spair = instr_data;
    KreitInstraceState *app = userdata;

    if (strstr(spair->next_name, "poc")) {
        *app_percpu_data(app, thread_interesting) = true;
    }
}

static void app_instrace_trace_tb_start(void *instr_data, void *userdata)
{
    const KreitEnvPC *envpc = instr_data;
    KreitInstraceState *app = userdata;
    int cpl = get_cpu_privilege(envpc->env);

    if (is_cpu_kernel_mode(cpl) && *app_percpu_data(app, thread_interesting)) {
        // record instruction
        circ_buf_insert(&app->inst_trace_buff, target_ulong, &envpc->pc);
        app->instcount++;
    }
}

static void app_trace_interrupt(void *instr_data, void *userdata)
{
    const KreitInterruptInfo *info = instr_data;
    KreitInstraceState *app = KREIT_INSTRACE_STATE(userdata);
    CPUArchState *env = info->env;
    int cpl = get_cpu_privilege(env);

    if (!is_cpu_kernel_mode(cpl))
        return;

    if (info->intno == 0xe) {
        // General Protection Fault
        qemu_spin_lock(&app->last_int_regs_lock);
        kreit_copy_cpu_regs(env, &app->last_int_regs);
        qemu_spin_unlock(&app->last_int_regs_lock);
    }
}

static void app_die_hook(void *instr_data, void *userdata)
{
    Object *obj = OBJECT(userdata);
    // KreitInstraceState *app = KREIT_INSTRACE_STATE(obj);
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);
    // CPUArchState *env = instr_data;

    // dump guest memory and stop trace
    qemu_log("kreit: guest kernel died\n");
    // kreit_copy_die_regs(env, app->regs_buff, *kreit_config(pt_regs_size));
    dump_trace_core(KREIT_INSTRACE_STATE(obj));
    kac->stop(obj);
}

static int app_init_userdata(Object *obj)
{
    KreitInstraceState *app = KREIT_INSTRACE_STATE(obj);
    circ_buf_init(&app->inst_trace_buff, target_ulong,
                  g_malloc(sizeof(target_ulong) * app->ringbuffer_size), app->ringbuffer_size);
    qemu_log("kreit: init circ buffer with size: %#lx\n", app->ringbuffer_size);
    return 0;
}

static void app_destroy_userdata(Object *obj)
{
    KreitInstraceState *app = KREIT_INSTRACE_STATE(obj);
    g_free(app->inst_trace_buff.buf);
    memset(&app->inst_trace_buff, 0, sizeof(circ_buf));
}

static void kreit_instrace_instance_init(Object *obj)
{
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);
    KreitInstraceState *app = KREIT_INSTRACE_STATE(obj);

    kac->register_instr(obj, KREIT_INSTR_TRACE_CONTEXT_SWITCH, app_instrace_trace_context_switch);
    kac->register_instr(obj, KREIT_INSTR_TB_START_ADDR, app_instrace_trace_tb_start);
    kac->register_instr(obj, KREIT_INSTR_INTTERUPT, app_trace_interrupt);
    kac->register_instr(obj, KREIT_INSTR_TRACE_DIE, app_die_hook);

    app->percpu_data = g_malloc0(sizeof(AppPercpuDataStruct) * kcont.nr_cpus);
    // qemu_spin_init(&app->last_int_regs_lock);
    app->ringbuffer_size = 1 << 16;
    app->instcount = 0;
    // app->regs_buff = g_malloc0(*kreit_config(pt_regs_size));
}

static void kreit_instrace_instance_finalize(Object *obj)
{
    KreitInstraceState *app = KREIT_INSTRACE_STATE(obj);

    // g_free(app->regs_buff);
    g_free(app->percpu_data);
}

static void app_set_ringbuffer_size(Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    KreitInstraceState *app = KREIT_INSTRACE_STATE(obj);
    uint64_t value;

    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }

    app->ringbuffer_size = value;
}

static void kreit_instrace_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);
    kac->name = KREIT_INSTRACE_APPNAME;
    kac->start_hook = app_init_userdata;
    kac->stop_hook = app_destroy_userdata;
    kreitapp_add_dependency(kac, "die-hook");
    kreitapp_add_dependency(kac, "tbstart");
    kreitapp_add_dependency(kac, "context-switch");

    object_class_property_add(klass, "ringbuffer-size", "uint64", NULL, app_set_ringbuffer_size, NULL, NULL);
}

static const TypeInfo kreit_instrace_type = {
    .name = TYPE_KREIT_INSTRACE,
    .parent = TYPE_KREITAPP,
    .instance_init = kreit_instrace_instance_init,
    .instance_finalize = kreit_instrace_instance_finalize,
    .class_init = kreit_instrace_class_init,
    .instance_size = sizeof(KreitInstraceState),
};

static void kreit_instrace_type_init(void)
{
    type_register_static(&kreit_instrace_type);
}

type_init(kreit_instrace_type_init);
