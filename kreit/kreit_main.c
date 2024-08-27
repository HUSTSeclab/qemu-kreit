#include "kreit/kreit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <errno.h>
#include "glibconfig.h"
#include "gmodule.h"
#include "hw/core/cpu.h"
#include "qapi-types-kreit.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qobject.h"
#include "qapi/util.h"
#include "qemu/compiler.h"
#include "qemu/log-for-trace.h"
#include "qemu/option.h"
// #include "kreit_target.h"
#include "qemu/thread.h"
#include "qemu/typedefs.h"
#include "qemu/config-file.h"
#include "hw/boards.h"
#include "exec/cpu-defs.h"
#include "kreit/instrument/app.h"

KreitTraceController kcont;

// static void init_vmlinux_info(const char *vmlinux_fn, uint64_t pid_offset, uint64_t pname_offset)
// {
//     struct vmlinux_parser *vmlinux;
//     target_ulong addr;

//     vmlinux = vmlinux_parser_init(vmlinux_fn);
//     g_assert(vmlinux);

//     if (!vmlinux_parser_symbol_value(vmlinux, "__switch_to_asm", &addr)) {
//         qemu_log("kreit: cannot get the address of __switch_to_asm\n");
//         g_assert(0);
//     }
//     *kreit_config(addr_context_switch) = addr;
//     qemu_log("kreit: " TARGET_FMT_lx " __switch_to_asm\n", addr);
//     if (!vmlinux_parser_symbol_value(vmlinux, "crash_save_vmcoreinfo", &addr)) {
//         qemu_log("kreit: cannot get the address of crash_save_vmcoreinfo\n");
//         g_assert(0);
//     }
//     // kcont.addr_crash_save_vmcoreinfo = addr;
//     // qemu_log("kreit: " TARGET_FMT_lx " crash_save_vmcoreinfo\n", kcont.addr_crash_save_vmcoreinfo);

//     *kreit_config(pid_offset) = pid_offset;
//     *kreit_config(name_offset) = pname_offset;
//     qemu_log("kreit: offsetof(pid, struct task_struct) = %ld\n", pid_offset);
//     qemu_log("kreit: offsetof(comm, struct task_struct) = %ld\n", pname_offset);

//     vmlinux_parser_destroy(vmlinux);
// }

// static void kreit_init_target_linux(QemuOpts *opts)
// {
//     kcont.target = TRACE_TARGET_LINUX;

//     // const char *output_path = qemu_opt_get(opts, "output-path");

//     const char *vmlinux_fn = qemu_opt_get(opts, "vmlinux");
//     qemu_log("kriet: vmlinux path: %s\n", vmlinux_fn);
//     if (vmlinux_fn)
//         init_vmlinux_info(vmlinux_fn,
//                           qemu_opt_get_number(opts, "pid-offset", 0),
//                           qemu_opt_get_number(opts, "pname-offset", 0));
// }

// static void kreit_init_target_qnx(QemuOpts *opts)
// {
//     kcont.target = TRACE_TARGET_QNX;

//     /// FIXME: do not hard code this address
//     *kreit_config(addr_context_switch) = 0xffff800000067ab0;
//     *kreit_config(pid_offset) = 0x8;
//     *kreit_config(name_offset) = 0x1a0;
// }

// copy from vl.c
static int object_parse_property_opt(Object *obj,
                                     const char *name, const char *value,
                                     const char *skip, Error **errp)
{
    if (g_str_equal(name, skip)) {
        return 0;
    }

    if (!object_property_parse(obj, name, value, errp)) {
        return -1;
    }

    return 0;
}

static int kreitapp_set_property(void *opaque,
                                const char *name, const char *value,
                                Error **errp)
{
    return object_parse_property_opt(opaque, name, value, "accel", errp);
}

static int init_kreit_apps(void *opaque, QemuOpts *opts, Error **errp)
{
    KreitAppState *app_state;
    const char *appname = qemu_opt_get(opts, "appname");

    app_state = kreitapp_init_by_name(appname);
    qemu_opt_foreach(opts, kreitapp_set_property,
                     app_state,
                     &error_fatal);

    qemu_log("kreitapp: found app: %s, autostart: %d\n", appname, app_state->autostart);
    if (app_state->autostart)
        kreitapp_start_by_name(appname);
    return 0;
}

// static int init_target_info(QemuOpts *opts)
// {
//     const char* target = qemu_opt_get(opts, "target");
//     if (!target)
//         return -1;

//     if (!strcmp("linux", target)) {
//         qemu_log("kreit: select target as linux\n");
//         kreit_init_target_linux(opts);
//     } else if (!strcmp("qnx", target)) {
//         qemu_log("kreit: select target as qnx\n");
//         kreit_init_target_qnx(opts);
//     } else {
//         qemu_log("kreit: unknown target provided\n");
//         return -1;
//     }
//     return 0;
// }

static int init_kernel_info(QemuOpts *opts)
{
    FILE *kernel_info;
    long filesize;
    long readsize;
    char *filebuff;
    int ret = 0;

    const char *target_name = qemu_opt_get(opts, "target");
    if (!target_name)
        return -1;

    if (strcmp(target_name, "linux") == 0) {
        kcont.target = TRACE_TARGET_LINUX;
    } else if (strcmp(target_name, "qnx") == 0) {
        kcont.target = TRACE_TARGET_QNX;
    } else {
        qemu_log("No target name provided\n");
        return -1;
    }

    const char *kernel_info_fn = qemu_opt_get(opts, "kernel-info");
    if (!kernel_info_fn) {
        qemu_log("kreit: no kernel info file provided\n");
        return -1;
    }

    kernel_info = fopen(kernel_info_fn, "r");
    if (!kernel_info) {
        qemu_log("kreit: error on opening file %s: %s\n", kernel_info_fn, strerror(errno));
        return errno;
    }

    fseek(kernel_info, 0, SEEK_END);
    filesize = ftell(kernel_info);
    fseek(kernel_info, 0, SEEK_SET);

    filebuff = g_malloc0(filesize + 1);
    readsize = fread(filebuff, 1, filesize, kernel_info);
    if (readsize != filesize) {
        qemu_log("kreit: error on read file\n");
        ret = errno;
        goto err_need_close;
    }

    kcont.kernel_info = qobject_to(QDict, qobject_from_json(filebuff, NULL));
    if (!kcont.kernel_info) {
        qemu_log("kreit: error on parsing json file\n");
        ret = -1;
        goto err_need_close;
    }

err_need_close:
    g_free(filebuff);
    fclose(kernel_info);
    return ret;
}

int kreit_init(void)
{
    int ret;
    QemuOpts *opts;
    QemuOptsList *olist;
    MachineState *machine = MACHINE(qdev_get_machine());

    olist = qemu_find_opts("kreit");

    opts = qemu_opts_create(olist, NULL, 0, &error_abort);

    kcont.nr_cpus = machine->smp.max_cpus;
    kcont.mem_size = machine->ram_size;

    kcont.percpu_data = g_malloc0(sizeof(KreitPerCpuData) * kcont.nr_cpus);

    // init kernel info
    ret = init_kernel_info(opts);
    if (ret != 0) {
        qemu_log("kreit: init kernel info failed\n");
        return ret;
    }

    // init target ops
    // ret = init_target_info(opts);
    // if (ret != 0)
    //     qemu_log("kreit: target specified function not working.\n");

    // init apps
    olist = qemu_find_opts("kreitapp");
    qemu_opts_foreach(qemu_find_opts("kreitapp"),
                      init_kreit_apps, NULL, &error_fatal);
    kreitapp_print_app_status();

    qemu_opts_del(opts);
    return 0;
}

static __attribute__((destructor)) void kreit_destroy(void)
{
    g_free(kcont.percpu_data);
    qobject_unref(kcont.kernel_info);
}
