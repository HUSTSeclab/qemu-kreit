#include "qemu/osdep.h"
#include "exec/cpu-defs.h"
#include "kreit/instrument/app.h"
#include "tcg/tcg.h"
#include "exec/helper-proto-common.h"
#include "exec/helper-gen-common.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qobject.h"
#include "qemu/log.h"

#define KREIT_DIE_HOOK_APPNAME "die-hook"
#define TYPE_KREIT_DIE_HOOK KREITAPP_CLASS_NAME(KREIT_DIE_HOOK_APPNAME)

typedef struct KreitDieHookState {
    /*< private >*/
    KreitAppState parent_obj;

    vaddr addr_die;
    vaddr addr_panic;
    /*< public >*/

} KreitDieHookState;

DECLARE_INSTANCE_CHECKER(KreitDieHookState, KREIT_DIE_HOOK_STATE,
                         TYPE_KREIT_DIE_HOOK)

static void app_insert_die_hook(void *instr_data, void *userdata)
{
    KreitDieHookState *appdata = KREIT_DIE_HOOK_STATE(userdata);

    target_ulong this_pc = (target_ulong) instr_data;

    if (this_pc == appdata->addr_die ||
        this_pc == appdata->addr_panic)
        gen_helper_kreit_trace_die(cpu_env);
}

static void app_instance_init(Object *obj)
{
    KreitDieHookState *kas = KREIT_DIE_HOOK_STATE(obj);
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);
    const char *addr_str;

    addr_str = qdict_get_str(kcont.kernel_info, "die-addr");
    if (addr_str)
        kas->addr_die = strtoull(addr_str, NULL, 16);
    else
        qemu_log("No addr of die() provided, die-hook app init failed.\n");

    addr_str = qdict_get_str(kcont.kernel_info, "panic-addr");
    if (addr_str)
        kas->addr_panic = strtoull(addr_str, NULL, 16);
    else
        qemu_log("No addr of panic() provided, die-hook app init failed.\n");


    kac->register_instr(obj, KREIT_INSTR_GEN_TB_START, app_insert_die_hook);
}

static void kreit_die_hook_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);

    kac->name = KREIT_DIE_HOOK_APPNAME;
}

static const TypeInfo kreit_die_hook_type = {
    .name = TYPE_KREIT_DIE_HOOK,
    .parent = TYPE_KREITAPP,
    .instance_init = app_instance_init,
    .class_init = kreit_die_hook_class_init,
    .instance_size = sizeof(KreitDieHookState),
};

static void kreit_die_hook_type_init(void)
{
    type_register_static(&kreit_die_hook_type);
}

type_init(kreit_die_hook_type_init);

