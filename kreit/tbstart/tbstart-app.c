#include "qemu/osdep.h"
#include "exec/cpu-defs.h"
#include "tcg/tcg.h"
#include "kreit/instrument/app.h"
#include "hw/core/cpu.h"
#include "tcg/tcg.h"
#include "exec/helper-proto-common.h"
#include "exec/helper-gen-common.h"

#define KREIT_TBSTART_APPNAME "tbstart"
#define TYPE_KREIT_TBSTART KREITAPP_CLASS_NAME(KREIT_TBSTART_APPNAME)

static void app_func_insert_tbstart_instr(void *instr_data, void *userdata)
{
    target_ulong pc = (target_ulong)instr_data;
    TCGv_i64 pc_op = tcg_constant_i64(pc);
    gen_helper_kreit_trace_tb_start(cpu_env, pc_op);
}

static void kreit_instcount_instance_init(Object *obj)
{
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);

    kac->register_instr(obj, KREIT_INSTR_GEN_TB_START, app_func_insert_tbstart_instr);
}

static void kreit_instcount_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);
    kac->name = KREIT_TBSTART_APPNAME;
}

static const TypeInfo kreit_tbstart_type = {
    .name = TYPE_KREIT_TBSTART,
    .parent = TYPE_KREITAPP,
    .instance_init = kreit_instcount_instance_init,
    .class_init = kreit_instcount_class_init,
};

static void kreit_tbstart_type_init(void)
{
    type_register_static(&kreit_tbstart_type);
}

type_init(kreit_tbstart_type_init);
