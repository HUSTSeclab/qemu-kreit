#include "instrument.h"

#include "qemu/atomic.h"

static GList *kreit_instr_list[KREIT_INSTR_END];

static void gfunc_kreit_instr_invoke_callback(gpointer data, gpointer user_data)
{
    KreitInstrState *kis = data;
    KreitInstrClass *kic = KREITINSTR_GET_CLASS(kis);
    void *instr_data = user_data;

    kic->invoke_callback(kis, instr_data);
}

void __kreit_instrument(KreitInstrType type, void *instr_data)
{
    GList *this_list = kreit_instr_list[type];

    g_list_foreach(this_list, gfunc_kreit_instr_invoke_callback, (gpointer)instr_data);
}

static void kreitinstr_invoke_callback(KreitInstrState *kis, void *instr_data)
{
    if (kis->type == KREIT_INSTR_GEN_TB_START) {
        kis->callback(instr_data, kis->userdata);
        return;
    }

    if (kis->__valid_bit) {
        kis->callback(instr_data, kis->userdata);
        return;
    }
}

KreitInstrState *kreitinstr_register(KreitInstrType type, KreitInstrumentCallback callback, void *data)
{
    KreitInstrClass *kic;
    KreitInstrState *kis;

    kic = KREITINSTR_CLASS(module_object_class_by_name(TYPE_KREITINSTR));
    kis = KREITINSTR_STATE(object_new_with_class(OBJECT_CLASS(kic)));

    kic->init_instr(kis, type, callback, data);
    kreit_instr_list[type] = g_list_append(kreit_instr_list[type], kis);

    return kis;
}

void kreitinstr_unregister(KreitInstrState *kis)
{
    kreit_instr_list[kis->type] = g_list_remove(kreit_instr_list[kis->type], kis);
}

static void kreitinstr_init_instr(KreitInstrState *kis, KreitInstrType type,
                                  KreitInstrumentCallback callback, void *data)
{
    kis->type = type;
    kis->callback = callback;
    kis->userdata = data;
}

static void kreitinstr_instance_init(Object *obj)
{
    KreitInstrState *kis = KREITINSTR_STATE(obj);

    kis->__valid_bit = false;
}

static void kreitinstr_class_init(ObjectClass *klass, void *data)
{
    KreitInstrClass *kic = KREITINSTR_CLASS(klass);

    kic->init_instr = kreitinstr_init_instr;
    kic->invoke_callback = kreitinstr_invoke_callback;
}

static const TypeInfo kreitinstr_type = {
    .name = TYPE_KREITINSTR,
    .parent = TYPE_OBJECT,
    .class_size = sizeof(KreitInstrClass),
    .instance_size = sizeof(KreitInstrState),
    .instance_init = kreitinstr_instance_init,
    .class_init = kreitinstr_class_init
};

static void kreitinstr_type_init(void)
{
    type_register_static(&kreitinstr_type);
}

type_init(kreitinstr_type_init);
