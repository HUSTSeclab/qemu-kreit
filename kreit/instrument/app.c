#include "kreit/instrument/app.h"

#include "qemu/log.h"
#include "qapi/visitor.h"
#include <stdio.h>

// List of KreitAppState
GHashTable *app_list;

void kreitapp_add_dependency(KreitAppClass* kac, const char *deps)
{
    kac->__app_dependencies = g_list_append(kac->__app_dependencies, (gpointer)deps);
}

static void gfunc_start_app_dependencies(gpointer data, gpointer userdata)
{
    kreitapp_start_by_name(data);
}

KreitAppState *kreitapp_find_by_name(const char *name)
{
    return g_hash_table_lookup(app_list, name);
}

int kreitapp_start_by_name(const char *name)
{
    KreitAppState *kas = g_hash_table_lookup(app_list, name);
    KreitAppClass *kac;

    if (!kas)
        return -1;

    kac = KREITAPP_GET_CLASS(kas);
    g_list_foreach(kac->__app_dependencies, gfunc_start_app_dependencies, NULL);
    return kac->start(OBJECT(kas));
}

int kreitapp_stop_by_name(const char *name)
{
    KreitAppState *kas = g_hash_table_lookup(app_list, name);
    KreitAppClass *kac;

    if (!kas)
        return -1;

    kac = KREITAPP_GET_CLASS(kas);
    kac->stop(OBJECT(kas));
    return 0;
}

static void ghfunc_start_app(gpointer key, gpointer value, gpointer user_data)
{
    KreitAppState *kas = value;
    KreitAppClass *kac = KREITAPP_GET_CLASS(kas);

    kreitapp_start_by_name(kac->name);
}

void kreitapp_start_all(void)
{
    g_hash_table_foreach(app_list, ghfunc_start_app, NULL);
}

static void gfunc_init_app_dependencies(gpointer data, gpointer userdata)
{
    kreitapp_init_by_name(data);
}

KreitAppState *kreitapp_init_by_name(const char *name)
{
    KreitAppState *kas;
    KreitAppClass *kac;

    kas = g_hash_table_lookup(app_list, name);
    if (kas)
        return kas;

    // init the dependencies first
    char *class_name = g_strdup_printf(KREITAPP_CLASS_NAME("%s"), name);

    kac = KREITAPP_CLASS(object_class_by_name(class_name));
    g_list_foreach(kac->__app_dependencies, gfunc_init_app_dependencies, NULL);

    kas = KREITAPP_STATE(object_new(class_name));
    g_free(class_name);

    g_hash_table_insert(app_list, (gpointer)name, kas);

    return kas;
}

static void kreitapp_register_instr(Object *obj, KreitInstrType type,
                                    KreitAppCallback callback)
{
    KreitInstrState *kis;
    KreitAppState *app = KREITAPP_STATE(obj);
    kis = kreitinstr_register(type, callback, app);
    app->__instr_list = g_list_append(app->__instr_list, kis);
}

static void gfunc_kreit_app_switch_valid_bit(void *data, gpointer on)
{
    KreitInstrState *kis = data;

    bool this_on = GPOINTER_TO_INT(on);
    kis->__valid_bit = this_on;
}

static int kreitapp_start_instr(Object *obj)
{
    int ret = 0;
    KreitAppState *app = KREITAPP_STATE(obj);
    KreitAppClass *kac = KREITAPP_GET_CLASS(app);

    if (app->__app_active)
        return 0;

    if (kac->start_hook) {
        ret = kac->start_hook(obj);
        if (ret)
            return ret;
    }

    /// FIXME: add something like read write lock here
    g_list_foreach(app->__instr_list, gfunc_kreit_app_switch_valid_bit, GINT_TO_POINTER(true));
    app->__app_active = true;

    return 0;
}

static void kreitapp_stop_instr(Object *obj)
{
    KreitAppState *app = KREITAPP_STATE(obj);
    KreitAppClass *kac = KREITAPP_GET_CLASS(app);

    if (!app->__app_active)
        return;

    /// FIXME: add something like read write lock here
    g_list_foreach(app->__instr_list, gfunc_kreit_app_switch_valid_bit, GINT_TO_POINTER(false));

    if(kac->stop_hook)
        kac->stop_hook(obj);
    app->__app_active = false;
}

static bool kreitapp_is_running(Object *obj)
{
    KreitAppState *kas = KREITAPP_STATE(obj);

    return kas->__app_active;
}

static void gfunc_unregister_instr(gpointer data, gpointer userdata)
{
    KreitInstrState *kis = data;
    kreitinstr_unregister(kis);
}

static void kreitapp_deinit(Object *obj)
{
    KreitAppState *kas = KREITAPP_STATE(obj);
    KreitAppClass *kac = KREITAPP_GET_CLASS(obj);

    kac->stop(obj);
    g_list_foreach(kas->__instr_list, gfunc_unregister_instr, NULL);
    g_hash_table_remove(app_list, kas);
}

static void gfunc_print_app_status(gpointer key, gpointer value, gpointer user_data)
{
    KreitAppState *kas = value;
    KreitAppClass *kac = KREITAPP_GET_CLASS(kas);

    qemu_log("kreitapp: %s, running status: %d\n", kac->name, kac->is_running(OBJECT(kas)));
}

void kreitapp_print_app_status(void)
{
    g_hash_table_foreach(app_list, gfunc_print_app_status, NULL);
}

static void kreitapp_set_appname(Object *obj, const char *str, Error **errp)
{
    KreitAppState *kas = KREITAPP_STATE(obj);

    g_free(kas->appname);
    kas->appname = g_strdup(str);
}

static void kreitapp_set_autostart(Object *obj, bool value, Error **errp)
{
    KreitAppState *kas = KREITAPP_STATE(obj);

    kas->autostart = value;
}

static void kreitapp_set_verbose(Object *obj, Visitor *v,
                                 const char *name, void *opaque,
                                 Error **errp)
{
    KreitAppState *kas = KREITAPP_STATE(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }

    kas->verbose = value;
}

static void kreitapp_class_init(ObjectClass *klass, void *data)
{
    KreitAppClass *kac = KREITAPP_CLASS(klass);

    kac->register_instr = kreitapp_register_instr;
    kac->start = kreitapp_start_instr;
    kac->stop = kreitapp_stop_instr;
    kac->is_running = kreitapp_is_running;

    object_class_property_add_str(klass, "appname",
        NULL, kreitapp_set_appname);

    object_class_property_add_bool(klass, "autostart",
        NULL, kreitapp_set_autostart);

    object_class_property_add(klass, "verbose", "int",
        NULL, kreitapp_set_verbose,
        NULL, NULL);
}

static const TypeInfo kreitapp_type = {
    .name = TYPE_KREITAPP,
    .parent = TYPE_OBJECT,
    .class_size = sizeof(KreitAppClass),
    .class_init = kreitapp_class_init,
    .instance_size = sizeof(KreitAppState),
    .instance_finalize = kreitapp_deinit
};

static void kreitapp_type_init(void)
{
    app_list = g_hash_table_new(g_str_hash, g_str_equal);
    type_register_static(&kreitapp_type);
}

type_init(kreitapp_type_init);
