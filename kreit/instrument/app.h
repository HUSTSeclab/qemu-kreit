#ifndef __KREIT_INSTRUMENT_APP_H__
#define __KREIT_INSTRUMENT_APP_H__

#include "kreit/instrument/instrument.h"
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/atomic.h"
#include "qom/object.h"

#define TYPE_KREITAPP "kreitapp"
#define KREITAPP_CLASS_PREFIX TYPE_KREITAPP "-"
#define KREITAPP_CLASS_NAME(a) (KREITAPP_CLASS_PREFIX a)

typedef KreitInstrumentCallback KreitAppCallback;

typedef struct KreitAppState {
    /*< private >*/
    Object parent_obj;
    bool __app_active;
    GList *__instr_list;

    /*< public >*/
    char *appname;
    bool autostart;
    int verbose;

    void *init_param;
} KreitAppState;

typedef struct KreitAppClass {
    /*< private >*/
    ObjectClass parent_class;
    GList *__app_dependencies;

    /*< public >*/
    const char *name;
    bool (*is_running)(Object *obj);
    void (*register_instr)(Object *obj, KreitInstrType type,
                           KreitAppCallback callback);
    int (*start)(Object *obj);
    void (*stop)(Object *obj);

    /*< pure virtual >*/
    int (*start_hook)(Object *obj);
    void (*stop_hook)(Object *obj);
} KreitAppClass;

#define KREITAPP_CLASS(klass) \
    OBJECT_CLASS_CHECK(KreitAppClass, (klass), TYPE_KREITAPP)

#define KREITAPP_GET_CLASS(obj) \
    OBJECT_GET_CLASS(KreitAppClass, (obj), TYPE_KREITAPP)

DECLARE_INSTANCE_CHECKER(KreitAppState, KREITAPP_STATE,
                         TYPE_KREITAPP)

void kreitapp_add_dependency(KreitAppClass* kac, const char *deps);

KreitAppState *kreitapp_init_by_name(const char *name);
void kreitapp_start_all(void);
KreitAppState *kreitapp_find_by_name(const char *name);
int kreitapp_start_by_name(const char *name);
int kreitapp_stop_by_name(const char *name);
void kreitapp_print_app_status(void);

static inline int kreitapp_get_verbose(Object *obj)
{
    KreitAppState* kas = KREITAPP_STATE(obj);

    return kas->verbose;
}

#endif // __KREIT_INSTRUMENT_APP_H__
