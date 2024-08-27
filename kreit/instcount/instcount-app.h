#ifndef __KREIT_INSTCOUNT_H__
#define __KREIT_INSTCOUNT_H__

#include "kreit/instrument/app.h"
#include "qemu/osdep.h"
#include "exec/cpu-defs.h"

#include "kreit/kreit.h"
#include <gmodule.h>

typedef struct KreitThreadPercpuData {
    size_t bbcount_user;
    size_t bbcount_kernel;
    int64_t time_user;
    int64_t time_kernel;
} KreitThreadPercpuData;

typedef struct KreitInstCountThread {
    int pid;
    char name[PROCESS_NAME_LENGTH];
    KreitThreadPercpuData *percpu_data;
} KreitInstCountThread;

extern GHashTable *kreit_instcount_threads;
extern QemuSpin kreit_instcount_threads_lock;

#endif // __KREIT_INSTCOUNT_H__
