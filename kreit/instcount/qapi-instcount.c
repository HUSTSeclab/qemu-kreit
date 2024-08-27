#include "qemu/osdep.h"
#include "qapi/util.h"
#include "qapi/qapi-commands-kreit.h"
#include "qemu/thread.h"

#include "instcount-app.h"

typedef struct QMPInstcountData {
    KreitThreadInstcountList list;
} QMPInstcountData;

static void grfunc_get_one_thread_data(gpointer key, gpointer value, gpointer userdata)
{
    QMPInstcountData *data = userdata;
    int pid = GPOINTER_TO_INT(key);
    KreitInstCountThread *this_thread = value;
    KreitThreadCpuData *cpudata;

    KreitThreadInstcount *one_count = g_malloc0(sizeof(KreitThreadInstcount));
    one_count->pid = pid;
    one_count->name = g_strdup(this_thread->name);
    for (int i = 0; i < kcont.nr_cpus; i++) {
        cpudata = g_malloc(sizeof(KreitThreadCpuData));
        cpudata->cpuindex = i;
        cpudata->bbcountkernel = this_thread->percpu_data[i].bbcount_kernel;
        cpudata->bbcountuser = this_thread->percpu_data[i].bbcount_user;
        cpudata->timekernel = this_thread->percpu_data[i].time_kernel;
        cpudata->timeuser = this_thread->percpu_data[i].time_user;
        QAPI_LIST_PREPEND(one_count->cpustatistics, cpudata);
        cpudata = NULL;
    }
    QAPI_LIST_PREPEND(data->list.next, one_count);
}

KreitThreadInstcountList *qmp_kreit_dump_instcount(Error **errp)
{
    QMPInstcountData data;
    data.list.next = NULL;

    qemu_spin_lock(&kreit_instcount_threads_lock);
    g_hash_table_foreach(kreit_instcount_threads, grfunc_get_one_thread_data, &data);
    qemu_spin_unlock(&kreit_instcount_threads_lock);

    return data.list.next;
}
