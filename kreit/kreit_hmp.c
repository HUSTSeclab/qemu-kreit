#include "qemu/osdep.h"
#include "qapi/qmp/qdict.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "kreit/kreit_hmp.h"

void hmp_kreit_start_trace(Monitor *mon, const QDict *qdict)
{
    // kreit_set_start_logging();
}

void hmp_kreit_stop_trace(Monitor *mon, const QDict *qdict)
{
    // kreit_set_stop_logging();
}
