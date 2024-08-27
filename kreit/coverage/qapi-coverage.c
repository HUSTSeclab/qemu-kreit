#include "qemu/osdep.h"
#include "qapi/util.h"
#include "qapi/qapi-commands-kreit.h"
#include "qapi/error.h"
#include "kreit/coverage/coverage-app-common.h"
#include "kreit/instrument/app.h"
#include "qemu/thread.h"

KreitBlockCoverageList *qmp_kreit_block_coverage(Error **errp)
{
    KreitBlockCoverageList *list;
    KreitCoverageState *kas = KREIT_COVERAGE_STATE(kreitapp_find_by_name("coverage"));

    if (!kas->block_coverage) {
        error_setg(errp, "block coverage is not enabled");
        return NULL;
    }

    qemu_spin_lock(&kreit_coverage_qapi_data.block_cov_lock);
    list = kreit_coverage_qapi_data.block_cov_list.next;
    kreit_coverage_qapi_data.block_cov_list.next = NULL;
    qemu_spin_unlock(&kreit_coverage_qapi_data.block_cov_lock);

    return list;
}

KreitEdgeCoverageList *qmp_kreit_edge_coverage(Error **errp)
{
    KreitEdgeCoverageList *list;
    KreitCoverageState *kas = KREIT_COVERAGE_STATE(kreitapp_find_by_name("coverage"));

    if (!kas->edge_coverage) {
        error_setg(errp, "edge coverage is not enabled");
        return NULL;
    }

    qemu_spin_lock(&kreit_coverage_qapi_data.edge_cov_lock);
    list = kreit_coverage_qapi_data.edge_cov_list.next;
    kreit_coverage_qapi_data.edge_cov_list.next = NULL;
    qemu_spin_unlock(&kreit_coverage_qapi_data.edge_cov_lock);

    return list;
}
