#ifndef __KREIT_COVERAGE_APP_H__
#define __KREIT_COVERAGE_APP_H__

#include "qemu/osdep.h"
#include "kreit/instrument/app.h"
#include "qapi/qapi-commands-kreit.h"
#include "exec/exec-all.h"

#define KREIT_COVERAGE_APPNAME "coverage"
#define TYPE_KREIT_COVERAGE KREITAPP_CLASS_NAME(KREIT_COVERAGE_APPNAME)

typedef struct KreitCoverageThread {
    int pid;
    GHashTable *tb_map;
    GHashTable *edge_map;
} KreitCoverageThread;

#define KREIT_START_TB_BUFF_SIZE (1 << 16)
#define KREIT_TRANSLATE_BUFF_SIZE (1 << 8)

typedef struct AppTB {
    target_ulong pc;
    size_t size;
} AppTB;

typedef struct AppPerCpuData {
    target_ulong *tb_addrs;
    size_t tb_addrs_idx;

    AppTB *trans_tb;
    size_t trans_tb_idx;
} AppPerCpuData;

typedef struct KreitCoverageState {
    /*< private >*/
    KreitAppState parent_obj;

    // Configuration
    bool block_coverage;
    bool edge_coverage;

    /*< public >*/
    GHashTable *threads;
    QemuSpin threads_lock;

    AppPerCpuData *percpu;
} KreitCoverageState;

DECLARE_INSTANCE_CHECKER(KreitCoverageState, KREIT_COVERAGE_STATE,
                         TYPE_KREIT_COVERAGE)

typedef struct KreitCoverageQapiData {
    KreitBlockCoverageList block_cov_list;
    QemuSpin block_cov_lock;
    KreitEdgeCoverageList edge_cov_list;
    QemuSpin edge_cov_lock;
} KreitCoverageQapiData;

extern KreitCoverageQapiData kreit_coverage_qapi_data;

#endif // __KREIT_COVERAGE_APP_H__
