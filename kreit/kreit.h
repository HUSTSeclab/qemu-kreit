#ifndef __KREIT_H__
#define __KREIT_H__

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "qemu/thread.h"

typedef enum TraceTarget {
    TRACE_TARGET_LINUX,
    TRACE_TARGET_QNX
} TraceTarget;

#define PROCESS_NAME_LENGTH 256

typedef struct KreitPerCpuData {
    int current_pid;
    char current_thread_name[PROCESS_NAME_LENGTH];
    int cpl;
} KreitPerCpuData;

typedef struct KreitTraceController {
    TraceTarget target;
    KreitPerCpuData *percpu_data;
    size_t nr_cpus;
    size_t mem_size;
    QDict *kernel_info;
} KreitTraceController;

extern KreitTraceController kcont;

#define cpu_n_data(index, datafeild) (&kcont.percpu_data[index].datafeild)
#define curr_cpu_data(datafeild) cpu_n_data(current_cpu->cpu_index, datafeild)

// #define kreit_config(datafeild) (&kcont.conf.datafeild)

int kreit_init(void);

uint32_t kreit_cpu_ldl(CPUState *cpu, vaddr addr);
uint64_t kreit_cpu_ldq(CPUState *cpu, vaddr addr);
void kreit_cpu_stl(CPUState *cpu, vaddr addr, uint32_t val);
void kreit_cpu_stq(CPUState *cpu, vaddr addr, uint64_t val);

#endif // __KREIT_H__
