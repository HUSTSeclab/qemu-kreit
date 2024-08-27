#include "context-switch-common.h"

#include "qemu/osdep.h"
#include "exec/exec-all.h"
#include "kreit/kreit.h"
#include "qemu/log.h"

KreitContextSwitchConf switch_conf;

bool *_skip_next_tcg_instr;

static inline int find_zero_in_bytes(char *bytes)
{
    for (int i = 0; i < 8; i++) {
        if (bytes[i] == 0)
            return i;
    }
    return 8;
}

static void linux_get_task_comm(CPUState *cpu, char *dest, vaddr task_p)
{
    uint64_t tmp_lu;
    uint64_t name_offset = switch_conf.pname_offset;

    tmp_lu = kreit_cpu_ldq(cpu, task_p + name_offset);
    memcpy(dest, (char *)&tmp_lu, sizeof(uint64_t));
    tmp_lu = kreit_cpu_ldq(cpu, task_p + name_offset + sizeof(uint64_t));
    memcpy(dest + sizeof(uint64_t), (char *)&tmp_lu, sizeof(uint64_t));
}

/// TODO: This should be a arch deps ops
void kreit_fill_switch_pair(CPUState *cpu, KreitSwitchPair *spair, bool tcg_api)
{
    CPUArchState *env = cpu->env_ptr;
    vaddr prev_task_p;
    vaddr next_task_p;
    vaddr next_name_p;
    char tmp_bytes[8];
    int zero_index;
    int str_pivot = 0;
    uint64_t name_offset = switch_conf.pname_offset;
    uint64_t pid_offset = switch_conf.pid_offset;

    memset(spair, 0, sizeof(KreitSwitchPair));

    switch (kcont.target) {
    case TRACE_TARGET_LINUX:
        prev_task_p = env->regs[R_EDI];
        next_task_p = env->regs[R_ESI];
        spair->prev = kreit_cpu_ldl(cpu, prev_task_p + pid_offset);
        spair->next = kreit_cpu_ldl(cpu, next_task_p + pid_offset);

        linux_get_task_comm(cpu, spair->prev_name, prev_task_p);
        linux_get_task_comm(cpu, spair->next_name, next_task_p);
        break;
    case TRACE_TARGET_QNX:
        spair->prev = *curr_cpu_data(current_pid);
        spair->next = kreit_cpu_ldl(cpu, env->regs[R_ESI] + pid_offset);

        strncpy(spair->prev_name, *curr_cpu_data(current_thread_name), PROCESS_NAME_LENGTH);
        memset(spair->next_name, 0, PROCESS_NAME_LENGTH);
        next_name_p = kreit_cpu_ldq(cpu, env->regs[R_ESI] + name_offset);
        if (!next_name_p)
            break;
        while (true) {
            *((uint64_t*)tmp_bytes) = kreit_cpu_ldq(cpu, next_name_p + str_pivot);
            zero_index = find_zero_in_bytes(tmp_bytes);
            memcpy(spair->next_name + str_pivot, tmp_bytes, zero_index);
            str_pivot += zero_index;
            if (str_pivot > PROCESS_NAME_LENGTH)
                break;
            if (zero_index < 8)
                break;
        }
        break;
    default:
        break;
    }

    spair->cpu = cpu;
}

void kreit_log_context_switch(const KreitSwitchPair *spair)
{
    qemu_log("kreit: cpu %d: context switch from %d: %s to %d: %s\n",
        current_cpu->cpu_index,
        spair->prev, spair->prev_name,
        spair->next, spair->next_name);
}
