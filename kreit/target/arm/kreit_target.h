#include <stdint.h>
#include <elf.h>

#include "cpu.h"

#define KREIT_LEN_REGVAL (32 * sizeof(target_ulong))

static inline int get_cpu_privilege(CPUArchState *env)
{
    return arm_current_el(env);
}

static inline bool is_cpu_kernel_mode(int priv)
{
    return priv == 3;
}

#define KREIT_E_MACHINE EM_AARCH64
