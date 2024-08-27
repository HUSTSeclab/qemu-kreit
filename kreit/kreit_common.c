#include "kreit.h"

uint32_t kreit_cpu_ldl(CPUState *cpu, vaddr addr)
{
    uint8_t buf[4];

    cpu_memory_rw_debug(cpu, addr, buf, 4, false);
    return *((uint32_t *)buf);
}

uint64_t kreit_cpu_ldq(CPUState *cpu, vaddr addr)
{
    uint8_t buf[8];

    cpu_memory_rw_debug(cpu, addr, buf, 8, false);
    return *((uint64_t *)buf);
}

void kreit_cpu_stl(CPUState *cpu, vaddr addr, uint32_t val)
{
    uint8_t buf[4];

    *((uint32_t *)buf) = val;
    cpu_memory_rw_debug(cpu, addr, buf, 4, true);
}

void kreit_cpu_stq(CPUState *cpu, vaddr addr, uint64_t val)
{
    uint8_t buf[8];

    *((uint64_t *)buf) = val;
    cpu_memory_rw_debug(cpu, addr, buf, 8, true);
}
