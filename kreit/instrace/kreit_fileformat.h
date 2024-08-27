#ifndef __KREIT_FILEFORMAT_H__
#define __KREIT_FILEFORMAT_H__

// Kreit file format v0.7

#include <stdint.h>
#include <stddef.h>

#define KREIT_FILEHEADER_LEN (4096)

#define KREIT_IDENT_LEN (8)

#define KERIT_MAG0 'K'
#define KERIT_MAG1 'R'
#define KERIT_MAG2 'E'
#define KERIT_MAG3 'I'
#define KERIT_MAG4 'T'

#define KREIT_MAGNUMS "KREIT"

typedef struct KreitFileHeader {
    // Magic number
    uint8_t ident[KREIT_IDENT_LEN];
    // Trace ID: timestamps of this tracing log
    uint64_t trace_id;
    // Value defined by <elf.h>
    int32_t e_machine;
    // Number of cpus of this instance
    uint32_t nr_cpus;
    // Index of the CPU emulated by QEMU
    uint32_t cpu_idx;
    // Size of register value buffer
    uint64_t regval_size;
    // Start object index of this tracing file
    uint64_t start_index;
    // End object index of this tracing file
    uint64_t end_index;
    // State of the icount mode (bool value)
    int32_t icount_on;
} KreitFileHeader;

typedef struct {
    uint16_t flag;
    uint16_t data_len;
    uint32_t cpl;
} KreitDataHeader;

#endif
