#include "asan-common.h"
#include "cpu.h"
#include "qemu/log.h"
#include "kreit_target.h"
#include "kreit/kreit.h"
#include "exec/log.h"

KreitAsanState *asan_state = NULL;

size_t kmalloc_cache_size[] = {
    0,
    8,
    16,
    32,
    64,
    96,
    128,
    192,
    256,
    512,
    1024,
    2048,
    4096,
    8192,
    16384,
    32768,
    65536,
    131072,
    262144,
    524288,
    1048576,
    2097152,
};

static inline size_t asan_align_to_kmalloc_cache_size(size_t size)
{
    for (int i = 0; i < sizeof(kmalloc_cache_size) / sizeof(size_t) - 1; i++) {
        if (size > kmalloc_cache_size[i] && size <= kmalloc_cache_size[i + 1])
            return kmalloc_cache_size[i + 1];
    }

    return 0;
}

size_t asan_allocator_aligned_size(size_t size)
{
    return asan_align_to_kmalloc_cache_size(size);
}

void asan_poison_region(vaddr ptr, size_t n, uint8_t poison_byte)
{
    vaddr start = ptr;
    vaddr end = ptr + n;
    size_t shadow_size;
    void *shadow_addr;

    if (kreitapp_get_verbose(OBJECT(asan_state)) >= 1)
        qemu_log("asan: poison range %#018lx - %#018lx\n", ptr, ptr + n);

    if (n == 0)
        return;

    // process partial bytes
    if (start & 0x7) {
        shadow_addr = get_shadow_addr(start);
        *((uint8_t *)shadow_addr) = start & 0x7;
    }

    if (end & 0x7) {
        shadow_addr = get_shadow_addr(end);
        *((uint8_t *)(shadow_addr + 1)) = end & 0x7;
    }

    // process others
    start = ROUND_UP(start, 8);
    end = ROUND_DOWN(end, 8);
    shadow_size = (end - start) >> 3;
    shadow_addr = get_shadow_addr(start);

    memset(shadow_addr, poison_byte, shadow_size);
}

void asan_unpoison_region(vaddr ptr, size_t n)
{
    if (kreitapp_get_verbose(OBJECT(asan_state)) >= 1)
        qemu_log("asan: unpoison range %#018lx - %#018lx\n", ptr, ptr + n);

    if (n == 0)
        return;

    void *start = get_shadow_addr(ptr);
    size_t shadow_size = ROUND_UP(n, 8) >> 3;
    memset(start, 0, shadow_size);
}

static const char* poisoned_strerror(uint8_t poison_byte)
{
    switch (poison_byte) {
        case ASAN_HEAP_RZ:
        case ASAN_HEAP_LEFT_RZ:
        case ASAN_HEAP_RIGHT_RZ: return "heap-buffer-overflow";
        case ASAN_HEAP_FREED: return "heap-use-after-free";
    }

    qemu_log("unknwon asan redzone err value: %d\n", poison_byte);
    return "use-after-poison";
}

static int poisoned_find_error(vaddr addr, size_t n,
                               vaddr* fault_addr,
                               const char** err_string)
{

  vaddr start = addr;
  vaddr end = start + n;
  int have_partials = 0;

    while (start < end) {
        int8_t* shadow_addr = get_shadow_addr(addr);
        switch (*shadow_addr) {
            case ASAN_VALID: have_partials = 0; break;
            case ASAN_PARTIAL1:
            case ASAN_PARTIAL2:
            case ASAN_PARTIAL3:
            case ASAN_PARTIAL4:
            case ASAN_PARTIAL5:
            case ASAN_PARTIAL6:
            case ASAN_PARTIAL7: {
                have_partials = 1;
                vaddr a = (start & ~7) + *shadow_addr;
                if (*fault_addr == 0 && a >= start && a < end) *fault_addr = a;
                break;

            }
            default: {
                if (*fault_addr == 0) *fault_addr = start;
                *err_string = poisoned_strerror(*shadow_addr);
                return 1;
            }
        }

        start += 8;
    }

    if (have_partials) {
        uint8_t* last_shadow_addr = get_shadow_addr((end & ~7) + 8);
        *err_string = poisoned_strerror(*last_shadow_addr);
        return 1;
    }

    if (*fault_addr == 0) *fault_addr = addr;
    *err_string = "use-after-poison";
    return 1;
}

// Regular text
#define ANSI_COLOR_BLK "\e[0;30m"
#define ANSI_COLOR_RED "\e[0;31m"
#define ANSI_COLOR_GRN "\e[0;32m"
#define ANSI_COLOR_YEL "\e[0;33m"
#define ANSI_COLOR_BLU "\e[0;34m"
#define ANSI_COLOR_MAG "\e[0;35m"
#define ANSI_COLOR_CYN "\e[0;36m"
#define ANSI_COLOR_WHT "\e[0;37m"

// High intensty text
#define ANSI_COLOR_HBLK "\e[0;90m"
#define ANSI_COLOR_HRED "\e[0;91m"
#define ANSI_COLOR_HGRN "\e[0;92m"
#define ANSI_COLOR_HYEL "\e[0;93m"
#define ANSI_COLOR_HBLU "\e[0;94m"
#define ANSI_COLOR_HMAG "\e[0;95m"
#define ANSI_COLOR_HCYN "\e[0;96m"
#define ANSI_COLOR_HWHT "\e[0;97m"

static const char* shadow_color_map[] = {

    "" /* 0x0 */,
    "" /* 0x1 */,
    "" /* 0x2 */,
    "" /* 0x3 */,
    "" /* 0x4 */,
    "" /* 0x5 */,
    "" /* 0x6 */,
    "" /* 0x7 */,
    "" /* 0x8 */,
    "" /* 0x9 */,
    "" /* 0xa */,
    "" /* 0xb */,
    "" /* 0xc */,
    "" /* 0xd */,
    "" /* 0xe */,
    "" /* 0xf */,
    "" /* 0x10 */,
    "" /* 0x11 */,
    "" /* 0x12 */,
    "" /* 0x13 */,
    "" /* 0x14 */,
    "" /* 0x15 */,
    "" /* 0x16 */,
    "" /* 0x17 */,
    "" /* 0x18 */,
    "" /* 0x19 */,
    "" /* 0x1a */,
    "" /* 0x1b */,
    "" /* 0x1c */,
    "" /* 0x1d */,
    "" /* 0x1e */,
    "" /* 0x1f */,
    "" /* 0x20 */,
    "" /* 0x21 */,
    "" /* 0x22 */,
    "" /* 0x23 */,
    "" /* 0x24 */,
    "" /* 0x25 */,
    "" /* 0x26 */,
    "" /* 0x27 */,
    "" /* 0x28 */,
    "" /* 0x29 */,
    "" /* 0x2a */,
    "" /* 0x2b */,
    "" /* 0x2c */,
    "" /* 0x2d */,
    "" /* 0x2e */,
    "" /* 0x2f */,
    "" /* 0x30 */,
    "" /* 0x31 */,
    "" /* 0x32 */,
    "" /* 0x33 */,
    "" /* 0x34 */,
    "" /* 0x35 */,
    "" /* 0x36 */,
    "" /* 0x37 */,
    "" /* 0x38 */,
    "" /* 0x39 */,
    "" /* 0x3a */,
    "" /* 0x3b */,
    "" /* 0x3c */,
    "" /* 0x3d */,
    "" /* 0x3e */,
    "" /* 0x3f */,
    "" /* 0x40 */,
    "" /* 0x41 */,
    "" /* 0x42 */,
    "" /* 0x43 */,
    "" /* 0x44 */,
    "" /* 0x45 */,
    "" /* 0x46 */,
    "" /* 0x47 */,
    "" /* 0x48 */,
    "" /* 0x49 */,
    "" /* 0x4a */,
    "" /* 0x4b */,
    "" /* 0x4c */,
    "" /* 0x4d */,
    "" /* 0x4e */,
    "" /* 0x4f */,
    "" /* 0x50 */,
    "" /* 0x51 */,
    "" /* 0x52 */,
    "" /* 0x53 */,
    "" /* 0x54 */,
    "" /* 0x55 */,
    "" /* 0x56 */,
    "" /* 0x57 */,
    "" /* 0x58 */,
    "" /* 0x59 */,
    "" /* 0x5a */,
    "" /* 0x5b */,
    "" /* 0x5c */,
    "" /* 0x5d */,
    "" /* 0x5e */,
    "" /* 0x5f */,
    "" /* 0x60 */,
    "" /* 0x61 */,
    "" /* 0x62 */,
    "" /* 0x63 */,
    "" /* 0x64 */,
    "" /* 0x65 */,
    "" /* 0x66 */,
    "" /* 0x67 */,
    "" /* 0x68 */,
    "" /* 0x69 */,
    "" /* 0x6a */,
    "" /* 0x6b */,
    "" /* 0x6c */,
    "" /* 0x6d */,
    "" /* 0x6e */,
    "" /* 0x6f */,
    "" /* 0x70 */,
    "" /* 0x71 */,
    "" /* 0x72 */,
    "" /* 0x73 */,
    "" /* 0x74 */,
    "" /* 0x75 */,
    "" /* 0x76 */,
    "" /* 0x77 */,
    "" /* 0x78 */,
    "" /* 0x79 */,
    "" /* 0x7a */,
    "" /* 0x7b */,
    "" /* 0x7c */,
    "" /* 0x7d */,
    "" /* 0x7e */,
    "" /* 0x7f */,
    "" /* 0x80 */,
    "" /* 0x81 */,
    "" /* 0x82 */,
    "" /* 0x83 */,
    "" /* 0x84 */,
    "" /* 0x85 */,
    "" /* 0x86 */,
    "" /* 0x87 */,
    "" /* 0x88 */,
    "" /* 0x89 */,
    "" /* 0x8a */,
    "" /* 0x8b */,
    "" /* 0x8c */,
    "" /* 0x8d */,
    "" /* 0x8e */,
    "" /* 0x8f */,
    "" /* 0x90 */,
    "" /* 0x91 */,
    "" /* 0x92 */,
    "" /* 0x93 */,
    "" /* 0x94 */,
    "" /* 0x95 */,
    "" /* 0x96 */,
    "" /* 0x97 */,
    "" /* 0x98 */,
    "" /* 0x99 */,
    "" /* 0x9a */,
    "" /* 0x9b */,
    "" /* 0x9c */,
    "" /* 0x9d */,
    "" /* 0x9e */,
    "" /* 0x9f */,
    "" /* 0xa0 */,
    "" /* 0xa1 */,
    "" /* 0xa2 */,
    "" /* 0xa3 */,
    "" /* 0xa4 */,
    "" /* 0xa5 */,
    "" /* 0xa6 */,
    "" /* 0xa7 */,
    "" /* 0xa8 */,
    "" /* 0xa9 */,
    "" /* 0xaa */,
    "" /* 0xab */,
    ANSI_COLOR_HRED /* 0xac */,
    "" /* 0xad */,
    "" /* 0xae */,
    "" /* 0xaf */,
    "" /* 0xb0 */,
    "" /* 0xb1 */,
    "" /* 0xb2 */,
    "" /* 0xb3 */,
    "" /* 0xb4 */,
    "" /* 0xb5 */,
    "" /* 0xb6 */,
    "" /* 0xb7 */,
    "" /* 0xb8 */,
    "" /* 0xb9 */,
    "" /* 0xba */,
    ANSI_COLOR_HYEL /* 0xbb */,
    "" /* 0xbc */,
    "" /* 0xbd */,
    "" /* 0xbe */,
    "" /* 0xbf */,
    "" /* 0xc0 */,
    "" /* 0xc1 */,
    "" /* 0xc2 */,
    "" /* 0xc3 */,
    "" /* 0xc4 */,
    "" /* 0xc5 */,
    "" /* 0xc6 */,
    "" /* 0xc7 */,
    "" /* 0xc8 */,
    "" /* 0xc9 */,
    ANSI_COLOR_HBLU /* 0xca */,
    ANSI_COLOR_HBLU /* 0xcb */,
    "" /* 0xcc */,
    "" /* 0xcd */,
    "" /* 0xce */,
    "" /* 0xcf */,
    "" /* 0xd0 */,
    "" /* 0xd1 */,
    "" /* 0xd2 */,
    "" /* 0xd3 */,
    "" /* 0xd4 */,
    "" /* 0xd5 */,
    "" /* 0xd6 */,
    "" /* 0xd7 */,
    "" /* 0xd8 */,
    "" /* 0xd9 */,
    "" /* 0xda */,
    "" /* 0xdb */,
    "" /* 0xdc */,
    "" /* 0xdd */,
    "" /* 0xde */,
    "" /* 0xdf */,
    "" /* 0xe0 */,
    "" /* 0xe1 */,
    "" /* 0xe2 */,
    "" /* 0xe3 */,
    "" /* 0xe4 */,
    "" /* 0xe5 */,
    "" /* 0xe6 */,
    "" /* 0xe7 */,
    "" /* 0xe8 */,
    "" /* 0xe9 */,
    "" /* 0xea */,
    "" /* 0xeb */,
    "" /* 0xec */,
    "" /* 0xed */,
    "" /* 0xee */,
    "" /* 0xef */,
    "" /* 0xf0 */,
    ANSI_COLOR_HRED /* 0xf1 */,
    ANSI_COLOR_HRED /* 0xf2 */,
    ANSI_COLOR_HRED /* 0xf3 */,
    "" /* 0xf4 */,
    ANSI_COLOR_HMAG /* 0xf5 */,
    ANSI_COLOR_HCYN /* 0xf6 */,
    ANSI_COLOR_HBLU /* 0xf7 */,
    ANSI_COLOR_HMAG /* 0xf8 */,
    ANSI_COLOR_HRED /* 0xf9 */,
    ANSI_COLOR_HRED /* 0xfa */,
    ANSI_COLOR_HRED /* 0xfb */,
    ANSI_COLOR_HBLU /* 0xfc */,
    ANSI_COLOR_HMAG /* 0xfd */,
    ANSI_COLOR_HYEL /* 0xfe */,
    ""                                                              /* 0xff */

};

#define _MEM2SHADOW(x) ((uint8_t *)get_shadow_addr(x))

#define _MEM2SHADOWPRINT(x) shadow_color_map[*_MEM2SHADOW(x)], *_MEM2SHADOW(x)

// Reset
#define ANSI_COLOR_RESET "\e[0m"

static int print_shadow_line(target_ulong addr)
{

  qemu_log(
          "  0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
          " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
          " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
          " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
          " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
          " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
          " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
          " "
          "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
          " %s%02x" ANSI_COLOR_RESET "\n",
          (uintptr_t)_MEM2SHADOW(addr), _MEM2SHADOWPRINT(addr),
          _MEM2SHADOWPRINT(addr + 8), _MEM2SHADOWPRINT(addr + 16),
          _MEM2SHADOWPRINT(addr + 24), _MEM2SHADOWPRINT(addr + 32),
          _MEM2SHADOWPRINT(addr + 40), _MEM2SHADOWPRINT(addr + 48),
          _MEM2SHADOWPRINT(addr + 56), _MEM2SHADOWPRINT(addr + 64),
          _MEM2SHADOWPRINT(addr + 72), _MEM2SHADOWPRINT(addr + 80),
          _MEM2SHADOWPRINT(addr + 88), _MEM2SHADOWPRINT(addr + 96),
          _MEM2SHADOWPRINT(addr + 104), _MEM2SHADOWPRINT(addr + 112),
          _MEM2SHADOWPRINT(addr + 120));

  return 1;

}

static int print_shadow_line_fault(target_ulong addr, target_ulong fault_addr)
{

  int         i = (fault_addr - addr) / 8;
  const char* format =
      "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
      " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
      " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
      " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
      " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
      " "
      "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
      " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
      " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
  switch (i) {

    case 0:
      format = "=>0x%012" PRIxPTR ":[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 1:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               "[%s%02x" ANSI_COLOR_RESET "]%s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 2:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 3:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               "[%s%02x" ANSI_COLOR_RESET "]%s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 4:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 5:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               "[%s%02x" ANSI_COLOR_RESET "]%s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 6:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 7:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               "[%s%02x" ANSI_COLOR_RESET "]%s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 8:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 9:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               "[%s%02x" ANSI_COLOR_RESET "]%s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 10:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 11:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 12:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 13:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET
               "]%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 14:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               "[%s%02x" ANSI_COLOR_RESET "]%s%02x" ANSI_COLOR_RESET "\n";
      break;
    case 15:
      format = "=>0x%012" PRIxPTR ": %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET
               " "
               "%s%02x" ANSI_COLOR_RESET " %s%02x" ANSI_COLOR_RESET
               " %s%02x" ANSI_COLOR_RESET "[%s%02x" ANSI_COLOR_RESET "]\n";
      break;

  }

  qemu_log(format, (uintptr_t)_MEM2SHADOW(addr), _MEM2SHADOWPRINT(addr),
          _MEM2SHADOWPRINT(addr + 8), _MEM2SHADOWPRINT(addr + 16),
          _MEM2SHADOWPRINT(addr + 24), _MEM2SHADOWPRINT(addr + 32),
          _MEM2SHADOWPRINT(addr + 40), _MEM2SHADOWPRINT(addr + 48),
          _MEM2SHADOWPRINT(addr + 56), _MEM2SHADOWPRINT(addr + 64),
          _MEM2SHADOWPRINT(addr + 72), _MEM2SHADOWPRINT(addr + 80),
          _MEM2SHADOWPRINT(addr + 88), _MEM2SHADOWPRINT(addr + 96),
          _MEM2SHADOWPRINT(addr + 104), _MEM2SHADOWPRINT(addr + 112),
          _MEM2SHADOWPRINT(addr + 120));

  return 1;

}

#undef _MEM2SHADOW
#undef _MEM2SHADOWPRINT

static void print_shadow(target_ulong addr) {

  target_ulong center = addr & ~127;
  qemu_log("\n----------------- SHADOW MEMORY -----------------\n\n");

  print_shadow_line(center - 16 * 8 * 5);
  print_shadow_line(center - 16 * 8 * 4);
  print_shadow_line(center - 16 * 8 * 3);
  print_shadow_line(center - 16 * 8 * 2);
  print_shadow_line(center - 16 * 8);
  print_shadow_line_fault(center, addr);
  print_shadow_line(center + 16 * 8);
  print_shadow_line(center + 16 * 8 * 2);
  print_shadow_line(center + 16 * 8 * 3);
  print_shadow_line(center + 16 * 8 * 4);
  print_shadow_line(center + 16 * 8 * 5);

}

static const char *get_access_type_string(int access_type)
{
    switch (access_type) {
        case ACCESS_TYPE_LOAD:
            return "read";
        case ACCESS_TYPE_STORE:
            return "write";
        case ACCESS_TYPE_DOUBLE_FREE:
            return "double free";
        default:
            return "";
    }
}

struct allocated_info_search_context {
    vaddr search_addr;
    // AsanAllocatedInfo *search_res;
    bool find_in_use;
};

static void gfunc_print_allocated_chunk(gpointer _not_used, gpointer _allocated_info, gpointer _userdata)
{
    AsanAllocatedInfo *allocated_info = _allocated_info;
    struct allocated_info_search_context *ctx = _userdata;
    vaddr addr = ctx->search_addr;
    AsanThreadInfo *thread_info;
    char *alloc_thread_pname = NULL;
    char *free_thread_pname = NULL;

    // qemu_log("ptr: %#018lx size: %ld\n", allocated_info->asan_chunk_start, allocated_info->chunk_size);

    // if (ctx->search_res)
    //     return;

    if (!(addr >= allocated_info->asan_chunk_start &&
        addr < allocated_info->asan_chunk_start + allocated_info->chunk_size)) {

        return;
    }

    if (ctx->find_in_use ^ allocated_info->in_use)
        return;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo, thread_info_hash_key(allocated_info->pid, current_cpu->cpu_index));
    if (thread_info)
        alloc_thread_pname = thread_info->process_name;
    if (!ctx->find_in_use) {
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo, thread_info_hash_key(allocated_info->free_pid, current_cpu->cpu_index));
    if (thread_info)
        free_thread_pname = thread_info->process_name;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    qemu_log("\tchunk at %#018lx, size: %ld\n", allocated_info->asan_chunk_start, allocated_info->request_size);
    qemu_log("\tallocated by thread %d (%s) at %#018lx\n", allocated_info->pid, alloc_thread_pname, allocated_info->allocated_at);
    if (!ctx->find_in_use)
        qemu_log("\tfree by thread %d (%s) at %#018lx\n", allocated_info->free_pid, free_thread_pname, allocated_info->free_at);
}

static void print_allocated_info(vaddr addr, bool find_in_use)
{
    struct allocated_info_search_context ctx = {
        .search_addr = addr,
        // .search_res = NULL,
        .find_in_use = find_in_use,
    };

    qemu_spin_lock(&asan_state->asan_allocated_info_lock);
    g_hash_table_foreach(asan_state->asan_allocated_info, gfunc_print_allocated_chunk, &ctx);
    qemu_spin_unlock(&asan_state->asan_allocated_info_lock);
}

static void trigger_cpu_crash_by_ud(CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;
    vaddr pc = kreit_get_pc(env);

    for (int i = 0; i < 16; i++) {
        kreit_cpu_stq(cpu, pc + i * 8, 0x9090909090909090);
    }
    kreit_cpu_stq(cpu, pc + 8 * 16, 0x9090909090900b0f);
}

static void print_cpu_basic_info(int cpu_index)
{
    int pid = kcont.percpu_data[cpu_index].current_pid;
    const char *pname = kcont.percpu_data[cpu_index].current_thread_name;

    qemu_log("[CPU %d] (pid: %d thread name: %s)\n", cpu_index, pid, pname);
}

static void print_crash_stack(void)
{
    CPUState *cpu;
    CPUArchState *env;
    vaddr sp;

    qemu_log("\n----------------- CRASH STACK -----------------\n\n");

    CPU_FOREACH(cpu) {
        env = cpu->env_ptr;
        sp = kreit_get_stack_ptr(env);

        print_cpu_basic_info(cpu->cpu_index);

        for (int i = 0; i < 8; i++) {
            // line
            qemu_log("%04x: ", 0x20 * i);
            for (int j = 0; j < 4; j++) {
                // column
                qemu_log("%016lx ", kreit_cpu_ldq(cpu, sp + 0x20 * i + 8 * j));
            }
            qemu_log("\n");
        }
        qemu_log("\n");
    }
}

static void print_all_cpu_state(void)
{
    CPUState *cpu;

    qemu_log("\n----------------- CPU STATE -----------------\n\n");

    CPU_FOREACH(cpu) {
        print_cpu_basic_info(cpu->cpu_index);
        log_cpu_state(CPU(cpu), CPU_DUMP_CCOP);
        qemu_log("\n");
    }

}

int asan_giovese_report_and_crash(int access_type, vaddr addr, size_t n,
                                  CPUArchState *env)
{
    vaddr fault_addr = 0;
    const char* error_type;
    vaddr curr_pc = kreit_get_pc(env);
    int pid = *curr_cpu_data(current_pid);
    AsanThreadInfo *thread_info;
    char *thread_pname = NULL;

    // tmp hack for qnx srealloc
    if (curr_pc >= 0xffff800000077e40 && curr_pc < 0xffff800000078e40)
        return 0;

    if (!poisoned_find_error(addr, n, &fault_addr, &error_type))
        return 0;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo, thread_info_hash_key(pid, current_cpu->cpu_index));
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
    if (thread_info)
        thread_pname = thread_info->process_name;

    qemu_log("QKASAN: %s in %#018lx\n",error_type, curr_pc);
    qemu_log("\tcpu %d pid: %d (%s)\n", current_cpu->cpu_index, pid, thread_pname);
    qemu_log("\ttry to %s on address %#018lx, size %ld\n", get_access_type_string(access_type), addr, n);

    // if ((access_type == ACCESS_TYPE_DOUBLE_FREE) || !strcmp("heap-use-after-free", error_type))
    //     print_allocated_info(addr, false);
    // else
    //     print_allocated_info(addr, true);

    qemu_log("\tfreed chunk info:\n");
    print_allocated_info(addr, false);
    qemu_log("\tin used chunk info:\n");
    print_allocated_info(addr, true);

    print_shadow(fault_addr);
    print_crash_stack();

    print_all_cpu_state();

    g_assert(0);
    return -1;
}

int asan_giovese_load1(vaddr ptr)
{
    int8_t* shadow_addr;
    int8_t k;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    k = *shadow_addr;
    return k != 0 && (intptr_t)((ptr & 7) + 1) > k;
}

int asan_giovese_load2(vaddr ptr)
{
    int8_t* shadow_addr;
    int8_t k;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    k = *shadow_addr;
    return k != 0 && (intptr_t)((ptr & 7) + 2) > k;
}

int asan_giovese_load4(vaddr ptr)
{
    int8_t* shadow_addr;
    int8_t k;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    k = *shadow_addr;
    return k != 0 && (intptr_t)((ptr & 7) + 4) > k;
}

int asan_giovese_load8(vaddr ptr)
{
    int8_t* shadow_addr;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    return (*shadow_addr);
}

int asan_giovese_load16(vaddr ptr)
{
    int8_t* shadow_addr;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    return (*shadow_addr) || (*(shadow_addr + 1));
}

int asan_giovese_store1(vaddr ptr)
{
    int8_t* shadow_addr;
    int8_t k;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    k = *shadow_addr;
    return k != 0 && (intptr_t)((ptr & 7) + 1) > k;
}

int asan_giovese_store2(vaddr ptr)
{
    int8_t* shadow_addr;
    int8_t k;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    k = *shadow_addr;
    return k != 0 && (intptr_t)((ptr & 7) + 2) > k;
}

int asan_giovese_store4(vaddr ptr)
{
    int8_t* shadow_addr;
    int8_t k;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    k = *shadow_addr;
    return k != 0 && (intptr_t)((ptr & 7) + 4) > k;
}

int asan_giovese_store8(vaddr ptr)
{
    int8_t* shadow_addr;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    return (*shadow_addr);
}

int asan_giovese_store16(vaddr ptr)
{
    int8_t* shadow_addr;
    AsanThreadInfo *thread_info;

    qemu_spin_lock(&asan_state->asan_threadinfo_lock);
    thread_info = g_hash_table_lookup(asan_state->asan_threadinfo,
        thread_info_hash_key(*curr_cpu_data(current_pid), current_cpu->cpu_index));
    if (!thread_info || !thread_info->asan_enabled) {
        qemu_spin_unlock(&asan_state->asan_threadinfo_lock);
        return 0;
    }
    qemu_spin_unlock(&asan_state->asan_threadinfo_lock);

    shadow_addr = get_shadow_addr(ptr);
    return (*shadow_addr) || (*(shadow_addr + 1));
}
