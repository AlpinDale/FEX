// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <cstddef>

#if defined(__APPLE__)
#define FEX_HOST_DARWIN 1
#define FEX_HOST_LINUX 0
#elif defined(__linux__)
#define FEX_HOST_DARWIN 0
#define FEX_HOST_LINUX 1
#elif defined(_WIN32)
#define FEX_HOST_DARWIN 0
#define FEX_HOST_LINUX 0
#else
#error "Unsupported host platform"
#endif

#if defined(__APPLE__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <TargetConditionals.h>

#define AT_NULL         0
#define AT_IGNORE       1
#define AT_EXECFD       2
#define AT_PHDR         3
#define AT_PHENT        4
#define AT_PHNUM        5
#define AT_PAGESZ       6
#define AT_BASE         7
#define AT_FLAGS        8
#define AT_ENTRY        9
#define AT_NOTELF       10
#define AT_UID          11
#define AT_EUID         12
#define AT_GID          13
#define AT_EGID         14
#define AT_CLKTCK       17
#define AT_PLATFORM     24
#define AT_HWCAP        16
#define AT_FPUCW        18
#define AT_DCACHEBSIZE  19
#define AT_ICACHEBSIZE  20
#define AT_UCACHEBSIZE  21
#define AT_SECURE       23
#define AT_RANDOM       25
#define AT_HWCAP2       26
#define AT_EXECFN       31
#define AT_SYSINFO      32
#define AT_SYSINFO_EHDR 33
#define AT_MINSIGSTKSZ  51
#define AT_FLAGS_PRESERVE_ARGV0 1

#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_GROWSDOWN 0x0100
#define MAP_DENYWRITE 0x0800
// MAP_NORESERVE may already be defined on macOS - use Linux value for guest emulation
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0x4000
#endif
#define MAP_STACK 0x20000

#define PER_LINUX 0x0000
#define READ_IMPLIES_EXEC 0x0400000
#define ADDR_NO_RANDOMIZE 0x0040000

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
#ifndef PR_GET_MEM_MODEL
#define PR_GET_MEM_MODEL 0x6d4d444c
#endif
#ifndef PR_SET_MEM_MODEL
#define PR_SET_MEM_MODEL 0x4d4d444c
#endif
#ifndef PR_SET_MEM_MODEL_DEFAULT
#define PR_SET_MEM_MODEL_DEFAULT 0
#endif
#ifndef PR_SET_MEM_MODEL_TSO
#define PR_SET_MEM_MODEL_TSO 1
#endif
#ifndef PR_GET_COMPAT_INPUT
#define PR_GET_COMPAT_INPUT 0x63494e50
#endif
#ifndef PR_SET_COMPAT_INPUT
#define PR_SET_COMPAT_INPUT 0x43494e50
#endif
#ifndef PR_SET_COMPAT_INPUT_DISABLE
#define PR_SET_COMPAT_INPUT_DISABLE 0
#endif
#ifndef PR_SET_COMPAT_INPUT_ENABLE
#define PR_SET_COMPAT_INPUT_ENABLE 1
#endif
#ifndef PR_GET_SHADOW_STACK_STATUS
#define PR_GET_SHADOW_STACK_STATUS 74
#endif
#ifndef PR_LOCK_SHADOW_STACK_STATUS
#define PR_LOCK_SHADOW_STACK_STATUS 76
#endif
#ifndef PR_SHADOW_STACK_ENABLE
#define PR_SHADOW_STACK_ENABLE (1ULL << 0)
#endif
#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_MAP
#define PR_SET_MM_MAP 14
#endif

struct prctl_mm_map {
  uint64_t start_code;
  uint64_t end_code;
  uint64_t start_data;
  uint64_t end_data;
  uint64_t start_brk;
  uint64_t brk;
  uint64_t start_stack;
  uint64_t arg_start;
  uint64_t arg_end;
  uint64_t env_start;
  uint64_t env_end;
  uint64_t* auxv;
  uint32_t auxv_size;
  uint32_t exe_fd;
};

namespace FHU::Platform {

inline uint64_t getauxval(unsigned long type) {
  switch (type) {
    case AT_EXECFD: return 0;
    case AT_UID: return getuid();
    case AT_EUID: return geteuid();
    case AT_GID: return getgid();
    case AT_EGID: return getegid();
    case AT_CLKTCK: return sysconf(_SC_CLK_TCK);
    case AT_PAGESZ: return sysconf(_SC_PAGESIZE);
    case AT_SECURE: return issetugid();
    case AT_RANDOM: return 0;
    case AT_HWCAP: return 0;
    case AT_HWCAP2: return 0;
    case AT_FLAGS: return 0;
    default: return 0;
  }
}

inline int prctl(int option, unsigned long arg2 = 0, unsigned long arg3 = 0,
                 unsigned long arg4 = 0, unsigned long arg5 = 0) {
  switch (option) {
    case PR_SET_VMA:
    case PR_GET_MEM_MODEL:
    case PR_SET_MEM_MODEL:
    case PR_GET_COMPAT_INPUT:
    case PR_SET_COMPAT_INPUT:
    case PR_GET_SHADOW_STACK_STATUS:
    case PR_LOCK_SHADOW_STACK_STATUS:
    case PR_SET_MM:
      return -1;
    default:
      return -1;
  }
}

inline int personality(unsigned long persona) {
  (void)persona;
  return 0;
}

struct sysinfo {
  long uptime;
  unsigned long loads[3];
  unsigned long totalram;
  unsigned long freeram;
  unsigned long sharedram;
  unsigned long bufferram;
  unsigned long totalswap;
  unsigned long freeswap;
  unsigned short procs;
  unsigned short pad;
  unsigned long totalhigh;
  unsigned long freehigh;
  unsigned int mem_unit;
  char _f[20 - 2 * sizeof(unsigned long) - sizeof(unsigned int)];
};

inline int get_sysinfo(struct sysinfo* info) {
  if (!info) return -1;

  memset(info, 0, sizeof(*info));

  struct timeval boottime;
  size_t len = sizeof(boottime);
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};
  if (sysctl(mib, 2, &boottime, &len, nullptr, 0) == 0) {
    struct timeval now;
    gettimeofday(&now, nullptr);
    info->uptime = now.tv_sec - boottime.tv_sec;
  }

  int64_t physmem;
  len = sizeof(physmem);
  if (sysctlbyname("hw.memsize", &physmem, &len, nullptr, 0) == 0) {
    info->totalram = physmem;
  }

  vm_size_t pagesize;
  mach_port_t mach_port = mach_host_self();
  vm_statistics64_data_t vm_stats;
  mach_msg_type_number_t count = sizeof(vm_stats) / sizeof(natural_t);
  host_page_size(mach_port, &pagesize);

  if (host_statistics64(mach_port, HOST_VM_INFO64, (host_info64_t)&vm_stats, &count) == KERN_SUCCESS) {
    info->freeram = (uint64_t)vm_stats.free_count * pagesize;
  }

  info->mem_unit = 1;
  return 0;
}

inline void* sbrk(intptr_t increment) {
  (void)increment;
  return (void*)-1;
}

} // namespace FHU::Platform

#else

#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <sys/sysinfo.h>
#include <unistd.h>

namespace FHU::Platform {

inline uint64_t getauxval(unsigned long type) {
  return ::getauxval(type);
}

inline int prctl(int option, unsigned long arg2 = 0, unsigned long arg3 = 0,
                 unsigned long arg4 = 0, unsigned long arg5 = 0) {
  return ::prctl(option, arg2, arg3, arg4, arg5);
}

inline int personality(unsigned long persona) {
  return ::personality(persona);
}

inline int get_sysinfo(struct sysinfo* info) {
  return ::sysinfo(info);
}

inline void* sbrk(intptr_t increment) {
  return ::sbrk(increment);
}

} // namespace FHU::Platform

#endif // __APPLE__

