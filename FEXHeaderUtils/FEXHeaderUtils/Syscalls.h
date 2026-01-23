// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/LogManager.h>

#include <cstdint>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#ifndef _WIN32
#ifdef __APPLE__
#include <sys/syscall.h>
#include <pthread.h>
#else
#include <syscall.h>
#endif
#else
#include <processthreadsapi.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

namespace FHU::Syscalls {
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#ifndef SEM_STAT_ANY
#define SEM_STAT_ANY 20
#endif

#ifndef SHM_STAT_ANY
#define SHM_STAT_ANY 15
#endif

#ifndef MSG_STAT_ANY
#define MSG_STAT_ANY 13
#endif

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#ifndef SYS_statx
#define SYS_statx 291
#endif
#elif defined(__x86_64__) || defined(_M_X64)
#ifndef SYS_statx
#define SYS_statx 332
#endif
#endif

// Common syscall numbers
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

#ifdef __APPLE__
// macOS implementations
inline int32_t getcpu(uint32_t* cpu, uint32_t* node) {
  // macOS doesn't have getcpu, but we can get current CPU with undocumented API
  // or just return 0 for simplicity
  if (cpu) {
    *cpu = 0; // TODO(alpin): could use _os_cpu_number() if available
  }
  if (node) {
    *node = 0;
  }
  return 0;
}

inline int32_t gettid() {
  uint64_t tid;
  pthread_threadid_np(nullptr, &tid);
  return static_cast<int32_t>(tid);
}

inline int32_t tgkill(pid_t tgid, pid_t tid, int sig) {
  // macOS doesn't have tgkill, use pthread_kill if same process
  if (tgid == getpid()) {
    // We can't directly signal a thread by tid on macOS
    // Fall back to kill for same process
    return kill(tgid, sig);
  }
  return kill(tgid, sig);
}

inline int32_t statx(int dirfd, const char* pathname, int32_t flags, uint32_t mask, void* statxbuf) {
  // macOS doesn't have statx, would need to emulate with fstatat
  // For now, return error
  errno = ENOSYS;
  return -1;
}

inline int32_t renameat2(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags) {
  // macOS doesn't have renameat2, use renameat if no special flags
  if (flags == 0) {
    return renameat(olddirfd, oldpath, newdirfd, newpath);
  }
  // Flags not supported on macOS
  errno = EINVAL;
  return -1;
}

inline int32_t pidfd_open(pid_t pid, unsigned int flags) {
  // macOS doesn't have pidfd
  errno = ENOSYS;
  return -1;
}

#elif !defined(_WIN32)
// Linux implementations
inline int32_t getcpu(uint32_t* cpu, uint32_t* node) {
  // Third argument is unused
#if defined(HAS_SYSCALL_GETCPU) && HAS_SYSCALL_GETCPU
  return ::getcpu(cpu, node);
#else
  return ::syscall(SYS_getcpu, cpu, node, nullptr);
#endif
}

inline int32_t gettid() {
#if defined(HAS_SYSCALL_GETTID) && HAS_SYSCALL_GETTID
  return ::gettid();
#else
  return ::syscall(SYS_gettid);
#endif
}

inline int32_t tgkill(pid_t tgid, pid_t tid, int sig) {
#if defined(HAS_SYSCALL_TGKILL) && HAS_SYSCALL_TGKILL
  return ::tgkill(tgid, tid, sig);
#else
  return ::syscall(SYS_tgkill, tgid, tid, sig);
#endif
}

inline int32_t statx(int dirfd, const char* pathname, int32_t flags, uint32_t mask, void* statxbuf) {
#if defined(HAS_SYSCALL_STATX) && HAS_SYSCALL_STATX
  return ::statx(dirfd, pathname, flags, mask, reinterpret_cast<struct statx* __restrict>(statxbuf));
#else
  return ::syscall(SYS_statx, dirfd, pathname, flags, mask, statxbuf);
#endif
}

inline int32_t renameat2(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags) {
#if defined(HAS_SYSCALL_RENAMEAT2) && HAS_SYSCALL_RENAMEAT2
  return ::renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
#else
  return ::syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
#endif
}

inline int32_t pidfd_open(pid_t pid, unsigned int flags) {
  return ::syscall(SYS_pidfd_open, pid, flags);
}
#else

inline int32_t getcpu(uint32_t* cpu, uint32_t* node) {
  if (cpu) {
    *cpu = GetCurrentProcessorNumber();
  }
  if (node) {
    *node = 0;
  }
  return 0;
}

inline int32_t tgkill(pid_t tgid, pid_t tid, int sig) {
  ERROR_AND_DIE_FMT("Unsupported");
  return 0;
}

inline int32_t gettid() {
  return GetCurrentThreadId();
}

#endif

} // namespace FHU::Syscalls
