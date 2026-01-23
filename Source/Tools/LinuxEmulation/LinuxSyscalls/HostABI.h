// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <cstring>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <pthread.h>
#include <sys/time.h>
#include <sys/wait.h>
#else
#include <syscall.h>
#endif

namespace FEX::HLE {
// kernel_sigaction structure - matches Linux kernel structure
// Defined here to avoid circular dependencies with SignalDelegator.h
struct kernel_sigaction {
  union {
    void (*handler)(int);
    void (*sigaction)(int, siginfo_t*, void*);
  };

  uint64_t sa_flags;

  void (*restorer)();
  uint64_t sa_mask;
};
} // namespace FEX::HLE

namespace FEX::HLE::HostABI {

#if defined(__APPLE__)

// Convert kernel_sigaction to native sigaction for macOS
inline int rt_sigaction(int signum, const FEX::HLE::kernel_sigaction* act, FEX::HLE::kernel_sigaction* oldact) {
  struct sigaction native_act;
  struct sigaction native_oldact;
  struct sigaction* act_ptr = nullptr;
  struct sigaction* oldact_ptr = nullptr;

  if (act) {
    memset(&native_act, 0, sizeof(native_act));
    native_act.sa_sigaction = act->sigaction;
    native_act.sa_flags = static_cast<int>(act->sa_flags);
    // Convert sa_mask from uint64_t to sigset_t
    sigemptyset(&native_act.sa_mask);
    for (int i = 1; i <= 31; ++i) {
      if (act->sa_mask & (1ULL << (i - 1))) {
        sigaddset(&native_act.sa_mask, i);
      }
    }
    act_ptr = &native_act;
  }

  if (oldact) {
    oldact_ptr = &native_oldact;
  }

  int result = sigaction(signum, act_ptr, oldact_ptr);

  if (result == 0 && oldact) {
    oldact->sigaction = native_oldact.sa_sigaction;
    oldact->sa_flags = native_oldact.sa_flags;
    oldact->restorer = nullptr;
    oldact->sa_mask = 0;
    for (int i = 1; i <= 31; ++i) {
      if (sigismember(&native_oldact.sa_mask, i)) {
        oldact->sa_mask |= (1ULL << (i - 1));
      }
    }
  }

  return result;
}

inline int rt_sigprocmask(int how, const uint64_t* set, uint64_t* oldset, size_t sigsetsize) {
  (void)sigsetsize;
  sigset_t newset, old;
  sigemptyset(&newset);
  sigemptyset(&old);

  if (set) {
    for (int i = 1; i <= 31; ++i) {
      if (*set & (1ULL << (i - 1))) {
        sigaddset(&newset, i);
      }
    }
  }

  int result;
  if (set) {
    result = pthread_sigmask(how, &newset, oldset ? &old : nullptr);
  } else {
    result = pthread_sigmask(how, nullptr, &old);
  }

  if (oldset && result == 0) {
    *oldset = 0;
    for (int i = 1; i <= 31; ++i) {
      if (sigismember(&old, i)) {
        *oldset |= (1ULL << (i - 1));
      }
    }
  }

  return result == 0 ? 0 : -1;
}

inline int rt_sigtimedwait(const uint64_t* set, siginfo_t* info, const struct timespec* timeout) {
  sigset_t sigset;
  sigemptyset(&sigset);
  for (int i = 1; i <= 31; ++i) {
    if (*set & (1ULL << (i - 1))) {
      sigaddset(&sigset, i);
    }
  }

  // macOS doesn't have sigtimedwait/sigwaitinfo
  // Use sigwait instead (which doesn't support timeout or return siginfo)
  int sig = 0;
  int result = sigwait(&sigset, &sig);
  if (result == 0) {
    if (info) {
      memset(info, 0, sizeof(siginfo_t));
      info->si_signo = sig;
    }
    return sig;
  }
  return -1;
}

inline int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t* info) {
  (void)tgid;
  (void)tid;
  (void)info;
  // macOS doesn't have rt_tgsigqueueinfo - use pthread_kill for the current thread
  // For other threads, this would need a thread registry to map tid to pthread_t
  if (tid == getpid()) {
    return kill(tid, sig);
  }
  // TODO: Implement proper thread signal queuing with thread registry
  return kill(tid, sig);
}

inline int execveat(int dirfd, const char* pathname, char* const argv[], char* const envp[], int flags) {
  (void)flags;
  // AT_FDCWD is -100 on Linux
  if (dirfd == -100) {
    return execve(pathname, argv, envp);
  }
  // macOS doesn't have execveat with dirfd support
  // TODO: Implement using fchdir + execve for other cases
  return -1;
}

inline int faccessat(int dirfd, const char* pathname, int mode) {
  return ::faccessat(dirfd, pathname, mode, 0);
}

#else

inline int rt_sigaction(int signum, const FEX::HLE::kernel_sigaction* act, FEX::HLE::kernel_sigaction* oldact) {
  return ::syscall(SYS_rt_sigaction, signum, act, oldact, 8);
}

inline int rt_sigprocmask(int how, const uint64_t* set, uint64_t* oldset, size_t sigsetsize) {
  return ::syscall(SYS_rt_sigprocmask, how, set, oldset, sigsetsize);
}

inline int rt_sigtimedwait(const uint64_t* set, siginfo_t* info, const struct timespec* timeout) {
  return ::syscall(SYS_rt_sigtimedwait, set, info, timeout);
}

inline int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t* info) {
  return ::syscall(SYS_rt_tgsigqueueinfo, tgid, tid, sig, info);
}

inline int execveat(int dirfd, const char* pathname, char* const argv[], char* const envp[], int flags) {
  return ::syscall(SYS_execveat, dirfd, pathname, argv, envp, flags);
}

inline int faccessat(int dirfd, const char* pathname, int mode) {
  return ::syscall(SYS_faccessat, dirfd, pathname, mode);
}

#endif

} // namespace FEX::HLE::HostABI

