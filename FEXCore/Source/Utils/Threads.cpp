// SPDX-License-Identifier: MIT
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/fextl/memory.h>

#include <pthread.h>
#include <unistd.h>
#ifndef _WIN32
#include <signal.h>
#include <sys/signal.h>
#ifndef __APPLE__
#include <sys/syscall.h>
#endif
#endif

namespace FEXCore::Threads {
static fextl::unique_ptr<FEXCore::Threads::Thread> CreateThread_Default(ThreadFunc Func, void* Arg) {
  ERROR_AND_DIE_FMT("Frontend didn't setup thread creation!");
}

static void CleanupAfterFork_Default() {
  ERROR_AND_DIE_FMT("Frontend didn't setup thread creation!");
}

static FEXCore::Threads::Pointers Ptrs = {
  .CreateThread = CreateThread_Default,
  .CleanupAfterFork = CleanupAfterFork_Default,
};

fextl::unique_ptr<FEXCore::Threads::Thread> FEXCore::Threads::Thread::Create(ThreadFunc Func, void* Arg) {
  return Ptrs.CreateThread(Func, Arg);
}

void FEXCore::Threads::Thread::CleanupAfterFork() {
  return Ptrs.CleanupAfterFork();
}

void FEXCore::Threads::Thread::SetInternalPointers(const Pointers& _Ptrs) {
  Ptrs = _Ptrs;
}

uint64_t SetSignalMask(uint64_t Mask) {
#if defined(_WIN32)
  return 0;
#elif defined(__APPLE__)
  sigset_t NewMask, OldMask;
  sigemptyset(&NewMask);
  // Convert the 64-bit mask to sigset_t
  for (int i = 1; i < 64; ++i) {
    if (Mask & (1ULL << i)) {
      sigaddset(&NewMask, i);
    }
  }
  ::sigprocmask(SIG_SETMASK, &NewMask, &OldMask);
  // Convert OldMask back to uint64_t
  uint64_t Result = 0;
  for (int i = 1; i < 64; ++i) {
    if (sigismember(&OldMask, i)) {
      Result |= (1ULL << i);
    }
  }
  return Result;
#else
  ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &Mask, &Mask, 8);
  return Mask;
#endif
}

void SetThreadName(const char* name) {
#if defined(_WIN32)
  // TODO:
#elif defined(__APPLE__)
  pthread_setname_np(name);
#else
  pthread_setname_np(pthread_self(), name);
#endif
}
} // namespace FEXCore::Threads
