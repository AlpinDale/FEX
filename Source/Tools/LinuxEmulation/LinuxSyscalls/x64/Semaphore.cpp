// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-x86-64
$end_info$
*/

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x64/Types.h"

#include <FEXHeaderUtils/Syscalls.h>

#ifdef __APPLE__
#include "LinuxSyscalls/LinuxCompat.h"
// On macOS, sys/sem.h defines IPC commands with different values than Linux.
// We need to use Linux values for proper emulation.
// Linux IPC/semctl commands (from linux/sem.h)
#define FEX_IPC_RMID 0
#define FEX_IPC_SET 1
#define FEX_IPC_STAT 2
#define FEX_IPC_INFO 3
#define FEX_SEM_STAT 18
#define FEX_SEM_INFO 19
#define FEX_SEM_STAT_ANY 20
#define FEX_GETALL 13
#define FEX_SETALL 17
#define FEX_SETVAL 16
#define FEX_GETVAL 12
#define FEX_GETPID 11
#define FEX_GETNCNT 14
#define FEX_GETZCNT 15
// Map to FEX_ names
#undef IPC_RMID
#undef IPC_SET
#undef IPC_STAT
#undef IPC_INFO
#define IPC_RMID FEX_IPC_RMID
#define IPC_SET FEX_IPC_SET
#define IPC_STAT FEX_IPC_STAT
#define IPC_INFO FEX_IPC_INFO
#define SEM_STAT FEX_SEM_STAT
#define SEM_INFO FEX_SEM_INFO
#define SEM_STAT_ANY FEX_SEM_STAT_ANY
#define GETALL FEX_GETALL
#define SETALL FEX_SETALL
#define SETVAL FEX_SETVAL
#define GETVAL FEX_GETVAL
#define GETPID FEX_GETPID
#define GETNCNT FEX_GETNCNT
#define GETZCNT FEX_GETZCNT
#else
#include <linux/sem.h>
#endif
#include <stddef.h>
#include <stdint.h>

namespace FEXCore::Core {
struct CpuStateFrame;
}

ARG_TO_STR(FEX::HLE::x64::semun, "%lx")

namespace FEX::HLE::x64 {
void RegisterSemaphore(FEX::HLE::SyscallHandler* Handler) {
  REGISTER_SYSCALL_IMPL_X64(semctl, [](FEXCore::Core::CpuStateFrame* Frame, int semid, int semnum, int cmd, FEX::HLE::x64::semun semun) -> uint64_t {
    uint64_t Result {};
    switch (cmd) {
    case IPC_SET: {
      struct semid64_ds buf {};
      FaultSafeUserMemAccess::VerifyIsReadable(semun.buf, sizeof(*semun.buf));
      buf = *semun.buf;
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, &buf);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(semun.buf, sizeof(*semun.buf));
        *semun.buf = buf;
      }
      break;
    }
    case SEM_STAT:
    case SEM_STAT_ANY:
    case IPC_STAT: {
      struct semid64_ds buf {};
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, &buf);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(semun.buf, sizeof(*semun.buf));
        *semun.buf = buf;
      }
      break;
    }
    case SEM_INFO:
    case IPC_INFO: {
      struct fex_seminfo si {};
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, &si);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(semun.__buf, sizeof(si));
        memcpy(semun.__buf, &si, sizeof(si));
      }
      break;
    }
    case GETALL:
    case SETALL: {
      // ptr is just a int32_t* in this case
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, semun.array);
      break;
    }
    case SETVAL: {
      // ptr is just a int32_t in this case
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, semun.val);
      break;
    }
    case IPC_RMID:
    case GETPID:
    case GETNCNT:
    case GETZCNT:
    case GETVAL: Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, semun); break;
    default: LOGMAN_MSG_A_FMT("Unhandled semctl cmd: {}", cmd); return -EINVAL;
    }
    SYSCALL_ERRNO();
  });
}
} // namespace FEX::HLE::x64
