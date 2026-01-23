// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"

#include <FEXCore/IR/IR.h>

#include <FEXHeaderUtils/Syscalls.h>

#include <fcntl.h>
#include <stdint.h>
#include <sys/file.h>
#ifdef __APPLE__
#include "LinuxSyscalls/LinuxCompat.h"
// eventfd stub for macOS
#define EFD_CLOEXEC O_CLOEXEC
#define EFD_NONBLOCK O_NONBLOCK
#define EFD_SEMAPHORE 1
// inotify stubs for macOS
#define IN_ACCESS 0x00000001
#define IN_MODIFY 0x00000002
#define IN_ATTRIB 0x00000004
#define IN_CLOSE_WRITE 0x00000008
#define IN_CLOSE_NOWRITE 0x00000010
#define IN_OPEN 0x00000020
#define IN_MOVED_FROM 0x00000040
#define IN_MOVED_TO 0x00000080
#define IN_CREATE 0x00000100
#define IN_DELETE 0x00000200
#define IN_DELETE_SELF 0x00000400
#define IN_MOVE_SELF 0x00000800
#define IN_CLOEXEC O_CLOEXEC
#define IN_NONBLOCK O_NONBLOCK
static inline int inotify_init(void) {
  errno = ENOSYS;
  return -1;
}
static inline int inotify_init1(int flags) {
  (void)flags;
  errno = ENOSYS;
  return -1;
}
static inline int inotify_add_watch(int fd, const char* pathname, uint32_t mask) {
  (void)fd;
  (void)pathname;
  (void)mask;
  errno = ENOSYS;
  return -1;
}
static inline int inotify_rm_watch(int fd, int wd) {
  (void)fd;
  (void)wd;
  errno = ENOSYS;
  return -1;
}
#else
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/timerfd.h>
#endif
#include <sys/mman.h>
#ifndef __APPLE__
#include <sys/timerfd.h>
#endif
#include <poll.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>

namespace FEX::HLE {
void RegisterFD(FEX::HLE::SyscallHandler* Handler) {
  using namespace FEXCore::IR;
  REGISTER_SYSCALL_IMPL(poll, [](FEXCore::Core::CpuStateFrame* Frame, struct pollfd* fds, nfds_t nfds, int timeout) -> uint64_t {
    if (nfds) {
      // fds is allowed to be garbage if nfds is zero.
      FaultSafeUserMemAccess::VerifyIsWritable(fds, sizeof(struct pollfd) * nfds);
    }
    uint64_t Result = ::poll(fds, nfds, timeout);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(open, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, int flags, uint32_t mode) -> uint64_t {
    flags = FEX::HLE::RemapFromX86Flags(flags);
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Open(pathname, flags, mode);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(close, [](FEXCore::Core::CpuStateFrame* Frame, int fd) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Close(fd);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(chown, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, uid_t owner, gid_t group) -> uint64_t {
    uint64_t Result = ::chown(pathname, owner, group);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(lchown, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, uid_t owner, gid_t group) -> uint64_t {
    uint64_t Result = ::lchown(pathname, owner, group);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(access, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, int mode) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Access(pathname, mode);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(pipe, [](FEXCore::Core::CpuStateFrame* Frame, int pipefd[2]) -> uint64_t {
    uint64_t Result = ::pipe(pipefd);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(dup3, [](FEXCore::Core::CpuStateFrame* Frame, int oldfd, int newfd, int flags) -> uint64_t {
    flags = FEX::HLE::RemapFromX86Flags(flags);
    uint64_t Result = ::dup3(oldfd, newfd, flags);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(inotify_init, [](FEXCore::Core::CpuStateFrame* Frame) -> uint64_t {
    uint64_t Result = ::inotify_init();
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(openat, [](FEXCore::Core::CpuStateFrame* Frame, int dirfs, const char* pathname, int flags, uint32_t mode) -> uint64_t {
    flags = FEX::HLE::RemapFromX86Flags(flags);
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Openat(dirfs, pathname, flags, mode);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(readlinkat, [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, char* buf, size_t bufsiz) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Readlinkat(dirfd, pathname, buf, bufsiz);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(faccessat, [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, int mode) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.FAccessat(dirfd, pathname, mode);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(faccessat2, [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, int mode, int flags) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.FAccessat2(dirfd, pathname, mode, flags);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(
    openat2, [](FEXCore::Core::CpuStateFrame* Frame, int dirfs, const char* pathname, struct open_how* how, size_t usize) -> uint64_t {
      open_how HostHow {};
      size_t HostSize = std::min(sizeof(open_how), usize);
      memcpy(&HostHow, how, HostSize);

      HostHow.flags = FEX::HLE::RemapFromX86Flags(HostHow.flags);
      uint64_t Result = FEX::HLE::_SyscallHandler->FM.Openat2(dirfs, pathname, &HostHow, HostSize);
      SYSCALL_ERRNO();
    });

  REGISTER_SYSCALL_IMPL(eventfd, [](FEXCore::Core::CpuStateFrame* Frame, uint32_t count) -> uint64_t {
    uint64_t Result = ::syscall(SYSCALL_DEF(eventfd2), count, 0);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(pipe2, [](FEXCore::Core::CpuStateFrame* Frame, int pipefd[2], int flags) -> uint64_t {
    flags = FEX::HLE::RemapFromX86Flags(flags);
    uint64_t Result = ::pipe2(pipefd, flags);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(
    statx, [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, int flags, uint32_t mask, struct statx* statxbuf) -> uint64_t {
      // Flags don't need remapped
      uint64_t Result = FEX::HLE::_SyscallHandler->FM.Statx(dirfd, pathname, flags, mask, statxbuf);
      SYSCALL_ERRNO();
    });

  REGISTER_SYSCALL_IMPL(close_range, [](FEXCore::Core::CpuStateFrame* Frame, unsigned int first, unsigned int last, unsigned int flags) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.CloseRange(first, last, flags);
    SYSCALL_ERRNO();
  });
}
} // namespace FEX::HLE
