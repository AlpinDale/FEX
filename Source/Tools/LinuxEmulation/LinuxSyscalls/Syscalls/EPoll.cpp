// SPDX-License-Identifier: MIT
/*
$info$
meta: LinuxSyscalls|syscalls-shared ~ Syscall implementations shared between x86 and x86-64
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"

#include <FEXCore/IR/IR.h>

#include <stdint.h>
#ifdef __APPLE__
#include "LinuxSyscalls/LinuxCompat.h"
static inline int epoll_create(int size) {
  (void)size;
  // On macOS we'd need to use kqueue for real implementation
  // For now, return error as this needs proper kqueue-based emulation
  errno = ENOSYS;
  return -1;
}
#else
#include <sys/epoll.h>
#endif

namespace FEX::HLE {
void RegisterEpoll(FEX::HLE::SyscallHandler* Handler) {
  using namespace FEXCore::IR;

  REGISTER_SYSCALL_IMPL(epoll_create, [](FEXCore::Core::CpuStateFrame* Frame, int size) -> uint64_t {
    uint64_t Result = epoll_create(size);
    SYSCALL_ERRNO();
  });
}
} // namespace FEX::HLE
