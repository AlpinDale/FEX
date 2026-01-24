// SPDX-License-Identifier: MIT
#pragma once

#ifdef __APPLE__

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

// Define this guard and structures early since both x32/Types.h and x64/Types.h include LinuxCompat.h
// and both try to define ipc64_perm and semid64_ds. Defining them here ensures consistency.
#ifndef FEX_X64_IPC_STRUCTS_DEFINED
#define FEX_X64_IPC_STRUCTS_DEFINED

// IPC permission structures from Linux kernel - these are architecture-specific
// but we use the x86-64 layout which is compatible with x86-32 for these structs
typedef int32_t __kernel_key_t;
typedef int32_t __kernel_mode_t;
typedef uint32_t __kernel_uid32_t;
typedef uint32_t __kernel_gid32_t;
typedef uint32_t __kernel_pid_t;
// __kernel_size_t: On macOS arm64, size_t is `unsigned long`.
// This must match drm.h's definition for BSD systems: `typedef size_t __kernel_size_t;`
// Use a guard to prevent redefinition when drm.h is included.
#ifndef FEX_KERNEL_SIZE_T_DEFINED
#define FEX_KERNEL_SIZE_T_DEFINED
typedef size_t __kernel_size_t;
#endif
typedef uint64_t __kernel_ulong_t;

struct __kernel_fsid_t {
  int val[2];
};

struct ipc64_perm {
  __kernel_key_t key;
  __kernel_uid32_t uid;
  __kernel_gid32_t gid;
  __kernel_uid32_t cuid;
  __kernel_gid32_t cgid;
  __kernel_mode_t mode;
  unsigned char __pad1[4 - sizeof(__kernel_mode_t)];
  unsigned short seq;
  unsigned short __pad2;
  __kernel_ulong_t __unused1;
  __kernel_ulong_t __unused2;
};

struct semid64_ds {
  struct ipc64_perm sem_perm;
  int64_t sem_otime;
  int64_t sem_ctime;
  __kernel_ulong_t sem_nsems;
  __kernel_ulong_t __unused3;
  __kernel_ulong_t __unused4;
};

#endif // FEX_X64_IPC_STRUCTS_DEFINED

// linux/seccomp.h compatibility
#define SECCOMP_MODE_DISABLED 0
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2

#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_KILL_THREAD  0x00000000U
#define SECCOMP_RET_KILL         SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_TRAP         0x00030000U
#define SECCOMP_RET_ERRNO        0x00050000U
#define SECCOMP_RET_USER_NOTIF   0x7fc00000U
#define SECCOMP_RET_TRACE        0x7ff00000U
#define SECCOMP_RET_LOG          0x7ffc0000U
#define SECCOMP_RET_ALLOW        0x7fff0000U

#define SECCOMP_RET_ACTION_FULL  0xffff0000U
#define SECCOMP_RET_ACTION       0x7fff0000U
#define SECCOMP_RET_DATA         0x0000ffffU

// seccomp_data structure used by seccomp BPF
#ifndef FEX_SECCOMP_DATA_DEFINED
#define FEX_SECCOMP_DATA_DEFINED
struct seccomp_data {
  int nr;
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t args[6];
};
#endif

#include <net/bpf.h>

#ifndef BPF_MOD
#define BPF_MOD   0x90
#endif
#ifndef BPF_XOR
#define BPF_XOR   0xa0
#endif

// linux/filter.h compatibility
struct sock_filter {
  uint16_t code;   // Filter code
  uint8_t  jt;     // Jump true
  uint8_t  jf;     // Jump false
  uint32_t k;      // Generic value
};

struct sock_fprog {
  unsigned short len;       // Number of filter blocks
  struct sock_filter *filter;
};

// BPF macros - only define if not already provided by net/bpf.h
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

#define BPF_MEMWORDS 16  // BPF scratch memory size

// linux/types.h compatibility - just need basic types
typedef int32_t __s32;
typedef uint32_t __u32;
typedef int64_t __s64;
typedef uint64_t __u64;
typedef int16_t __s16;
typedef uint16_t __u16;
typedef int8_t __s8;
typedef uint8_t __u8;
typedef uint64_t __le64;
typedef uint32_t __le32;
typedef uint16_t __le16;
typedef uint64_t __be64;
typedef uint32_t __be32;
typedef uint16_t __be16;

// off64_t - macOS uses off_t which is already 64-bit
typedef off_t off64_t;

// linux/mman.h compatibility - additional mmap flags
#ifndef MAP_GROWSDOWN
#define MAP_GROWSDOWN 0x0100
#endif
#ifndef MAP_DENYWRITE
#define MAP_DENYWRITE 0x0800
#endif
#ifndef MAP_EXECUTABLE
#define MAP_EXECUTABLE 0x1000
#endif
#ifndef MAP_LOCKED
#define MAP_LOCKED 0x2000
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0x4000
#endif
#ifndef MAP_POPULATE
#define MAP_POPULATE 0x8000
#endif
#ifndef MAP_NONBLOCK
#define MAP_NONBLOCK 0x10000
#endif
#ifndef MAP_STACK
#define MAP_STACK 0x20000
#endif
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_SYNC
#define MAP_SYNC 0x80000
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// linux/futex.h compatibility
#define FUTEX_WAIT            0
#define FUTEX_WAKE            1
#define FUTEX_FD              2
#define FUTEX_REQUEUE         3
#define FUTEX_CMP_REQUEUE     4
#define FUTEX_WAKE_OP         5
#define FUTEX_LOCK_PI         6
#define FUTEX_UNLOCK_PI       7
#define FUTEX_TRYLOCK_PI      8
#define FUTEX_WAIT_BITSET     9
#define FUTEX_WAKE_BITSET     10
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12

#define FUTEX_PRIVATE_FLAG    128
#define FUTEX_CLOCK_REALTIME  256

#define FUTEX_CMD_MASK        ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

#define FUTEX_WAIT_PRIVATE    (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE    (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)

// linux/openat2.h compatibility
struct open_how {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};

#define RESOLVE_NO_XDEV       0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS   0x04
#define RESOLVE_BENEATH       0x08
#define RESOLVE_IN_ROOT       0x10
#define RESOLVE_CACHED        0x20

// sys/personality.h compatibility
#define PER_LINUX             0x0000
#define PER_LINUX_32BIT       0x0008
#define READ_IMPLIES_EXEC     0x0400000
#define ADDR_LIMIT_32BIT      0x0800000
#define ADDR_NO_RANDOMIZE     0x0040000

// Signal compatibility constants
#ifndef SI_KERNEL
#define SI_KERNEL 0x80
#endif
#ifndef SI_SIGIO
#define SI_SIGIO -5
#endif
#ifndef SIGPOLL
#define SIGPOLL SIGIO
#endif

// SHM flags
#ifndef SHM_EXEC
#define SHM_EXEC 0100000
#endif

// IPC control commands
#ifndef IPC_STAT
#define IPC_STAT 2
#endif
#ifndef IPC_SET
#define IPC_SET 1
#endif
#ifndef IPC_RMID
#define IPC_RMID 0
#endif

// mremap flags - macOS doesn't have mremap, but we define the flags for compatibility
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

// memfd flags
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif

// File sealing flags
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL     0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK   0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW     0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE    0x0008
#endif
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

// F_ADD_SEALS and F_GET_SEALS fcntl commands
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif

// sendfile on macOS has different signature; for compatibility, stub it
// (actual implementation would need platform-specific code)
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

// O_PATH and O_TMPFILE don't exist on macOS
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_TMPFILE
#define O_TMPFILE 020200000
#endif

// memfd_create stub for macOS - uses shm_open as fallback
// Returns a file descriptor or -1 on error
#include <stdlib.h>
#include <errno.h>

static inline int memfd_create(const char* name, unsigned int flags) {
  // macOS doesn't have memfd_create, use a temporary file instead
  char template_path[] = "/tmp/fex_memfd_XXXXXX";
  int fd = mkstemp(template_path);
  if (fd >= 0) {
    // Remove the file but keep the fd open
    unlink(template_path);
    if (flags & MFD_CLOEXEC) {
      fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
  }
  return fd;
}

// tgkill stub for macOS - use pthread_kill
#include <pthread.h>
static inline int tgkill(int tgid, int tid, int sig) {
  // macOS doesn't have tgkill, this is a simplified implementation
  // In practice, FEX would need to track thread IDs to pthreads mapping
  (void)tgid;
  (void)tid;
  return kill(tgid, sig);  // Simplified: just signal the process
}

// signalfd stub for macOS - not directly supported
// Return -1 with ENOSYS as this needs kqueue-based emulation
static inline int signalfd(int fd, const void* mask, int flags) {
  (void)fd;
  (void)mask;
  (void)flags;
  errno = ENOSYS;
  return -1;
}

// personality stub for macOS
#define PERSONALITY_LINUX 0
static inline int personality(unsigned long persona) {
  (void)persona;
  // macOS doesn't have personality, return success for Linux personality
  return PERSONALITY_LINUX;
}

// Syscall numbers for signal operations
// macOS doesn't have these as syscall numbers, define stubs
#define SYS_rt_sigaction    512  // Placeholder - not real macOS syscall
#define SYS_rt_sigprocmask  513  // Placeholder - not real macOS syscall
#define SYS_rt_sigtimedwait 514  // Placeholder - not real macOS syscall
#define SYS_execveat        515  // Placeholder - not real macOS syscall
#define SYS_getrandom       516  // Placeholder - not real macOS syscall

// seccomp operation constants
#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_GET_NOTIF_SIZES 3

// Audit constants
#define AUDIT_SECCOMP 1326

// AT_* constants for openat and related syscalls
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

// Clone flags
#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif
#ifndef CLONE_FS
#define CLONE_FS 0x00000200
#endif
#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif
#ifndef CLONE_SIGHAND
#define CLONE_SIGHAND 0x00000800
#endif
#ifndef CLONE_PTRACE
#define CLONE_PTRACE 0x00002000
#endif
#ifndef CLONE_VFORK
#define CLONE_VFORK 0x00004000
#endif
#ifndef CLONE_PARENT
#define CLONE_PARENT 0x00008000
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_SYSVSEM
#define CLONE_SYSVSEM 0x00040000
#endif
#ifndef CLONE_SETTLS
#define CLONE_SETTLS 0x00080000
#endif
#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x00100000
#endif
#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000
#endif
#ifndef CLONE_DETACHED
#define CLONE_DETACHED 0x00400000
#endif
#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED 0x00800000
#endif
#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID 0x01000000
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef CLONE_IO
#define CLONE_IO 0x80000000
#endif

// prctl constants
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

// sys/prctl.h stub for macOS
static inline int prctl(int option, ...) {
  (void)option;
  // Stub implementation - most prctl operations aren't supported on macOS
  if (option == PR_GET_NO_NEW_PRIVS) {
    return 0;  // Return 0 (no new privs not set)
  }
  if (option == PR_SET_NO_NEW_PRIVS) {
    return 0;  // Pretend success
  }
  errno = EINVAL;
  return -1;
}

// seccomp filter flags
#define SECCOMP_FILTER_FLAG_TSYNC 1
#define SECCOMP_FILTER_FLAG_LOG 2
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW 4
#define SECCOMP_FILTER_FLAG_NEW_LISTENER 8
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH 16

// gettid - macOS doesn't have gettid, use pthread_threadid_np
static inline pid_t gettid(void) {
  uint64_t tid;
  pthread_threadid_np(NULL, &tid);
  return (pid_t)tid;
}

// sendfile stub for macOS
// macOS has sendfile but with different signature
#include <sys/socket.h>
#include <sys/uio.h>
static inline ssize_t linux_sendfile(int out_fd, int in_fd, off_t* offset, size_t count) {
  off_t len = count;
  off_t start = offset ? *offset : 0;
  int result = sendfile(in_fd, out_fd, start, &len, NULL, 0);
  if (result == 0 || (result == -1 && errno == EAGAIN)) {
    if (offset) *offset += len;
    return len;
  }
  return -1;
}
#define sendfile linux_sendfile

// process_vm_readv/writev stubs - not available on macOS
static inline ssize_t process_vm_readv(pid_t pid, const struct iovec* local_iov, unsigned long liovcnt,
                                       const struct iovec* remote_iov, unsigned long riovcnt, unsigned long flags) {
  (void)pid; (void)local_iov; (void)liovcnt; (void)remote_iov; (void)riovcnt; (void)flags;
  errno = ENOSYS;
  return -1;
}

static inline ssize_t process_vm_writev(pid_t pid, const struct iovec* local_iov, unsigned long liovcnt,
                                        const struct iovec* remote_iov, unsigned long riovcnt, unsigned long flags) {
  (void)pid; (void)local_iov; (void)liovcnt; (void)remote_iov; (void)riovcnt; (void)flags;
  errno = ENOSYS;
  return -1;
}

// timerfd stubs for macOS
#define TFD_CLOEXEC O_CLOEXEC
#define TFD_NONBLOCK O_NONBLOCK
#define TFD_TIMER_ABSTIME 1

static inline int timerfd_create(int clockid, int flags) {
  (void)clockid; (void)flags;
  errno = ENOSYS;
  return -1;
}

static inline int timerfd_settime(int fd, int flags, const struct itimerspec* new_value, struct itimerspec* old_value) {
  (void)fd; (void)flags; (void)new_value; (void)old_value;
  errno = ENOSYS;
  return -1;
}

static inline int timerfd_gettime(int fd, struct itimerspec* curr_value) {
  (void)fd; (void)curr_value;
  errno = ENOSYS;
  return -1;
}

// posix_fadvise64 - macOS doesn't have this, use posix_fadvise or stub
#define posix_fadvise64 posix_fadvise

// fstatfs64 - use fstatfs on macOS
#define fstatfs64 fstatfs

// loff_t typedef
typedef off_t loff_t;

// umount stub for macOS - use unmount
#include <sys/mount.h>
static inline int umount(const char* target) {
  return unmount(target, 0);
}
static inline int umount2(const char* target, int flags) {
  return unmount(target, flags);
}

// epoll compatibility - definitions are in LinuxSyscalls/Types.h
// Additional epoll constants not in Types.h
#ifndef EPOLLPRI
#define EPOLLPRI       0x002
#endif
#ifndef EPOLLRDNORM
#define EPOLLRDNORM    0x040
#endif
#ifndef EPOLLRDBAND
#define EPOLLRDBAND    0x080
#endif
#ifndef EPOLLWRNORM
#define EPOLLWRNORM    0x100
#endif
#ifndef EPOLLWRBAND
#define EPOLLWRBAND    0x200
#endif
#ifndef EPOLLMSG
#define EPOLLMSG       0x400
#endif
#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1U << 28)
#endif
#ifndef EPOLLWAKEUP
#define EPOLLWAKEUP    (1U << 29)
#endif
#ifndef EPOLL_CLOEXEC
#define EPOLL_CLOEXEC  02000000
#endif

// Shared memory structures for macOS
// macOS has sys/shm.h but with different structure layouts
#include <sys/ipc.h>

// shmid_ds on macOS is different from Linux - define Linux-compatible version
struct linux_shmid_ds {
  struct ipc_perm shm_perm;
  size_t shm_segsz;
  pid_t shm_lpid;
  pid_t shm_cpid;
  unsigned short shm_nattch;
  time_t shm_atime;
  time_t shm_dtime;
  time_t shm_ctime;
};

// Audit architecture constants (from linux/audit.h)
#define AUDIT_ARCH_I386    0x40000003
#define AUDIT_ARCH_X86_64  0xc000003e

// xattr functions - macOS has different API
#include <sys/xattr.h>

// macOS xattr functions have different signatures than Linux
// Linux: ssize_t getxattr(const char *path, const char *name, void *value, size_t size);
// macOS: ssize_t getxattr(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options);

static inline ssize_t linux_getxattr(const char* path, const char* name, void* value, size_t size) {
  return getxattr(path, name, value, size, 0, 0);
}

static inline ssize_t linux_lgetxattr(const char* path, const char* name, void* value, size_t size) {
  return getxattr(path, name, value, size, 0, XATTR_NOFOLLOW);
}

static inline ssize_t linux_fgetxattr(int fd, const char* name, void* value, size_t size) {
  return fgetxattr(fd, name, value, size, 0, 0);
}

static inline int linux_setxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
  int macos_flags = 0;
  if (flags & 0x1) macos_flags |= XATTR_CREATE;  // XATTR_CREATE
  if (flags & 0x2) macos_flags |= XATTR_REPLACE; // XATTR_REPLACE
  return setxattr(path, name, value, size, 0, macos_flags);
}

static inline int linux_lsetxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
  int macos_flags = XATTR_NOFOLLOW;
  if (flags & 0x1) macos_flags |= XATTR_CREATE;
  if (flags & 0x2) macos_flags |= XATTR_REPLACE;
  return setxattr(path, name, value, size, 0, macos_flags);
}

static inline int linux_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
  int macos_flags = 0;
  if (flags & 0x1) macos_flags |= XATTR_CREATE;
  if (flags & 0x2) macos_flags |= XATTR_REPLACE;
  return fsetxattr(fd, name, value, size, 0, macos_flags);
}

static inline ssize_t linux_listxattr(const char* path, char* list, size_t size) {
  return listxattr(path, list, size, 0);
}

static inline ssize_t linux_llistxattr(const char* path, char* list, size_t size) {
  return listxattr(path, list, size, XATTR_NOFOLLOW);
}

static inline ssize_t linux_flistxattr(int fd, char* list, size_t size) {
  return flistxattr(fd, list, size, 0);
}

static inline int linux_removexattr(const char* path, const char* name) {
  return removexattr(path, name, 0);
}

static inline int linux_lremovexattr(const char* path, const char* name) {
  return removexattr(path, name, XATTR_NOFOLLOW);
}

static inline int linux_fremovexattr(int fd, const char* name) {
  return fremovexattr(fd, name, 0);
}

// Macro redirects for xattr functions to use Linux-compatible wrappers
#define lgetxattr linux_lgetxattr
#define lsetxattr linux_lsetxattr
#define llistxattr linux_llistxattr
#define lremovexattr linux_lremovexattr

// pthread_getattr_np alternative for macOS
static inline int fex_pthread_getattr_np(pthread_t thread, pthread_attr_t* attr) {
  // Initialize the attr
  int ret = pthread_attr_init(attr);
  if (ret != 0) return ret;

  // Get stack info using macOS-specific APIs
  void* stackaddr = pthread_get_stackaddr_np(thread);
  size_t stacksize = pthread_get_stacksize_np(thread);

  // On macOS, stackaddr points to the TOP of the stack, not the base
  // Adjust to get the base address
  void* stackbase = (void*)((uintptr_t)stackaddr - stacksize);

  pthread_attr_setstack(attr, stackbase, stacksize);
  return 0;
}
#define pthread_getattr_np fex_pthread_getattr_np

// fstatat64 - macOS uses fstatat with struct stat
#define fstatat64 fstatat

// stat64 - macOS uses struct stat
#define stat64 stat
#define lstat64 lstat
#define fstat64 fstat

// mremap stub - macOS doesn't have mremap, need to emulate with mmap/munmap/memcpy
// This is a simplified version that doesn't handle all cases
static inline void* fex_mremap(void* old_address, size_t old_size, size_t new_size, int flags, ...) {
  // MREMAP_MAYMOVE means we can return a different address
  if (!(flags & MREMAP_MAYMOVE)) {
    // Can't move, and we can't resize in place on macOS
    if (new_size > old_size) {
      errno = ENOMEM;
      return MAP_FAILED;
    }
    // Shrinking might work, but let's be conservative
    return old_address;
  }

  // Allocate new region
  void* new_address = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (new_address == MAP_FAILED) {
    return MAP_FAILED;
  }

  // Copy data
  size_t copy_size = old_size < new_size ? old_size : new_size;
  memcpy(new_address, old_address, copy_size);

  // Unmap old region unless MREMAP_DONTUNMAP is set
  if (!(flags & MREMAP_DONTUNMAP)) {
    munmap(old_address, old_size);
  }

  return new_address;
}
#define mremap fex_mremap

// Shared memory stubs for macOS
// macOS has shm_* POSIX functions but not the same shmget/shmat/shmdt/shmctl
#include <sys/shm.h>

// shmid_ds structure for macOS - use the system one if available
// The struct is defined but may be incomplete

// Additional signal info fields macros - macOS siginfo_t is different
// These provide default values when the macOS siginfo_t doesn't have the field
#define FEX_GET_SI_TIMERID(info) 0
#define FEX_GET_SI_OVERRUN(info) 0
#define FEX_GET_SI_INT(info) 0
#define FEX_GET_SI_FD(info) 0
#define FEX_GET_SI_UTIME(info) 0
#define FEX_GET_SI_STIME(info) 0
#define FEX_GET_SI_CALL_ADDR(info) nullptr
#define FEX_GET_SI_SYSCALL(info) 0

// macOS stat structure uses different field names for timespec members
// On macOS, use st_atimespec instead of st_atim, etc.
// Accessor macros for timespec fields in stat structures
#define FEX_STAT_ATIME_SEC(s) ((s).st_atimespec.tv_sec)
#define FEX_STAT_ATIME_NSEC(s) ((s).st_atimespec.tv_nsec)
#define FEX_STAT_MTIME_SEC(s) ((s).st_mtimespec.tv_sec)
#define FEX_STAT_MTIME_NSEC(s) ((s).st_mtimespec.tv_nsec)
#define FEX_STAT_CTIME_SEC(s) ((s).st_ctimespec.tv_sec)
#define FEX_STAT_CTIME_NSEC(s) ((s).st_ctimespec.tv_nsec)

// statfs structure compatibility
#include <sys/mount.h>  // macOS uses sys/mount.h for statfs
struct linux_statfs64 {
  uint32_t f_type;
  int32_t f_bsize;
  uint64_t f_blocks;
  uint64_t f_bfree;
  uint64_t f_bavail;
  uint64_t f_files;
  uint64_t f_ffree;
  struct { int val[2]; } f_fsid;
  int32_t f_namelen;
  int32_t f_frsize;
  int32_t f_flags;
  int32_t f_spare[4];
};

// IPC constants
#ifndef IPC_INFO
#define IPC_INFO 3
#endif
#ifndef SEM_INFO
#define SEM_INFO 19
#endif
#ifndef SEM_STAT
#define SEM_STAT 18
#endif
#ifndef MSG_STAT
#define MSG_STAT 11
#endif
#ifndef MSG_INFO
#define MSG_INFO 12
#endif
#ifndef SHM_STAT
#define SHM_STAT 13
#endif
#ifndef SHM_INFO
#define SHM_INFO 14
#endif
#ifndef SHM_LOCK
#define SHM_LOCK 11
#endif
#ifndef SHM_UNLOCK
#define SHM_UNLOCK 12
#endif

// msgbuf structure for System V message queues
struct msgbuf {
  long mtype;
  char mtext[1];
};

// mmsghdr structure for sendmmsg/recvmmsg
struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int msg_len;
};

// recvmmsg/sendmmsg stubs
static inline int recvmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags, struct timespec* timeout) {
  (void)sockfd; (void)msgvec; (void)vlen; (void)flags; (void)timeout;
  errno = ENOSYS;
  return -1;
}

static inline int sendmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags) {
  (void)sockfd; (void)msgvec; (void)vlen; (void)flags;
  errno = ENOSYS;
  return -1;
}

// sched_rr_get_interval stub
static inline int sched_rr_get_interval(pid_t pid, struct timespec* tp) {
  (void)pid;
  if (tp) {
    tp->tv_sec = 0;
    tp->tv_nsec = 100000000; // 100ms default time slice
  }
  return 0;
}

// posix_fadvise stub for macOS
static inline int fex_posix_fadvise(int fd, off_t offset, off_t len, int advice) {
  (void)fd; (void)offset; (void)len; (void)advice;
  // macOS doesn't have posix_fadvise, silently succeed
  return 0;
}
#define posix_fadvise fex_posix_fadvise

// pread64/pwrite64 - macOS already supports large files, just use pread/pwrite
#define pread64 pread
#define pwrite64 pwrite

// readahead stub
static inline ssize_t readahead(int fd, off_t offset, size_t count) {
  (void)fd; (void)offset; (void)count;
  // macOS doesn't have readahead, but fcntl F_RDADVISE is similar
  // For simplicity, return success without doing anything
  return 0;
}

// fallocate stub - macOS uses fcntl with F_PREALLOCATE
static inline int fallocate(int fd, int mode, off_t offset, off_t len) {
  (void)mode;
  fstore_t store = {F_ALLOCATECONTIG, F_PEOFPOSMODE, offset, len, 0};
  if (fcntl(fd, F_PREALLOCATE, &store) == -1) {
    store.fst_flags = F_ALLOCATEALL;
    if (fcntl(fd, F_PREALLOCATE, &store) == -1) {
      return -1;
    }
  }
  return ftruncate(fd, offset + len);
}

// vmsplice stub - not available on macOS
static inline ssize_t vmsplice(int fd, const struct iovec* iov, size_t nr_segs, unsigned int flags) {
  (void)fd; (void)iov; (void)nr_segs; (void)flags;
  errno = ENOSYS;
  return -1;
}

// splice stub - not available on macOS
static inline ssize_t splice(int fd_in, off_t* off_in, int fd_out, off_t* off_out, size_t len, unsigned int flags) {
  (void)fd_in; (void)off_in; (void)fd_out; (void)off_out; (void)len; (void)flags;
  errno = ENOSYS;
  return -1;
}

// tee stub - not available on macOS
static inline ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags) {
  (void)fd_in; (void)fd_out; (void)len; (void)flags;
  errno = ENOSYS;
  return -1;
}

// Splice flags
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 2
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE 4
#endif
#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 8
#endif

// aio_abi.h - Linux async I/O structures
// These are Linux kernel AIO, not POSIX aio
#ifndef FEX_AIO_CONTEXT_T_DEFINED
#define FEX_AIO_CONTEXT_T_DEFINED
typedef unsigned long aio_context_t;
#endif

#ifndef FEX_IOCB_DEFINED
#define FEX_IOCB_DEFINED
struct iocb {
  uint64_t aio_data;
  uint32_t aio_key;
  uint32_t aio_reserved1;
  uint16_t aio_lio_opcode;
  int16_t aio_reqprio;
  uint32_t aio_fildes;
  uint64_t aio_buf;
  uint64_t aio_nbytes;
  int64_t aio_offset;
  uint64_t aio_reserved2;
  uint32_t aio_flags;
  uint32_t aio_resfd;
};
#endif

#ifndef FEX_IO_EVENT_DEFINED
#define FEX_IO_EVENT_DEFINED
struct io_event {
  uint64_t data;
  uint64_t obj;
  int64_t res;
  int64_t res2;
};
#endif

// Linux AIO opcodes
#ifndef FEX_IOCB_CMD_DEFINED
#define FEX_IOCB_CMD_DEFINED
#define IOCB_CMD_PREAD 0
#define IOCB_CMD_PWRITE 1
#define IOCB_CMD_FSYNC 2
#define IOCB_CMD_FDSYNC 3
#define IOCB_CMD_POLL 5
#define IOCB_CMD_NOOP 6
#define IOCB_CMD_PREADV 7
#define IOCB_CMD_PWRITEV 8
#endif

// seccomp_notif structures
#ifndef FEX_SECCOMP_NOTIF_DEFINED
#define FEX_SECCOMP_NOTIF_DEFINED
struct seccomp_notif_sizes {
  uint16_t seccomp_notif;
  uint16_t seccomp_notif_resp;
  uint16_t seccomp_data;
};

struct seccomp_notif {
  uint64_t id;
  uint32_t pid;
  uint32_t flags;
  struct seccomp_data data;
};

struct seccomp_notif_resp {
  uint64_t id;
  int64_t val;
  int32_t error;
  uint32_t flags;
};
#endif

// clone() function is not available on macOS
// We need to define it as a stub that uses pthread_create or fork
// This is a complex function that requires careful emulation
typedef int (*clone_fn)(void*);
static inline int fex_clone(clone_fn fn, void* stack, int flags, void* arg, ...) {
  (void)fn; (void)stack; (void)flags; (void)arg;
  // clone() is highly Linux-specific
  // For basic functionality, we can use fork() for process cloning
  // or pthread_create for thread cloning
  if (flags & CLONE_VM) {
    // Thread-like clone - needs pthread_create
    errno = ENOSYS;
    return -1;
  } else {
    // Process-like clone - can use fork
    errno = ENOSYS;
    return -1;
  }
}
// Note: We don't #define clone because it conflicts with std::clone

// linux/utsname.h compatibility
#define __OLD_UTS_LEN 8
#define __NEW_UTS_LEN 64

struct oldold_utsname {
  char sysname[9];
  char nodename[9];
  char release[9];
  char version[9];
  char machine[9];
};

struct old_utsname {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
};

// Linux utsname structure (macOS utsname doesn't have domainname)
// Use a different struct name and typedef to avoid conflicts with sys/utsname.h
struct linux_utsname {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};

// sysinfo structure for macOS
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
  unsigned long totalhigh;
  unsigned long freehigh;
  unsigned int mem_unit;
  char _f[20 - 2 * sizeof(long) - sizeof(int)];
};

// sysinfo() stub - gets system information
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>

static inline int sysinfo(struct sysinfo* info) {
  if (!info) {
    errno = EFAULT;
    return -1;
  }
  memset(info, 0, sizeof(*info));

  // Get uptime
  struct timeval boottime;
  size_t len = sizeof(boottime);
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};
  if (sysctl(mib, 2, &boottime, &len, NULL, 0) == 0) {
    time_t now;
    time(&now);
    info->uptime = now - boottime.tv_sec;
  }

  // Get load averages
  double loadavg[3];
  if (getloadavg(loadavg, 3) != -1) {
    info->loads[0] = (unsigned long)(loadavg[0] * 65536);
    info->loads[1] = (unsigned long)(loadavg[1] * 65536);
    info->loads[2] = (unsigned long)(loadavg[2] * 65536);
  }

  // Get memory info
  vm_size_t page_size;
  mach_port_t mach_port = mach_host_self();
  host_page_size(mach_port, &page_size);

  vm_statistics64_data_t vm_stats;
  mach_msg_type_number_t count = sizeof(vm_stats) / sizeof(natural_t);
  if (host_statistics64(mach_port, HOST_VM_INFO64, (host_info64_t)&vm_stats, &count) == KERN_SUCCESS) {
    uint64_t total = (uint64_t)vm_stats.free_count + vm_stats.active_count +
                     vm_stats.inactive_count + vm_stats.wire_count;
    info->totalram = total * page_size;
    info->freeram = (uint64_t)vm_stats.free_count * page_size;
  }

  info->procs = 1;  // Placeholder
  info->mem_unit = 1;

  return 0;
}

// Socket options not available on macOS
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif
#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#endif
// NOTE: Linux SO_* values differ from macOS. We use unique values that don't conflict
// with macOS's existing socket options to allow case statements to work.
// These are FEX-internal mappings and actual syscall translation handles the real values.
#ifndef SO_SNDBUFFORCE
#define SO_SNDBUFFORCE 0x8001  // Unique value for FEX
#endif
#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 0x8002
#endif
#ifndef SO_NO_CHECK
#define SO_NO_CHECK 0x8003
#endif
#ifndef SO_PRIORITY
#define SO_PRIORITY 0x8004
#endif
#ifndef SO_BSDCOMPAT
#define SO_BSDCOMPAT 0x8005
#endif
#ifndef SO_PASSCRED
#define SO_PASSCRED 0x8006
#endif
#ifndef SO_PEERCRED
#define SO_PEERCRED 0x8007
#endif
#ifndef SO_SECURITY_AUTHENTICATION
#define SO_SECURITY_AUTHENTICATION 22
#endif
#ifndef SO_SECURITY_ENCRYPTION_TRANSPORT
#define SO_SECURITY_ENCRYPTION_TRANSPORT 23
#endif
#ifndef SO_SECURITY_ENCRYPTION_NETWORK
#define SO_SECURITY_ENCRYPTION_NETWORK 24
#endif
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif
#ifndef SO_DETACH_FILTER
#define SO_DETACH_FILTER 27
#endif
#ifndef SO_PEERNAME
#define SO_PEERNAME 28
#endif
#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif
#ifndef SO_PASSSEC
#define SO_PASSSEC 34
#endif
#ifndef SO_MARK
#define SO_MARK 36
#endif
#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif
#ifndef SO_WIFI_STATUS
#define SO_WIFI_STATUS 41
#endif
#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF 42
#endif
#ifndef SO_NOFCS
#define SO_NOFCS 43
#endif
#ifndef SO_LOCK_FILTER
#define SO_LOCK_FILTER 44
#endif
#ifndef SO_SELECT_ERR_QUEUE
#define SO_SELECT_ERR_QUEUE 45
#endif
#ifndef SO_BUSY_POLL
#define SO_BUSY_POLL 46
#endif
#ifndef SO_MAX_PACING_RATE
#define SO_MAX_PACING_RATE 47
#endif
#ifndef SO_BPF_EXTENSIONS
#define SO_BPF_EXTENSIONS 48
#endif
#ifndef SO_INCOMING_CPU
#define SO_INCOMING_CPU 49
#endif
#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif
#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif
#ifndef SO_CNX_ADVICE
#define SO_CNX_ADVICE 53
#endif
#ifndef SCM_TIMESTAMPING_OPT_STATS
#define SCM_TIMESTAMPING_OPT_STATS 54
#endif
#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif
#ifndef SCM_TIMESTAMPING_PKTINFO
#define SCM_TIMESTAMPING_PKTINFO 58
#endif
#ifndef SO_PEERGROUPS
#define SO_PEERGROUPS 59
#endif
#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif
#ifndef SO_TXTIME
#define SO_TXTIME 61
#endif
#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62
#endif
#ifndef SO_PROTOCOL
#define SO_PROTOCOL 38
#endif
#ifndef SO_DOMAIN
#define SO_DOMAIN 39
#endif

// Socket type flags
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0x80000
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0x800
#endif

// accept4 stub for macOS - macOS doesn't have accept4
static inline int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
  int fd = accept(sockfd, addr, addrlen);
  if (fd >= 0) {
    if (flags & SOCK_CLOEXEC) {
      fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    if (flags & SOCK_NONBLOCK) {
      int fl = fcntl(fd, F_GETFL);
      fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
  }
  return fd;
}

// CSIGNAL mask for clone
#ifndef CSIGNAL
#define CSIGNAL 0x000000ff
#endif

// dup3 stub for macOS - macOS doesn't have dup3
static inline int dup3(int oldfd, int newfd, int flags) {
  if (oldfd == newfd) {
    errno = EINVAL;
    return -1;
  }
  int result = dup2(oldfd, newfd);
  if (result >= 0 && (flags & O_CLOEXEC)) {
    fcntl(result, F_SETFD, FD_CLOEXEC);
  }
  return result;
}

// pipe2 stub for macOS - macOS doesn't have pipe2
static inline int pipe2(int pipefd[2], int flags) {
  int result = pipe(pipefd);
  if (result == 0) {
    if (flags & O_CLOEXEC) {
      fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
      fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    }
    if (flags & O_NONBLOCK) {
      fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
      fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL) | O_NONBLOCK);
    }
  }
  return result;
}

// TIMER_ABSTIME for timer operations
#ifndef TIMER_ABSTIME
#define TIMER_ABSTIME 1
#endif

// timex structure and adjtimex for macOS
#ifndef FEX_TIMEX_DEFINED
#define FEX_TIMEX_DEFINED
struct timex {
  unsigned int modes;
  long offset;
  long freq;
  long maxerror;
  long esterror;
  int status;
  long constant;
  long precision;
  long tolerance;
  struct timeval time;
  long tick;
  long ppsfreq;
  long jitter;
  int shift;
  long stabil;
  long jitcnt;
  long calcnt;
  long errcnt;
  long stbcnt;
  int tai;
  int _padding[11];
};
#endif

static inline int adjtimex(struct timex* buf) {
  (void)buf;
  errno = ENOSYS;
  return -1;
}

static inline int clock_adjtime(clockid_t clk_id, struct timex* buf) {
  (void)clk_id; (void)buf;
  errno = ENOSYS;
  return -1;
}

// setfsuid/setfsgid stubs for macOS
static inline int setfsuid(uid_t uid) {
  (void)uid;
  return geteuid();  // Return the previous effective uid
}

static inline int setfsgid(gid_t gid) {
  (void)gid;
  return getegid();  // Return the previous effective gid
}

// clone syscall stub for macOS
// On macOS, we can't emulate Linux clone() fully. For thread creation, we'd need to use pthread_create.
// For fork-like behavior, we'd use fork(). This stub returns an error for now.
#ifdef __cplusplus
extern "C" {
#endif
static inline int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...) {
  (void)fn; (void)stack; (void)flags; (void)arg;
  errno = ENOSYS;
  return -1;
}
#ifdef __cplusplus
}
#endif

#endif // __APPLE__
