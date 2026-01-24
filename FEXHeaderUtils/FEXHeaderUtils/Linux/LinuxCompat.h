// SPDX-License-Identifier: MIT
#pragma once

#if !defined(__APPLE__)
#define FEX_ST_ATIME(st) ((st).st_atim)
#define FEX_ST_MTIME(st) ((st).st_mtim)
#define FEX_ST_CTIME(st) ((st).st_ctim)
#define FEX_SIGMASK_VAL(sigmask) ((sigmask).__val[0])
#endif

#ifdef __APPLE__

#include <stdint.h>
#include <sys/types.h>

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef char* caddr_t;
typedef uint32_t fixpt_t;
typedef unsigned long long u_quad_t;

#include <sys/stat.h>
#include <sys/uio.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

// macOS uses st_atimespec, st_mtimespec, st_ctimespec instead of st_atim, st_mtim, st_ctim
#define FEX_ST_ATIME(st) ((st).st_atimespec)
#define FEX_ST_MTIME(st) ((st).st_mtimespec)
#define FEX_ST_CTIME(st) ((st).st_ctimespec)

// stat64 is the same as stat on macOS 64-bit
typedef struct stat stat64;

// statfs64 is the same as statfs on macOS 64-bit
#include <sys/mount.h>
typedef struct statfs statfs64;

// __kernel_fsid_t for filesystem ID
typedef struct { int __val[2]; } __kernel_fsid_t;

// statfs compatibility
#define FEX_STATFS_NAMELEN(sf) (255)  // macOS doesn't have this, use max
#define FEX_STATFS_FRSIZE(sf) ((sf).f_bsize)  // fragment size = block size on macOS

// signal info codes not defined on macOS
#define SI_KERNEL 0x80
#define SI_SIGIO -5

// signals not defined on macOS
#ifndef SIGPOLL
#define SIGPOLL SIGIO  // SIGPOLL is SIGIO on macOS
#endif

// sigset_t on macOS is just an unsigned int, not a struct with __val array
#define FEX_SIGMASK_VAL(sigmask) (sigmask)

// siginfo_t member accessors for macOS compatibility
// macOS siginfo_t has a different structure than Linux
#define FEX_SI_TIMERID(si) (0)  // not available on macOS
#define FEX_SI_OVERRUN(si) (0)  // not available on macOS
#define FEX_SI_INT(si) ((si)->si_value.sival_int)
#define FEX_SI_FD(si) (0)  // not available on macOS
#define FEX_SI_UTIME(si) (0)  // not available on macOS
#define FEX_SI_STIME(si) (0)  // not available on macOS
#define FEX_SI_CALL_ADDR(si) (nullptr)  // not available on macOS
#define FEX_SI_SYSCALL(si) (0)  // not available on macOS

// macOS doesn't have this
struct itimerspec {
  struct timespec it_interval;
  struct timespec it_value;
};

// not defined on macOS
#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif

// some Linux-specific types (defined early so they can be used by structures below)
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

// loff_t - 64-bit file offset
typedef off_t loff_t;

// not available on macOS
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL   0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW   0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE  0x0008
#endif
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

// same as fstat/fstatfs on macOS 64-bit
#define fstat64 fstat
#define fstatfs64 fstatfs
// not available on macOS
// POSIX_FADV_* values
#ifndef POSIX_FADV_NORMAL
#define POSIX_FADV_NORMAL     0
#endif
#ifndef POSIX_FADV_RANDOM
#define POSIX_FADV_RANDOM     1
#endif
#ifndef POSIX_FADV_SEQUENTIAL
#define POSIX_FADV_SEQUENTIAL 2
#endif
#ifndef POSIX_FADV_WILLNEED
#define POSIX_FADV_WILLNEED   3
#endif
#ifndef POSIX_FADV_DONTNEED
#define POSIX_FADV_DONTNEED   4
#endif
#ifndef POSIX_FADV_NOREUSE
#define POSIX_FADV_NOREUSE    5
#endif

static inline int posix_fadvise(int fd, off_t offset, off_t len, int advice) {
  (void)fd; (void)offset; (void)len; (void)advice;
  // posix_fadvise is a hint, returning 0 (success) is acceptable
  return 0;
}

#define posix_fadvise64 posix_fadvise

// macOS uses pread/pwrite for all sizes
#define pread64 pread
#define pwrite64 pwrite

// macOS uses fstatat for all sizes
#define fstatat64 fstatat

// xattr functions on macOS have different signatures than Linux
// Linux: getxattr(path, name, value, size)
// macOS: getxattr(path, name, value, size, position, options)
#include <sys/xattr.h>
static inline ssize_t linux_getxattr(const char *path, const char *name, void *value, size_t size) {
  return ::getxattr(path, name, value, size, 0, 0);
}
static inline ssize_t linux_lgetxattr(const char *path, const char *name, void *value, size_t size) {
  return ::getxattr(path, name, value, size, 0, XATTR_NOFOLLOW);
}
static inline ssize_t linux_fgetxattr(int fd, const char *name, void *value, size_t size) {
  return ::fgetxattr(fd, name, value, size, 0, 0);
}
static inline int linux_setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
  int options = 0;
  if (flags & 1) options |= XATTR_CREATE;
  if (flags & 2) options |= XATTR_REPLACE;
  return ::setxattr(path, name, value, size, 0, options);
}
static inline int linux_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
  int options = XATTR_NOFOLLOW;
  if (flags & 1) options |= XATTR_CREATE;
  if (flags & 2) options |= XATTR_REPLACE;
  return ::setxattr(path, name, value, size, 0, options);
}
static inline int linux_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) {
  int options = 0;
  if (flags & 1) options |= XATTR_CREATE;
  if (flags & 2) options |= XATTR_REPLACE;
  return ::fsetxattr(fd, name, value, size, 0, options);
}
static inline ssize_t linux_listxattr(const char *path, char *list, size_t size) {
  return ::listxattr(path, list, size, 0);
}
static inline ssize_t linux_llistxattr(const char *path, char *list, size_t size) {
  return ::listxattr(path, list, size, XATTR_NOFOLLOW);
}
static inline ssize_t linux_flistxattr(int fd, char *list, size_t size) {
  return ::flistxattr(fd, list, size, 0);
}
static inline int linux_removexattr(const char *path, const char *name) {
  return ::removexattr(path, name, 0);
}
static inline int linux_lremovexattr(const char *path, const char *name) {
  return ::removexattr(path, name, XATTR_NOFOLLOW);
}
static inline int linux_fremovexattr(int fd, const char *name) {
  return ::fremovexattr(fd, name, 0);
}

#define getxattr linux_getxattr
#define lgetxattr linux_lgetxattr
#define fgetxattr linux_fgetxattr
#define setxattr linux_setxattr
#define lsetxattr linux_lsetxattr
#define fsetxattr linux_fsetxattr
#define listxattr linux_listxattr
#define llistxattr linux_llistxattr
#define flistxattr linux_flistxattr
#define removexattr linux_removexattr
#define lremovexattr linux_lremovexattr
#define fremovexattr linux_fremovexattr

// not available on macOS
static inline int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
  (void)fd; (void)flags; (void)new_value; (void)old_value;
  errno = ENOSYS;
  return -1;
}

static inline int timerfd_gettime(int fd, struct itimerspec *curr_value) {
  (void)fd; (void)curr_value;
  errno = ENOSYS;
  return -1;
}

// not available on macOS
static inline ssize_t readahead(int fd, off_t offset, size_t count) {
  (void)fd; (void)offset; (void)count;
  errno = ENOSYS;
  return -1;
}

// not available on macOS
// FALLOC_POSIX definition for fallocate modes
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE     0x01
#endif
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE    0x02
#endif
#ifndef FALLOC_FL_COLLAPSE_RANGE
#define FALLOC_FL_COLLAPSE_RANGE 0x08
#endif
#ifndef FALLOC_FL_ZERO_RANGE
#define FALLOC_FL_ZERO_RANGE    0x10
#endif

static inline int fallocate(int fd, int mode, off_t offset, off_t len) {
  (void)fd; (void)mode; (void)offset; (void)len;
  errno = ENOSYS;
  return -1;
}

// not available on macOS
static inline ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags) {
  (void)fd; (void)iov; (void)nr_segs; (void)flags;
  errno = ENOSYS;
  return -1;
}

// macOS has a different signature than Linux for sendfile
// Linux: ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
// macOS: int sendfile(int fd, int s, off_t offset, off_t *len, struct sf_hdtr *hdtr, int flags);
#include <sys/socket.h>
// We need to undefine sendfile and provide our own Linux-compatible wrapper
// since macOS's signature is incompatible
#ifdef sendfile
#undef sendfile
#endif
static inline ssize_t linux_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
  off_t len = count;
  off_t start_offset = offset ? *offset : lseek(in_fd, 0, SEEK_CUR);
  
  // macOS sendfile: sendfile(in_fd, out_fd, offset, &len, hdtr, flags)
  // NOTE: macOS has reversed fd order compared to Linux!
  int result = ::sendfile(in_fd, out_fd, start_offset, &len, nullptr, 0);
  
  if (result == 0 || (result == -1 && errno == EAGAIN)) {
    // Success or partial success
    if (offset) {
      *offset += len;
    } else {
      lseek(in_fd, start_offset + len, SEEK_SET);
    }
    return len > 0 ? len : (result == 0 ? 0 : -1);
  }
  
  return -1;
}
#define sendfile linux_sendfile

// not available on macOS, return ENOSYS
static inline ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                                       const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
  (void)pid; (void)local_iov; (void)liovcnt; (void)remote_iov; (void)riovcnt; (void)flags;
  errno = ENOSYS;
  return -1;
}

static inline ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                                        const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
  (void)pid; (void)local_iov; (void)liovcnt; (void)remote_iov; (void)riovcnt; (void)flags;
  errno = ENOSYS;
  return -1;
}

static inline int umount(const char *target) {
  return unmount(target, 0);
}

static inline int umount2(const char *target, int flags) {
  return unmount(target, flags);
}

// O_PATH and O_TMPFILE don't exist on macOS
#ifndef O_PATH
#define O_PATH 010000000  // Linux value; on macOS we emulate with O_RDONLY
#endif
#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)  // Linux value
#endif

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

// ipc64_perm structure for IPC
struct ipc64_perm {
  __u32 key;
  __u32 uid;
  __u32 gid;
  __u32 cuid;
  __u32 cgid;
  __u16 mode;
  __u16 __pad1;
  __u16 seq;
  __u16 __pad2;
  __u64 __unused1;
  __u64 __unused2;
};

// shmid64_ds structure for shared memory
struct shmid64_ds {
  struct ipc64_perm shm_perm;
  __u64 shm_segsz;
  __u64 shm_atime;
  __u64 shm_dtime;
  __u64 shm_ctime;
  __u32 shm_cpid;
  __u32 shm_lpid;
  __u64 shm_nattch;
  __u64 __unused1;
  __u64 __unused2;
};

// semid64_ds structure for semaphores
struct semid64_ds {
  struct ipc64_perm sem_perm;
  __u64 sem_otime;
  __u64 sem_ctime;
  __u64 sem_nsems;
  __u64 __unused1;
  __u64 __unused2;
};

// msqid64_ds structure for message queues
struct msqid64_ds {
  struct ipc64_perm msg_perm;
  __u64 msg_stime;
  __u64 msg_rtime;
  __u64 msg_ctime;
  __u64 msg_cbytes;
  __u64 msg_qnum;
  __u64 msg_qbytes;
  __u32 msg_lspid;
  __u32 msg_lrpid;
  __u64 __unused1;
  __u64 __unused2;
};

// shminfo structure
struct shminfo {
  __u64 shmmax;
  __u64 shmmin;
  __u64 shmmni;
  __u64 shmseg;
  __u64 shmall;
};

// shm_info structure
struct shm_info {
  int used_ids;
  __u64 shm_tot;
  __u64 shm_rss;
  __u64 shm_swp;
  __u64 swap_attempts;
  __u64 swap_successes;
};

// SHM flags
#ifndef SHM_EXEC
#define SHM_EXEC 0100000
#endif

// epoll definitions for macOS - only define if not already defined by Types.h
#ifndef FEX_EPOLL_DEFINED
#define FEX_EPOLL_DEFINED

typedef union epoll_data {
  void* ptr;
  int fd;
  __u32 u32;
  __u64 u64;
} epoll_data_t;

struct epoll_event {
  __u32 events;
  epoll_data_t data;
};

#ifndef EPOLLIN
#define EPOLLIN 0x001
#define EPOLLPRI 0x002
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDNORM 0x040
#define EPOLLRDBAND 0x080
#define EPOLLWRNORM 0x100
#define EPOLLWRBAND 0x200
#define EPOLLMSG 0x400
#define EPOLLET 0x80000000
#define EPOLLONESHOT 0x40000000
#define EPOLLWAKEUP 0x20000000
#endif

#ifndef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#endif

// epoll stubs for macOS (epoll doesn't exist, would need kqueue translation)
inline int epoll_create(int size) { (void)size; return -1; }
inline int epoll_create1(int flags) { (void)flags; return -1; }
inline int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) { 
  (void)epfd; (void)op; (void)fd; (void)event; return -1; 
}
inline int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) { 
  (void)epfd; (void)events; (void)maxevents; (void)timeout; return -1; 
}
#endif // FEX_EPOLL_DEFINED
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;

// macOS has its own definitions in sys/ipc.h, sys/shm.h, etc. for IPC structures
// We use the macOS definitions directly and don't redefine them here.
// The Linux-specific layout differences are handled by the x32/Types.h layer.

struct mq_attr {
  long mq_flags;
  long mq_maxmsg;
  long mq_msgsize;
  long mq_curmsgs;
  long __reserved[4];
};

// Time adjustment structures (from sys/timex.h)
// macOS has timex but with different layout
// On macOS, we define it early before sys/timex.h can be included
// Files that need sys/timex.h should include LinuxCompat.h first
#if defined(__APPLE__)
// Define Linux-compatible timex structure (macOS sys/timex.h has incompatible layout)
// This must be defined before any sys/timex.h include
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
  int __padding[11];
};
#else
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
  int __padding[11];
};
#endif

// timex modes
#define ADJ_OFFSET          0x0001
#define ADJ_FREQUENCY       0x0002
#define ADJ_MAXERROR        0x0004
#define ADJ_ESTERROR        0x0008
#define ADJ_STATUS          0x0010
#define ADJ_TIMECONST       0x0020
#define ADJ_TAI             0x0080
#define ADJ_SETOFFSET       0x0100
#define ADJ_MICRO           0x1000
#define ADJ_NANO            0x2000
#define ADJ_TICK            0x4000
#define ADJ_OFFSET_SINGLESHOT 0x8001
#define ADJ_OFFSET_SS_READ  0xa001

// STA_ flags
#define STA_PLL             0x0001
#define STA_PPSFREQ         0x0002
#define STA_PPSTIME         0x0004
#define STA_FLL             0x0008
#define STA_INS             0x0010
#define STA_DEL             0x0020
#define STA_UNSYNC          0x0040
#define STA_FREQHOLD        0x0080
#define STA_PPSSIGNAL       0x0100
#define STA_PPSJITTER       0x0200
#define STA_PPSWANDER       0x0400
#define STA_PPSERROR        0x0800
#define STA_CLOCKERR        0x1000
#define STA_NANO            0x2000
#define STA_MODE            0x4000
#define STA_CLK             0x8000

// sysinfo structure
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
  char _f[20 - 2 * sizeof(long) - sizeof(int)];
};

#include <mach/mach.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>

static inline int fex_get_sysinfo(struct sysinfo *info) {
  if (!info) return -1;
  memset(info, 0, sizeof(*info));
  

  // uptime
  struct timeval boottime;
  size_t size = sizeof(boottime);
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};
  if (sysctl(mib, 2, &boottime, &size, nullptr, 0) == 0) {
    time_t now;
    time(&now);
    info->uptime = now - boottime.tv_sec;
  }
  
  // memory info
  vm_size_t page_size;
  host_page_size(mach_host_self(), &page_size);
  
  vm_statistics64_data_t vm_stats;
  mach_msg_type_number_t count = sizeof(vm_stats) / sizeof(natural_t);
  if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm_stats, &count) == KERN_SUCCESS) {
    info->totalram = (vm_stats.free_count + vm_stats.active_count + vm_stats.inactive_count + vm_stats.wire_count) * page_size;
    info->freeram = vm_stats.free_count * page_size;
  }
  
  info->mem_unit = 1;
  info->procs = 1;  // stub value
  
  return 0;
}

// matches linux
#define __NEW_UTS_LEN 64
struct new_utsname {
  char sysname[__NEW_UTS_LEN + 1];
  char nodename[__NEW_UTS_LEN + 1];
  char release[__NEW_UTS_LEN + 1];
  char version[__NEW_UTS_LEN + 1];
  char machine[__NEW_UTS_LEN + 1];
  char domainname[__NEW_UTS_LEN + 1];
};

#define CLONE_VM             0x00000100
#define CLONE_FS             0x00000200
#define CLONE_FILES          0x00000400
#define CLONE_SIGHAND        0x00000800
#define CLONE_PIDFD          0x00001000
#define CLONE_PTRACE         0x00002000
#define CLONE_VFORK          0x00004000
#define CLONE_PARENT         0x00008000
#define CLONE_THREAD         0x00010000
#define CLONE_NEWNS          0x00020000
#define CLONE_SYSVSEM        0x00040000
#define CLONE_SETTLS         0x00080000
#define CLONE_PARENT_SETTID  0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_DETACHED       0x00400000
#define CLONE_UNTRACED       0x00800000
#define CLONE_CHILD_SETTID   0x01000000
#define CLONE_NEWCGROUP      0x02000000
#define CLONE_NEWUTS         0x04000000
#define CLONE_NEWIPC         0x08000000
#define CLONE_NEWUSER        0x10000000
#define CLONE_NEWPID         0x20000000
#define CLONE_NEWNET         0x40000000
#define CLONE_IO             0x80000000

// O_* flags that may be missing
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

#ifndef O_DIRECT
#define O_DIRECT 0x10000
#endif

#ifndef O_NOATIME
#define O_NOATIME 0x40000
#endif

#ifndef O_PATH
#define O_PATH 0x200000
#endif

#ifndef O_TMPFILE
#define O_TMPFILE (0x400000 | O_DIRECTORY)
#endif

// F_* commands that may be missing
#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#endif

#ifndef F_GETOWN_EX
#define F_GETOWN_EX 16
#endif

#ifndef F_OFD_GETLK
#define F_OFD_GETLK 36
#endif

#ifndef F_OFD_SETLK
#define F_OFD_SETLK 37
#endif

#ifndef F_OFD_SETLKW
#define F_OFD_SETLKW 38
#endif

// AT_* flags
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

// MREMAP flags
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

// waitid options
#ifndef P_PIDFD
#define P_PIDFD 3
#endif

// rlimit constants
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

// prctl operations
#ifndef PR_SET_PDEATHSIG
#define PR_SET_PDEATHSIG 1
#endif

#ifndef PR_GET_PDEATHSIG
#define PR_GET_PDEATHSIG 2
#endif

#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif

#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif

#ifndef PR_GET_KEEPCAPS
#define PR_GET_KEEPCAPS 7
#endif

#ifndef PR_SET_KEEPCAPS
#define PR_SET_KEEPCAPS 8
#endif

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif

#ifndef PR_GET_NAME
#define PR_GET_NAME 16
#endif

#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif

#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif

#ifndef PR_SET_TSC
#define PR_SET_TSC 26
#endif

#ifndef PR_GET_TSC
#define PR_GET_TSC 25
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

#ifndef PR_GET_CHILD_SUBREAPER
#define PR_GET_CHILD_SUBREAPER 37
#endif

// ELF auxiliary vector types
typedef struct {
  uint32_t a_type;
  union {
    uint32_t a_val;
  } a_un;
} Elf32_auxv_t;

typedef struct {
  uint64_t a_type;
  union {
    uint64_t a_val;
  } a_un;
} Elf64_auxv_t;

// BPF maximum instructions
#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

// seccomp_data structure
#ifndef FEX_SECCOMP_DATA_DEFINED
#define FEX_SECCOMP_DATA_DEFINED
struct seccomp_data {
  int nr;
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t args[6];
};
#endif

// seccomp notification structures
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

// si_arch for siginfo
#define FEX_SI_ARCH(si) (0)

inline void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, ...) {
  errno = ENOSYS;
  return (void*)-1;  // MAP_FAILED
}

// macOS uses pthread or fork
// TODO(alpin): Implement this properly
#include <unistd.h>

// macOS uses pthread_mach_thread_np and pthread_self
#include <pthread.h>
inline pid_t gettid() {
  uint64_t tid;
  pthread_threadid_np(NULL, &tid);
  return (pid_t)tid;
}

// macOS uses pthread_kill
// For now, provide a stub that uses pthread_kill internally
// This won't work perfectly but allows compilation
// TODO(alpin): Implement this properly
inline int tgkill(pid_t tgid, pid_t tid, int sig) {
  // On macOS, we can't directly send signals to specific threads from outside
  errno = ENOSYS;
  return -1;
}

inline int prctl(int option, ...) {
  // Most prctl operations don't make sense on macOS
  // Return success for commonly used operations that can be safely ignored
  switch (option) {
    case PR_SET_NAME:
    case PR_GET_NAME:
    case PR_SET_DUMPABLE:
    case PR_GET_DUMPABLE:
    case PR_SET_NO_NEW_PRIVS:
    case PR_GET_NO_NEW_PRIVS:
      return 0;
    default:
      errno = EINVAL;
      return -1;
  }
}

// minimal stub
// On macOS, we use pthread_create or fork instead
// TODO(alpin): Implement this properly
#ifndef CLONE_VM
#define CLONE_VM             0x00000100
#define CLONE_FS             0x00000200
#define CLONE_FILES          0x00000400
#define CLONE_SIGHAND        0x00000800
#define CLONE_PTRACE         0x00002000
#define CLONE_VFORK          0x00004000
#define CLONE_PARENT         0x00008000
#define CLONE_THREAD         0x00010000
#define CLONE_NEWNS          0x00020000
#define CLONE_SYSVSEM        0x00040000
#define CLONE_SETTLS         0x00080000
#define CLONE_PARENT_SETTID  0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_DETACHED       0x00400000
#define CLONE_UNTRACED       0x00800000
#define CLONE_CHILD_SETTID   0x01000000
#define CLONE_NEWCGROUP      0x02000000
#define CLONE_NEWUTS         0x04000000
#define CLONE_NEWIPC         0x08000000
#define CLONE_NEWUSER        0x10000000
#define CLONE_NEWPID         0x20000000
#define CLONE_NEWNET         0x40000000
#define CLONE_IO             0x80000000
#define CLONE_CLEAR_SIGHAND  0x100000000ULL
#define CLONE_INTO_CGROUP    0x200000000ULL
#define CLONE_NEWTIME        0x00000080
#endif

// these three constants are needed even if CLONE_VM is already defined
// So we define them unconditionally on macOS
#if defined(__APPLE__)
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP   0x200000000ULL
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME       0x00000080
#endif
#endif

// no pipe2 on macOS, so we'll fallback to pipe
// HACK(alpin): this could become an issue, so marking this here for later
inline int pipe2(int pipefd[2], int flags) {
  if (pipe(pipefd) < 0) {
    return -1;
  }
  
  if (flags & O_NONBLOCK) {
    int fl0 = fcntl(pipefd[0], F_GETFL);
    int fl1 = fcntl(pipefd[1], F_GETFL);
    if (fl0 == -1 || fl1 == -1 || 
        fcntl(pipefd[0], F_SETFL, fl0 | O_NONBLOCK) == -1 ||
        fcntl(pipefd[1], F_SETFL, fl1 | O_NONBLOCK) == -1) {
      close(pipefd[0]);
      close(pipefd[1]);
      return -1;
    }
  }
  
  if (flags & O_CLOEXEC) {
    int fl0 = fcntl(pipefd[0], F_GETFD);
    int fl1 = fcntl(pipefd[1], F_GETFD);
    if (fl0 == -1 || fl1 == -1 || 
        fcntl(pipefd[0], F_SETFD, fl0 | FD_CLOEXEC) == -1 ||
        fcntl(pipefd[1], F_SETFD, fl1 | FD_CLOEXEC) == -1) {
      close(pipefd[0]);
      close(pipefd[1]);
      return -1;
    }
  }
  
  return 0;
}

#ifndef POLLRDHUP
#define POLLRDHUP 0x2000
#endif

// macOS has poll but not ppoll
inline int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
  int timeout_ms = -1;
  if (timeout_ts) {
    timeout_ms = timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000;
  }
  
  // TODO(alpin): sigmask is ignored on macOS; we should do something with sigprocmask
  (void)sigmask;
  
  return poll(fds, nfds, timeout_ms);
}

// multi-message header for sendmmsg/recvmmsg
struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int msg_len;
};

inline int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  (void)sockfd; (void)msgvec; (void)vlen; (void)flags;
  errno = ENOSYS;
  return -1;
}

inline int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
  (void)sockfd; (void)msgvec; (void)vlen; (void)flags; (void)timeout;
  errno = ENOSYS;
  return -1;
}

// msgbuf for msgsnd/msgrcv
struct msgbuf {
  long mtype;
  char mtext[1];
};

// IPC command constants
#ifndef IPC_RMID
#define IPC_RMID 0
#endif

#ifndef IPC_SET
#define IPC_SET 1
#endif

#ifndef IPC_STAT
#define IPC_STAT 2
#endif

#ifndef IPC_INFO
#define IPC_INFO 3
#endif

#ifndef MSG_STAT
#define MSG_STAT 11
#endif

#ifndef MSG_INFO
#define MSG_INFO 12
#endif

#ifndef SEM_INFO
#define SEM_INFO 19
#endif

#ifndef SEM_STAT
#define SEM_STAT 18
#endif

#ifndef SHM_STAT
#define SHM_STAT 13
#endif

#ifndef SHM_INFO
#define SHM_INFO 14
#endif

inline int sched_rr_get_interval(pid_t pid, struct timespec *tp) {
  (void)pid; (void)tp;
  errno = ENOSYS;
  return -1;
}

// futex constants for emulation
#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#endif

#ifndef FUTEX_WAKE
#define FUTEX_WAKE 1
#endif

#ifndef FUTEX_FD
#define FUTEX_FD 2
#endif

#ifndef FUTEX_REQUEUE
#define FUTEX_REQUEUE 3
#endif

#ifndef FUTEX_CMP_REQUEUE
#define FUTEX_CMP_REQUEUE 4
#endif

#ifndef FUTEX_WAKE_OP
#define FUTEX_WAKE_OP 5
#endif

#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI 6
#endif

#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI 7
#endif

#ifndef FUTEX_TRYLOCK_PI
#define FUTEX_TRYLOCK_PI 8
#endif

#ifndef FUTEX_WAIT_BITSET
#define FUTEX_WAIT_BITSET 9
#endif

#ifndef FUTEX_WAKE_BITSET
#define FUTEX_WAKE_BITSET 10
#endif

#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif

#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI 12
#endif

#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif

#ifndef FUTEX_CLOCK_REALTIME
#define FUTEX_CLOCK_REALTIME 256
#endif

#ifndef FUTEX_CMD_MASK
#define FUTEX_CMD_MASK ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)
#endif

// SHM lock/unlock constants
#ifndef SHM_LOCK
#define SHM_LOCK 11
#endif

#ifndef SHM_UNLOCK
#define SHM_UNLOCK 12
#endif

// macOS has some of these but with different values
// We need to use Linux values for syscall emulation
// Undef any macOS definitions first
#ifdef SO_PASSCRED
#undef SO_PASSCRED
#endif

#ifdef SO_PEERCRED
#undef SO_PEERCRED
#endif

#ifdef SO_SNDBUFFORCE
#undef SO_SNDBUFFORCE
#endif

#ifdef SO_RCVBUFFORCE
#undef SO_RCVBUFFORCE
#endif

#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33

// socket options that don't exist on macOS
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif

#ifndef SO_DETACH_FILTER
#define SO_DETACH_FILTER 27
#endif

#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#endif

#ifndef SO_NO_CHECK
#define SO_NO_CHECK 11
#endif

#ifndef SO_PRIORITY
#define SO_PRIORITY 12
#endif

#ifndef SO_BSDCOMPAT
#define SO_BSDCOMPAT 14
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

#ifndef SO_PROTOCOL
#define SO_PROTOCOL 38
#endif

#ifndef SO_DOMAIN
#define SO_DOMAIN 39
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

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

// CSIGNAL for clone
#ifndef CSIGNAL
#define CSIGNAL 0x000000ff
#endif

// Timer flags
#ifndef TIMER_ABSTIME
#define TIMER_ABSTIME 1
#endif

// Personality flags
#ifndef PER_LINUX
#define PER_LINUX 0x0000
#endif

#ifndef PER_LINUX32
#define PER_LINUX32 0x0008
#endif

#ifndef UNAME26
#define UNAME26 0x0020000
#endif

#ifndef PTRACE_PEEKTEXT
#define PTRACE_PEEKTEXT 1
#endif

#ifndef PTRACE_PEEKDATA
#define PTRACE_PEEKDATA 2
#endif

#ifndef PTRACE_POKETEXT
#define PTRACE_POKETEXT 4
#endif

#ifndef PTRACE_POKEDATA
#define PTRACE_POKEDATA 5
#endif

#ifndef PTRACE_ATTACH
#define PTRACE_ATTACH 16
#endif

#ifndef PTRACE_DETACH
#define PTRACE_DETACH 17
#endif

// macOS has adjtime but not adjtimex
inline int adjtimex(struct timex *buf) {
  (void)buf;
  errno = ENOSYS;
  return -1;
}

inline int clock_adjtime(clockid_t clk_id, struct timex *buf) {
  (void)clk_id; (void)buf;
  errno = ENOSYS;
  return -1;
}

// SOCK_NONBLOCK and SOCK_CLOEXEC flags for socket functions
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 04000
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif

// no accept4 on macOS, so we'll fallback to accept
inline int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  int fd = accept(sockfd, addr, addrlen);
  if (fd < 0) {
    return fd;
  }

  if (flags & SOCK_NONBLOCK) {
    int fl = fcntl(fd, F_GETFL);
    if (fl == -1 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
      close(fd);
      return -1;
    }
  }

  if (flags & SOCK_CLOEXEC) {
    int fl = fcntl(fd, F_GETFD);
    if (fl == -1 || fcntl(fd, F_SETFD, fl | FD_CLOEXEC) == -1) {
      close(fd);
      return -1;
    }
  }
  
  return fd;
}

// no dup3 on macOS, so we'll fallback to dup2
inline int dup3(int oldfd, int newfd, int flags) {
  if (oldfd == newfd) {
    errno = EINVAL;
    return -1;
  }
  
  int result = dup2(oldfd, newfd);
  if (result < 0) {
    return result;
  }

  if (flags & O_CLOEXEC) {
    int fl = fcntl(newfd, F_GETFD);
    if (fl == -1 || fcntl(newfd, F_SETFD, fl | FD_CLOEXEC) == -1) {
      close(newfd);
      return -1;
    }
  }
  
  return result;
}

struct inotify_event {
  int wd;
  uint32_t mask;
  uint32_t cookie;
  uint32_t len;
  char name[];
};

#define IN_ACCESS        0x00000001
#define IN_MODIFY        0x00000002
#define IN_ATTRIB        0x00000004
#define IN_CLOSE_WRITE   0x00000008
#define IN_CLOSE_NOWRITE 0x00000010
#define IN_OPEN          0x00000020
#define IN_MOVED_FROM    0x00000040
#define IN_MOVED_TO      0x00000080
#define IN_CREATE        0x00000100
#define IN_DELETE        0x00000200
#define IN_DELETE_SELF   0x00000400
#define IN_MOVE_SELF     0x00000800

// inotify_init flags
#ifndef IN_NONBLOCK
#define IN_NONBLOCK 0x00008000
#endif

#ifndef IN_CLOEXEC
#define IN_CLOEXEC 0x02000000
#endif

// POSIX_FADV constants
#ifndef POSIX_FADV_NORMAL
#define POSIX_FADV_NORMAL 0
#endif

#ifndef POSIX_FADV_RANDOM
#define POSIX_FADV_RANDOM 1
#endif

#ifndef POSIX_FADV_SEQUENTIAL
#define POSIX_FADV_SEQUENTIAL 2
#endif

#ifndef POSIX_FADV_WILLNEED
#define POSIX_FADV_WILLNEED 3
#endif

#ifndef POSIX_FADV_DONTNEED
#define POSIX_FADV_DONTNEED 4
#endif

#ifndef POSIX_FADV_NOREUSE
#define POSIX_FADV_NOREUSE 5
#endif

// stub
inline int inotify_init() {
  errno = ENOSYS;
  return -1;
}

// stub
inline int inotify_init1(int flags) {
  (void)flags;
  errno = ENOSYS;
  return -1;
}

// stub
inline int inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
  (void)fd; (void)pathname; (void)mask;
  errno = ENOSYS;
  return -1;
}

// stub
inline int inotify_rm_watch(int fd, int wd) {
  (void)fd; (void)wd;
  errno = ENOSYS;
  return -1;
}

// no execvpe on macOS, so we'll fallback to execve
inline int execvpe(const char *file, char *const argv[], char *const envp[]) {
  extern char **environ;
  char **old_environ = environ;
  environ = const_cast<char**>(envp);
  int result = execve(file, argv, envp);
  environ = old_environ;
  return result;
}

// macOS has fsync but not fdatasync, use fsync as fallback
inline int fdatasync(int fd) {
  return fsync(fd);
}

// no getrandom on macOS, so we'll fallback to /dev/urandom
#include <sys/stat.h>
inline ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
  (void)flags; // GRND_NONBLOCK, GRND_RANDOM flags ignored
  static int urandom_fd = -1;
  
  if (urandom_fd == -1) {
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
      errno = ENOSYS;
      return -1;
    }
  }
  
  ssize_t result = read(urandom_fd, buf, buflen);
  return result;
}

// Linux ioctl macros
#ifndef _IOC_DIRSHIFT
#define _IOC_DIRSHIFT 30
#define _IOC_TYPESHIFT 8
#define _IOC_NRSHIFT 0
#define _IOC_SIZESHIFT 16
#define _IOC_DIRBITS 2
#define _IOC_TYPEBITS 8
#define _IOC_NRBITS 8
#define _IOC_SIZEBITS 14
#define _IOC_DIRMASK ((1 << _IOC_DIRBITS) - 1)
#define _IOC_TYPEMASK ((1 << _IOC_TYPEBITS) - 1)
#define _IOC_NRMASK ((1 << _IOC_NRBITS) - 1)
#define _IOC_SIZEMASK ((1 << _IOC_SIZEBITS) - 1)
#define _IOC_DIR(nr) (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr) (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr) (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr) (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)
#endif

#endif // __APPLE__
