// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/fmt.h>

#include <fcntl.h>
#ifdef __APPLE__
#include <limits.h>
#include <sys/param.h>
#else
#include <linux/limits.h>
#endif
#include <unistd.h>

namespace FEX {

[[nodiscard]]
inline int get_fdpath(int fd, char* SymlinkPath) {
#ifdef __APPLE__
  // macOS: use fcntl with F_GETPATH to get the file path
  if (fcntl(fd, F_GETPATH, SymlinkPath) == -1) {
    return -1;
  }
  return strlen(SymlinkPath);
#else
  auto Path = fextl::fmt::format("/proc/self/fd/{}", fd);
  return readlinkat(AT_FDCWD, Path.c_str(), SymlinkPath, PATH_MAX);
#endif
}

} // namespace FEX
