// SPDX-License-Identifier: MIT
#pragma once

#ifdef __APPLE__

#include <stdint.h>

struct open_how {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};

// resolve flags
#define RESOLVE_NO_XDEV       0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS   0x04
#define RESOLVE_BENEATH       0x08
#define RESOLVE_IN_ROOT       0x10
#define RESOLVE_CACHED        0x20

#endif // __APPLE__
