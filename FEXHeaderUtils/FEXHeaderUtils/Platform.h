// SPDX-License-Identifier: MIT
#pragma once

#if defined(__APPLE__)
#define FEX_PLATFORM_MACOS 1
#define FEX_PLATFORM_LINUX 0
#define FEX_PLATFORM_WINDOWS 0
#elif defined(_WIN32)
#define FEX_PLATFORM_MACOS 0
#define FEX_PLATFORM_LINUX 0
#define FEX_PLATFORM_WINDOWS 1
#else
#define FEX_PLATFORM_MACOS 0
#define FEX_PLATFORM_LINUX 1
#define FEX_PLATFORM_WINDOWS 0
#endif

#if FEX_PLATFORM_MACOS
#include <limits.h>
#include <sys/syslimits.h>
#else
#include <linux/limits.h>
#endif

// MAP_FIXED_NOREPLACE is Linux 4.17+
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// MAP_NORESERVE may not exist on all platforms
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

// MADV_HUGEPAGE is Linux-specific
#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 0
#endif

// MADV_DONTNEED behavior differs between platforms
// On macOS it's called MADV_FREE for similar behavior
#if FEX_PLATFORM_MACOS && !defined(MADV_DONTNEED)
#define MADV_DONTNEED MADV_FREE
#endif
