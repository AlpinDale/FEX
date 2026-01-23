// SPDX-License-Identifier: MIT
#pragma once

#include <sys/mman.h>

#ifdef __APPLE__

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

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

#ifndef MAP_32BIT
#define MAP_32BIT 0x40
#endif

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif

#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif

#ifndef MADV_DODUMP
#define MADV_DODUMP 17
#endif

#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif

#ifndef MADV_KEEPONFORK
#define MADV_KEEPONFORK 19
#endif

#ifndef MADV_COLD
#define MADV_COLD 20
#endif

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

#ifndef MADV_HWPOISON
#define MADV_HWPOISON 100
#endif

#ifndef MADV_SOFT_OFFLINE
#define MADV_SOFT_OFFLINE 101
#endif

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#endif // __APPLE__
