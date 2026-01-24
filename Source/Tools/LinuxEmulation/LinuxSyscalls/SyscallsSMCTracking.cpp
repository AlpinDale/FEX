// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: SMC/MMan Tracking
$end_info$
*/

#include <Common/Config.h>
#include "Common/FDUtils.h"
#include "Common/FEXServerClient.h"
#include "Common/FileMappingBaseAddress.h"

#include <filesystem>
#include <sys/file.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include "LinuxSyscalls/LinuxCompat.h"
#else
#include <sys/personality.h>
#include <sys/shm.h>
#endif

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/LinuxAllocator.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXHeaderUtils/Filesystem.h>
#include <Linux/Utils/ELFParser.h>

namespace FEX::HLE {
// SMC interactions
bool SyscallHandler::HandleSegfault(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  const auto FaultAddress = (uintptr_t)((siginfo_t*)info)->si_addr;

  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  auto CallRetStackInfo = ThreadObject->GetCallRetStackInfo();
  if (FaultAddress >= CallRetStackInfo.AllocationBase && FaultAddress < CallRetStackInfo.AllocationEnd) {
    // Reset REG_CALLRET_SP to the default location to allow for underflows/overflows
    ArchHelpers::Context::SetArmReg(ucontext, 25, CallRetStackInfo.DefaultLocation);
    return true;
  }

  {
    // Can't use the deferred signal lock in the SIGSEGV handler.
    auto lk = FEXCore::MaskSignalsAndLockMutex<std::shared_lock>(_SyscallHandler->VMATracking.Mutex);

    auto VMATracking = &_SyscallHandler->VMATracking;

    // If the write spans two pages, they will be flushed one at a time (generating two faults)
    auto Entry = VMATracking->FindVMAEntry(FaultAddress);

    // If an untracked address, or the mapping wasn't writable, it can't be handled here
    if (Entry == VMATracking->VMAs.end() || !Entry->second.Prot.Writable) {
      return false;
    }

    auto FaultBase = FEXCore::AlignDown(FaultAddress, FEXCore::Utils::FEX_PAGE_SIZE);

    auto UnprotectRegionCallback = [](uintptr_t Start, uintptr_t Length) {
      auto rv = mprotect((void*)Start, Length, PROT_READ | PROT_WRITE);
      LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", Start, Length);
    };

    if (Entry->second.Flags.Shared) {
      LOGMAN_THROW_A_FMT(Entry->second.Resource, "VMA tracking error");

      auto Offset = FaultBase - Entry->first + Entry->second.Offset;

      auto VMA = Entry->second.Resource->FirstVMA;
      LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

      // Flush all mirrors, remap the page writable as needed
      do {
        if (VMA->Offset <= Offset && (VMA->Offset + VMA->Length) > Offset) {
          auto FaultBaseMirrored = Offset - VMA->Offset + VMA->Base;

          if (VMA->Prot.Writable) {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
          } else {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE);
          }
        }
      } while ((VMA = VMA->ResourceNextVMA));
    } else {
      _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBase, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);

    auto CTX = Thread->CTX;
    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext)) && !CTX->IsCurrentBlockSingleInst(Thread) &&
        CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
      // If we are not in a single-instruction block, and the SMC write address could intersect with the current block,
      // reconstruct the context and repeat the faulting instruction as a single-instruction block so any SMC it performs
      // is immediately picked up.
      ThreadObject->SignalInfo.Delegator->SpillSRA(Thread, ucontext, Thread->CurrentFrame->InSyscallInfo & 0xFFFF);

      // Adjust context to return to the dispatcher, reloading SRA from thread state
      const auto& Config = ThreadObject->SignalInfo.Delegator->GetConfig();
      ArchHelpers::Context::SetPc(ucontext, Config.AbsoluteLoopTopAddressFillSRA);
      ArchHelpers::Context::SetArmReg(ucontext, 1, 1); // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
    }

    return true;
  }
}

void SyscallHandler::MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  const auto Base = Start & FEXCore::Utils::FEX_PAGE_MASK;
  const auto Top = FEXCore::AlignUp(Start + Length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    if (SMCChecks != FEXCore::Config::CONFIG_SMC_MTRACK) {
      return;
    }

    auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

    // Find the first mapping at or after the range ends, or ::end().
    // Top points to the address after the end of the range
    auto Mapping = VMATracking.VMAs.lower_bound(Top);

    while (Mapping != VMATracking.VMAs.begin()) {
      Mapping--;

      const auto MapBase = Mapping->first;
      const auto MapTop = MapBase + Mapping->second.Length;

      if (MapTop <= Base) {
        // Mapping ends before the Range start, exit
        break;
      } else {
        const auto ProtectBase = std::max(MapBase, Base);
        const auto ProtectSize = std::min(MapTop, Top) - ProtectBase;

        if (Mapping->second.Flags.Shared) {
          LOGMAN_THROW_A_FMT(Mapping->second.Resource, "VMA tracking error");

          const auto OffsetBase = ProtectBase - Mapping->first + Mapping->second.Offset;
          const auto OffsetTop = OffsetBase + ProtectSize;

          auto VMA = Mapping->second.Resource->FirstVMA;
          LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

#ifndef __APPLE__
          // On macOS, MAP_JIT memory cannot have its protection changed with mprotect.
          // SMC tracking via mprotect is not supported on macOS.
          do {
            auto VMAOffsetBase = VMA->Offset;
            auto VMAOffsetTop = VMA->Offset + VMA->Length;
            auto VMABase = VMA->Base;

            if (VMA->Prot.Writable && VMAOffsetBase < OffsetTop && VMAOffsetTop > OffsetBase) {

              const auto MirroredBase = std::max(VMAOffsetBase, OffsetBase);
              const auto MirroredSize = std::min(OffsetTop, VMAOffsetTop) - MirroredBase;

              auto rv = mprotect((void*)(MirroredBase - VMAOffsetBase + VMABase), MirroredSize, PROT_READ);
              LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", MirroredBase, MirroredSize);
            }
          } while ((VMA = VMA->ResourceNextVMA));
#else
          (void)VMA;
          (void)OffsetBase;
          (void)OffsetTop;
#endif

        } else if (Mapping->second.Prot.Writable) {
#ifndef __APPLE__
          // On macOS, MAP_JIT memory cannot have its protection changed with mprotect.
          // SMC tracking via mprotect is not supported on macOS.
          int rv = mprotect((void*)ProtectBase, ProtectSize, PROT_READ);

          LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", ProtectBase, ProtectSize);
#else
          (void)ProtectBase;
          (void)ProtectSize;
#endif
        }
      }
    }
  }
}

void SyscallHandler::InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  InvalidateCodeRangeIfNecessary(Thread, Start, Length);
}

static FEXCore::ExecutableFileSectionInfo BuildSectionInfo(const VMATracking::MappedResource& Resource, uint64_t Base, uint64_t Size) {
  return FEXCore::ExecutableFileSectionInfo {*Resource.MappedFile, Resource.FirstVMA->Base, Base, Base + Size};
}

std::optional<FEXCore::ExecutableFileSectionInfo>
SyscallHandler::LookupExecutableFileSection(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

  auto EntryIt = VMATracking.FindVMAEntry(GuestAddr);
  if (EntryIt == VMATracking.VMAs.end() || !EntryIt->second.Resource || !EntryIt->second.Resource->MappedFile) {
    return std::nullopt;
  }

  auto& [MappingBaseAddr, Entry] = *EntryIt;
  return BuildSectionInfo(*Entry.Resource, MappingBaseAddr, Entry.Length);
}

FEXCore::HLE::ExecutableRangeInfo SyscallHandler::QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);

  auto Entry = VMATracking.FindVMAEntry(Address);
  if (Entry == VMATracking.VMAs.end() ||
      (!Entry->second.Prot.Executable && (!(ThreadObject->persona & READ_IMPLIES_EXEC) || !Entry->second.Prot.Readable))) {
    return {0, 0, false};
  }
  return {Entry->first, Entry->second.Length, Entry->second.Prot.Writable};
}

static fextl::vector<Elf64_Phdr> ReadELFHeaders(int FD, std::span<std::byte> HeaderData = {}) {
  std::string_view ELFMagic = ELFMAG;
  if (HeaderData.data()) {
    if (HeaderData.size_bytes() < ELFMagic.size() || std::memcmp(ELFMagic.data(), HeaderData.data(), ELFMagic.size()) != 0) {
      // Not an ELF file
      return {};
    }
  } else {
    // Read from FD in case the caller didn't have a mapped header available
  }

  ELFParser Parser;
  Parser.ReadElf(dup(FD));
  return std::move(Parser.phdrs);
}

static void LoadCodeCache(FEXCore::Core::InternalThreadState& Thread, FEXCore::ExecutableFileSectionInfo& Section, uint64_t CodeCacheConfigId) {
  auto CacheFilename = fextl::fmt::format("{}cache/{}-{:016x}", FEX::Config::GetCacheDirectory(),
                                          FEXCore::CodeMap::GetBaseFilename(Section.FileInfo, false), CodeCacheConfigId);
  int CacheFD = open(CacheFilename.c_str(), O_RDONLY);
  if (CacheFD == -1) {
    LogMan::Msg::IFmt("Cache file does not exist: {}", CacheFilename);
    return;
  }

  struct stat buf;
  if (fstat(CacheFD, &buf) != 0) {
    LogMan::Msg::EFmt("Invalid cache file: {}", CacheFilename);
    close(CacheFD);
    return;
  }

  auto CacheFileSize = buf.st_size;
  auto MappedCache = (std::byte*)FEXCore::Allocator::mmap(nullptr, CacheFileSize, PROT_READ, MAP_PRIVATE, CacheFD, 0);
  LOGMAN_THROW_A_FMT(MappedCache, "Failed to map code cache into memory");
  if (!Thread.CTX->GetCodeCache().LoadData(&Thread, MappedCache, Section)) {
    // TODO: Delete this cache file
  }
  FEXCore::Allocator::munmap(MappedCache, CacheFileSize);
  close(CacheFD);
}

void* SyscallHandler::GuestMmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, int flags,
                                int fd, off_t offset) {
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  std::optional<LateApplyExtendedVolatileMetadata> LateMetadata = std::nullopt;

  std::optional<FEXCore::ExecutableFileSectionInfo> CachedSection;

  {
    // NOTE: Frontend calls this with a nullptr Thread during initialization, but
    //       providing this code with a valid Thread object earlier would allow
    //       us to be more optimal by using GuardSignalDeferringSection instead
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

#ifdef __APPLE__
    // On macOS, filter out Linux-specific flags BEFORE checking for MAP_32BIT
    // because some Linux flags (like MAP_NORESERVE=0x4000) may have different values
    // that conflict with X86_64_MAP_32BIT on macOS (where MAP_NORESERVE=0x40).
    // The flags value here uses Linux definitions from LinuxCompat.h.
    int filtered_flags = flags;
    filtered_flags &= ~MAP_GROWSDOWN;  // Linux 0x0100
    filtered_flags &= ~MAP_NORESERVE;  // Linux 0x4000 (note: macOS MAP_NORESERVE is 0x40!)
    filtered_flags &= ~MAP_STACK;      // Linux 0x20000
    bool Map32Bit = !Is64Bit || (filtered_flags & FEX::HLE::X86_64_MAP_32BIT);
#else
    bool Map32Bit = !Is64Bit || (flags & FEX::HLE::X86_64_MAP_32BIT);
#endif
    LogMan::Msg::DFmt("GuestMmap: addr=0x{:x} len=0x{:x} prot=0x{:x} flags=0x{:x} Is64Bit={} Map32Bit={}",
                      reinterpret_cast<uint64_t>(addr), length, prot, flags, Is64Bit, Map32Bit);
    if (Map32Bit) {
      Result = (uint64_t)Get32BitAllocator()->Mmap((void*)addr, length, prot, flags, fd, offset);
      LogMan::Msg::DFmt("32bit mmap result: 0x{:x}", Result);
      if (FEX::HLE::HasSyscallError(Result)) {
        return reinterpret_cast<void*>(Result);
      }
      LOGMAN_THROW_A_FMT(Is64Bit || (Result >> 32) == 0 || (Result >> 32) == 0xFFFFFFFF, "values must fit to 32 bits");
    } else {
#ifdef __APPLE__
      // On macOS, executable memory requires MAP_JIT flag, but MAP_JIT is incompatible with MAP_FIXED.
      // For executable mappings, we must remove MAP_FIXED and let macOS choose the address.
      // Also filter out Linux-specific flags that macOS doesn't understand.
      int macos_flags = flags;

      // Translate Linux mmap flags to macOS flags
      // The incoming flags may use Linux definitions (from guest syscalls via ELF loader)
      // or macOS definitions (from internal FEX code).
      //
      // Key differences:
      // - Linux MAP_ANONYMOUS = 0x20, macOS MAP_ANONYMOUS = 0x1000
      // - Linux MAP_DENYWRITE = 0x0800, macOS MAP_JIT = 0x0800 (CONFLICT!)
      // - Linux MAP_EXECUTABLE = 0x1000 = macOS MAP_ANONYMOUS (CONFLICT!)
      // - Linux MAP_GROWSDOWN = 0x0100, MAP_STACK = 0x20000, etc. (not on macOS)

      constexpr int LINUX_MAP_ANONYMOUS = 0x20;
      constexpr int LINUX_MAP_GROWSDOWN = 0x0100;
      constexpr int LINUX_MAP_DENYWRITE = 0x0800;
      // Note: LINUX_MAP_EXECUTABLE = 0x1000 = macOS MAP_ANONYMOUS, so we can't blindly remove it
      constexpr int LINUX_MAP_LOCKED = 0x2000;
      constexpr int LINUX_MAP_NORESERVE = 0x4000;
      constexpr int LINUX_MAP_POPULATE = 0x8000;
      constexpr int LINUX_MAP_NONBLOCK = 0x10000;
      constexpr int LINUX_MAP_STACK = 0x20000;
      constexpr int LINUX_MAP_HUGETLB = 0x40000;

      // Check if this looks like Linux flags (has Linux MAP_ANONYMOUS = 0x20 set)
      bool has_linux_anonymous = (macos_flags & LINUX_MAP_ANONYMOUS) != 0;

      // Build translated flags
      int translated_flags = macos_flags;

      // If using Linux MAP_ANONYMOUS (0x20), convert to macOS MAP_ANONYMOUS (0x1000)
      // Also: If Linux MAP_ANONYMOUS is set, then 0x1000 means LINUX_MAP_EXECUTABLE, not macOS MAP_ANONYMOUS
      if (has_linux_anonymous) {
        translated_flags &= ~LINUX_MAP_ANONYMOUS;
        translated_flags |= MAP_ANONYMOUS;
        // In this case, 0x1000 (if present) is Linux MAP_EXECUTABLE, remove it
        translated_flags &= ~0x1000;  // Remove LINUX_MAP_EXECUTABLE
        translated_flags |= MAP_ANONYMOUS; // Re-add macOS MAP_ANONYMOUS
      }
      // If Linux MAP_ANONYMOUS (0x20) is NOT set, then 0x1000 is macOS MAP_ANONYMOUS - keep it

      // Remove Linux-specific flags that conflict with or don't exist on macOS
      translated_flags &= ~LINUX_MAP_GROWSDOWN;
      translated_flags &= ~LINUX_MAP_DENYWRITE;   // Conflicts with macOS MAP_JIT!
      translated_flags &= ~LINUX_MAP_LOCKED;
      translated_flags &= ~LINUX_MAP_NORESERVE;
      translated_flags &= ~LINUX_MAP_POPULATE;
      translated_flags &= ~LINUX_MAP_NONBLOCK;
      translated_flags &= ~LINUX_MAP_STACK;
      translated_flags &= ~LINUX_MAP_HUGETLB;

      macos_flags = translated_flags;

      // Only use MAP_JIT for anonymous executable mappings (JIT code).
      // File-backed executable mappings (loading ELF files) can use regular mmap + mprotect.
      bool is_anonymous = (macos_flags & MAP_ANONYMOUS) != 0;
      bool needs_exec = (prot & PROT_EXEC) != 0;
      bool needs_jit = is_anonymous && needs_exec;

      if (needs_jit) {
        macos_flags |= MAP_JIT;
        macos_flags &= ~MAP_FIXED; // MAP_JIT cannot be combined with MAP_FIXED
      }

      // macOS ARM64 uses 16KB pages, but Linux ELF files have 4KB-aligned sections.
      // We need to handle file-backed mappings with non-16KB-aligned offsets by using
      // anonymous memory + pread instead of direct file mapping.
      constexpr size_t MACOS_PAGE_SIZE = 16384;  // 16KB
      bool offset_needs_workaround = (fd >= 0) && ((offset % MACOS_PAGE_SIZE) != 0);

      // Check if address also needs alignment workaround
      uintptr_t requested_addr = reinterpret_cast<uintptr_t>(addr);
      bool addr_needs_alignment = (requested_addr != 0) && ((requested_addr % MACOS_PAGE_SIZE) != 0);

      if (offset_needs_workaround || addr_needs_alignment) {
        // Either offset or address is not 16KB-aligned.
        // We need to:
        // 1. Round down the address to 16KB boundary
        // 2. Calculate the padding needed
        // 3. Allocate at the aligned address with extra size
        // 4. Read file data at the correct offset within the allocation

        uintptr_t aligned_addr = requested_addr & ~(MACOS_PAGE_SIZE - 1);  // Round down to 16KB
        size_t addr_padding = requested_addr - aligned_addr;
        size_t aligned_length = length + addr_padding;
        // Round up length to 16KB boundary
        aligned_length = (aligned_length + MACOS_PAGE_SIZE - 1) & ~(MACOS_PAGE_SIZE - 1);

        // Keep MAP_FIXED if originally requested, just change to anonymous
        int anon_flags = macos_flags | MAP_ANONYMOUS;
        int alloc_prot = PROT_READ | PROT_WRITE;  // Need write to copy data

        Result = reinterpret_cast<uint64_t>(::mmap(reinterpret_cast<void*>(aligned_addr), aligned_length, alloc_prot, anon_flags, -1, 0));

        if (Result != ~0ULL) {
          // Read file data at the correct offset within the allocation
          if (fd >= 0) {
            ssize_t bytes_read = ::pread(fd, reinterpret_cast<void*>(Result + addr_padding), length, offset);
            if (bytes_read < 0) {
              int saved_errno = errno;
              LogMan::Msg::EFmt("GuestMmap: pread failed: {}", strerror(saved_errno));
              ::munmap(reinterpret_cast<void*>(Result), aligned_length);
              return reinterpret_cast<void*>(-saved_errno);
            }
          }

          // Set the correct protection for the entire aligned region
          if (prot != alloc_prot) {
            if (::mprotect(reinterpret_cast<void*>(Result), aligned_length, prot) != 0) {
              int saved_errno = errno;
              LogMan::Msg::EFmt("GuestMmap: mprotect failed: {}", strerror(saved_errno));
              ::munmap(reinterpret_cast<void*>(Result), aligned_length);
              return reinterpret_cast<void*>(-saved_errno);
            }
          }

          // Return the address the caller requested (may be in the middle of the allocation)
          Result = Result + addr_padding;
        }
      } else if (!needs_jit && needs_exec && fd >= 0) {
        // For file-backed executable mappings, map as RW first, then mprotect to RX
        // This works around macOS restrictions on directly mapping executable memory from files
        int initial_prot = (prot & ~PROT_EXEC) | PROT_WRITE;
        Result = reinterpret_cast<uint64_t>(::mmap(reinterpret_cast<void*>(addr), length, initial_prot, macos_flags, fd, offset));
        if (Result != ~0ULL) {
          // Now change protection to the requested executable permission
          if (::mprotect(reinterpret_cast<void*>(Result), length, prot) != 0) {
            int saved_errno = errno;
            LogMan::Msg::EFmt("mprotect to RX failed: {}", strerror(saved_errno));
            ::munmap(reinterpret_cast<void*>(Result), length);
            return reinterpret_cast<void*>(-saved_errno);
          }
        }
      } else {
        Result = reinterpret_cast<uint64_t>(::mmap(reinterpret_cast<void*>(addr), length, prot, macos_flags, fd, offset));
      }
      if (Result == ~0ULL) {
        int saved_errno = errno;
        LogMan::Msg::EFmt("mmap failed at 0x{:x}, size 0x{:x}, prot 0x{:x}, flags 0x{:x}: {}", reinterpret_cast<uint64_t>(addr), length,
                          prot, macos_flags, strerror(saved_errno));
        return reinterpret_cast<void*>(-saved_errno);
      }
      LogMan::Msg::DFmt("mmap(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}) -> 0x{:x}", reinterpret_cast<uint64_t>(addr), length, prot, macos_flags, Result);
      // Note: With MAP_JIT, the actual address may differ from the requested address
#else
      Result = reinterpret_cast<uint64_t>(::mmap(reinterpret_cast<void*>(addr), length, prot, flags, fd, offset));
      if (Result == ~0ULL) {
        return reinterpret_cast<void*>(-errno);
      }
#endif
    }

    LateMetadata = TrackMmap(Thread, Result, length, prot, flags, fd, offset, CachedSection);
  }

  InvalidateCodeRangeIfNecessary(Thread, Result, Size);

  if (LateMetadata) {
    auto CodeInvalidationlk = GuardSignalDeferringSectionWithFallback(CTX->GetCodeInvalidationMutex(), Thread);
    CTX->AddForceTSOInformation(LateMetadata->VolatileValidRanges, std::move(LateMetadata->VolatileInstructions));
  }

  if (EnableCodeCaching && CachedSection) {
    LoadCodeCache(*Thread, *CachedSection, CodeCacheConfigId);
  }

  return reinterpret_cast<void*>(Result);
}

uint64_t SyscallHandler::GuestMunmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, uint64_t length) {
  LOGMAN_THROW_A_FMT(Is64Bit || (reinterpret_cast<uintptr_t>(addr) >> 32) == 0, "values must fit to 32 bits: {}", fmt::ptr(addr));
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    // Frontend calls this with nullptr Thread during initialization.
    // This is why `GuardSignalDeferringSectionWithFallback` is used here.
    // To be more optimal the frontend should provide this code with a valid Thread object earlier.
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

    if (reinterpret_cast<uintptr_t>(addr) < 0x1'0000'0000ULL) {
      Result = Get32BitAllocator()->Munmap(addr, length);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    } else {
      Result = ::munmap(addr, length);
      if (Result == -1) {
        return -errno;
      }
    }
    TrackMunmap(Thread, addr, length);
  }
  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), Size);

  if (length) {
    auto CodeInvalidationlk = GuardSignalDeferringSectionWithFallback(CTX->GetCodeInvalidationMutex(), Thread);
    CTX->RemoveForceTSOInformation(reinterpret_cast<uint64_t>(addr), length);
  }

  return Result;
}

uint64_t SyscallHandler::GuestMremap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* old_address, size_t old_size,
                                     size_t new_size, int flags, void* new_address) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::mremap(old_address, old_size, new_size, flags, new_address));
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result = reinterpret_cast<uint64_t>(Get32BitAllocator()->Mremap(old_address, old_size, new_size, flags, new_address));
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }
    TrackMremap(Thread, reinterpret_cast<uint64_t>(old_address), old_size, new_size, flags, Result);
  }

  InvalidateCodeRangeIfNecessaryOnRemap(Thread, reinterpret_cast<uint64_t>(old_address), Result, old_size, new_size);
  return Result;
}

int SyscallHandler::OpenCodeMapFile() {
  // Query from FEXServer whether this is the first instance of this executable; if it is, also enable code dumping!
  FEX_CONFIG_OPT(RootFSPath, ROOTFS);
  FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
  auto ProgramName = FEXCore::Config::Get(FEXCore::Config::CONFIG_APP_FILENAME);
  LOGMAN_THROW_A_FMT(ProgramName && ProgramName.value()->c_str()[0] == '/', "");

  // Check RootFS first, then the plain path
  auto ProgramFD = open((RootFSPath() + ProgramName.value()->c_str()).c_str(), O_RDONLY);
  if (ProgramFD == -1) {
    ProgramFD = open(ProgramName.value()->c_str(), O_RDONLY);
  }
  if (ProgramFD == -1) {
    return -1;
  }

  int CodeMapFD = FEXServerClient::RequestCodeMapFD(FEXServerClient::GetServerFD(), ProgramFD, Multiblock);
  close(ProgramFD);
  if (CodeMapFD == -1) {
    return -1;
  }

  // Acquire exclusive lock to prevent FEXServer from processing this file eagerly
  [[maybe_unused]] auto ret = flock(CodeMapFD, LOCK_EX);
  LOGMAN_THROW_A_FMT(ret == 0, "Could not lock code map");

  FM.SetProtectedCodeMapFD(CodeMapFD);

  // Ensure the file descriptor is closed on exec
  auto flags = fcntl(CodeMapFD, F_GETFD);
  fcntl(CodeMapFD, F_SETFD, flags | FD_CLOEXEC);
  return CodeMapFD;
}

uint64_t SyscallHandler::GuestMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    Result = ::mprotect(addr, len, prot);
    if (Result == -1) {
      return -errno;
    }

    TrackMprotect(Thread, addr, len, prot);
  }

  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), len);
  return Result;
}

uint64_t SyscallHandler::GuestShmat(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, int shmid, const void* shmaddr, int shmflg) {
  uint64_t Result {};
  uint64_t Length {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::shmat(shmid, shmaddr, shmflg));
      if (Result == -1) {
        return -errno;
      }
    } else {
      uint32_t Addr;
      Result = Get32BitAllocator()->Shmat(shmid, shmaddr, shmflg, &Addr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
      Result = Addr;
    }

    shmid_ds stat;

    auto res = shmctl(shmid, IPC_STAT, &stat);
    LOGMAN_THROW_A_FMT(res != -1, "shmctl IPC_STAT failed");

    Length = stat.shm_segsz;
    TrackShmat(Thread, shmid, Result, shmflg, Length);
  }

  InvalidateCodeRangeIfNecessary(Thread, Result, Length);
  return Result;
}

uint64_t SyscallHandler::GuestShmdt(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, const void* shmaddr) {
  uint64_t Result {};
  uint64_t Length {};
  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = ::shmdt(shmaddr);
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result = Get32BitAllocator()->Shmdt(shmaddr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }

    Length = TrackShmdt(Thread, reinterpret_cast<uintptr_t>(shmaddr));
  }

  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uintptr_t>(shmaddr), Length);
  return Result;
}

// MMan Tracking
std::optional<SyscallHandler::LateApplyExtendedVolatileMetadata>
SyscallHandler::TrackMmap(FEXCore::Core::InternalThreadState* Thread, uint64_t addr, size_t length, int prot, int flags, int fd,
                          off_t offset, std::optional<FEXCore::ExecutableFileSectionInfo>& CachedSection) {
  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  const auto ProtMapping = VMATracking::VMAProt::fromProt(prot);

  VMATracking::MappedResource* Resource = nullptr;

  std::optional<SyscallHandler::LateApplyExtendedVolatileMetadata> VolatileMetadata = std::nullopt;

  if (!(flags & MAP_ANONYMOUS)) {
    struct stat64 buf;
    fstat64(fd, &buf);

    const VMATracking::MRID mrid {static_cast<uint64_t>(buf.st_dev), static_cast<uint64_t>(buf.st_ino)};

    char Tmp[PATH_MAX];
    auto PathLength = FEX::get_fdpath(fd, Tmp);

    auto [ResourceIt, ResourceEnd] = VMATracking.FindResources(mrid);
    bool Inserted = false;
    const bool MappedELFHeaderAgain = ResourceIt != ResourceEnd && offset == 0 && !ResourceIt->second.ProgramHeaders.empty();
    if (ResourceIt == ResourceEnd || MappedELFHeaderAgain) {
      // Create a new MappedResource for previously unseen file and for re-mappings of an ELF header
      ResourceIt = VMATracking.InsertMappedResource(mrid, {nullptr, nullptr, 0});
      ResourceIt->second.Iterator = ResourceIt;
      Inserted = true;
    }
    Resource = &ResourceIt->second;

    // Only handle FDs that are backed by regular files that are executable
    if (PathLength != -1 && S_ISREG(buf.st_mode) && (buf.st_mode & S_IXUSR)) {
      // ELF files that are mapped multiple times get a separate MappedResource for each base virtual address
      if (Inserted) {
        Resource->MappedFile = fextl::make_unique<FEXCore::ExecutableFileInfo>();
        Resource->MappedFile->Filename = fextl::string(Tmp, PathLength);
        Resource->MappedFile->FileId = CTX->GetCodeCache().ComputeCodeMapId(Resource->MappedFile->Filename, fd);

        // Read ELF headers if applicable.
        // For performance, skip ELF checks if we're not mapping the file header
        bool CheckForElfFile = (offset == 0);
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
        CheckForElfFile = true;
#endif
        if (CheckForElfFile) {
          Resource->ProgramHeaders = ReadELFHeaders(fd, std::span {reinterpret_cast<std::byte*>(addr), length});
          LOGMAN_THROW_A_FMT(Resource->ProgramHeaders.empty() || offset == 0, "Expected file offset 0 for the first mapping of an ELF "
                                                                              "file");
        }
      } else if (ResourceIt->second.ProgramHeaders.empty()) {
        // Not an ELF file, so we don't need to distinguish between different base addresses
      } else {
        // Mapped a non-header section of an ELF file.
        // Look up the corresponding MappedResource using the expected base address.

        ResourceIt = std::find_if(ResourceIt, ResourceEnd, [&](const VMATracking::MappedResource::ContainerType::value_type& ResourcePair) {
          auto& Resource = ResourcePair.second;
          auto ExpectedBases = FEXCore::InferMappingBaseAddress(
            Resource.ProgramHeaders, addr, Size, offset,
            (ProtMapping.Executable ? PF_X : 0) | (ProtMapping.Writable ? PF_W : 0) | (ProtMapping.Readable ? PF_R : 0));
          return std::ranges::find(ExpectedBases, Resource.FirstVMA->Base) != ExpectedBases.end();
        });
        if (ResourceIt == ResourceEnd) {
          // This isn't necessarily a fatal exception. It just means the ELF section isn't a part of the ELF Program headers.
          // Node.js hits this as it maps a section of itself that isn't a part of the program headers.
          LogMan::Msg::IFmt("Warning: Could not find base for file mapping at {:#x} (offset {:#x}): {}", addr, offset,
                            std::string_view(Tmp, PathLength));
        } else {
          Resource = &ResourceIt->second;
        }
      }

      if (Resource->MappedFile) {
        const fextl::string Filename = FHU::Filesystem::GetFilename(Resource->MappedFile->Filename);

        // We now have the filename and the offset in the filename getting mapped.
        // Check for extended volatile metadata.
        auto it = ExtendedMetaData.find(Filename);
        if (it != ExtendedMetaData.end()) {
          SyscallHandler::LateApplyExtendedVolatileMetadata LateMetadata;
          FEX::VolatileMetadata::ApplyFEXExtendedVolatileMetadata(
            it->second, LateMetadata.VolatileInstructions, LateMetadata.VolatileValidRanges, addr, addr + length, offset, offset + length);

          if (!LateMetadata.VolatileInstructions.empty() || !LateMetadata.VolatileValidRanges.Empty()) {
            VolatileMetadata.emplace(std::move(LateMetadata));
          }
        }
      }
    }
  } else if (flags & MAP_SHARED) {
    VMATracking::MRID mrid {VMATracking::SpecialDev::Anon, AnonSharedId++};

    auto [Iter, IterEnd] = VMATracking.FindResources(mrid);
    LOGMAN_THROW_A_FMT(Iter == IterEnd, "VMA tracking error");

    Iter = VMATracking.InsertMappedResource(mrid, {nullptr, nullptr, 0});
    Resource = &Iter->second;
    Resource->Iterator = Iter;
  }

  VMATracking.TrackVMARange(CTX, Resource, addr, offset, Size, VMATracking::VMAFlags::fromFlags(flags), VMATracking::VMAProt::fromProt(prot));

  // Load code cache if present.
  // FEXServer was requested to generate library caches on program launch.
  if (EnableCodeCaching && Resource && Resource->MappedFile && VMATracking::VMAProt::fromProt(prot).Executable) {
    if (Thread) {
      CachedSection.emplace(BuildSectionInfo(*Resource, addr, Size));
    } else {
      // Cache can't be loaded with a thread; skip this for now
      LogMan::Msg::DFmt("Oops, tried caching without a thread: {}", Resource->MappedFile->Filename);
    }
  }

  return VolatileMetadata;
}

void SyscallHandler::TrackMunmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length) {
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  VMATracking.DeleteVMARange(CTX, reinterpret_cast<uintptr_t>(addr), Size);
}

void SyscallHandler::TrackMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Size = FEXCore::AlignUp(len, FEXCore::Utils::FEX_PAGE_SIZE);

  VMATracking.ChangeProtectionFlags(reinterpret_cast<uintptr_t>(addr), Size, VMATracking::VMAProt::fromProt(prot));
}

void SyscallHandler::TrackMremap(FEXCore::Core::InternalThreadState* Thread, uint64_t OldAddress, size_t OldSize, size_t NewSize, int flags,
                                 uint64_t NewAddress) {
  OldSize = FEXCore::AlignUp(OldSize, FEXCore::Utils::FEX_PAGE_SIZE);
  NewSize = FEXCore::AlignUp(NewSize, FEXCore::Utils::FEX_PAGE_SIZE);

  const auto OldVMA = VMATracking.FindVMAEntry(OldAddress);

  const auto OldResource = OldVMA->second.Resource;
  const auto OldOffset = OldVMA->second.Offset + OldAddress - OldVMA->first;
  const auto OldFlags = OldVMA->second.Flags;
  const auto OldProt = OldVMA->second.Prot;

  LOGMAN_THROW_A_FMT(OldVMA != VMATracking.VMAs.end(), "VMA Tracking corruption");

  if (OldSize == 0) {
    // Mirror existing mapping
    // must be a shared mapping
    LOGMAN_THROW_A_FMT(OldResource != nullptr, "VMA Tracking error");
    LOGMAN_THROW_A_FMT(OldFlags.Shared, "VMA Tracking error");
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt);
  } else {

#ifndef MREMAP_DONTUNMAP
// MREMAP_DONTUNMAP is kernel 5.7+ and might not exist
#define MREMAP_DONTUNMAP 4
#endif
    if (!(flags & MREMAP_DONTUNMAP)) {
      VMATracking.DeleteVMARange(CTX, OldAddress, OldSize, OldResource);
    }

    // Make anonymous mapping
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt);
  }
}

void SyscallHandler::TrackShmat(FEXCore::Core::InternalThreadState* Thread, int shmid, uint64_t shmaddr, int shmflg, uint64_t Length) {
  VMATracking::MRID mrid {VMATracking::SpecialDev::SHM, static_cast<uint64_t>(shmid)};

  auto [Iter, IterEnd] = VMATracking.FindResources(mrid);
  if (Iter == IterEnd) {
    Iter = VMATracking.InsertMappedResource(mrid, {nullptr, nullptr, Length});
    Iter->second.Iterator = Iter;
  }
  auto Resource = &Iter->second;
  VMATracking.TrackVMARange(CTX, Resource, shmaddr, 0, Length, VMATracking::VMAFlags::fromFlags(MAP_SHARED), VMATracking::VMAProt::fromSHM(shmflg));
}

uint64_t SyscallHandler::TrackShmdt(FEXCore::Core::InternalThreadState* Thread, uint64_t shmaddr) {
  return VMATracking.DeleteSHMRegion(CTX, static_cast<uintptr_t>(shmaddr));
}

void SyscallHandler::TrackMadvise(FEXCore::Core::InternalThreadState* Thread, uintptr_t Base, uintptr_t Size, int advice) {
  Size = FEXCore::AlignUp(Size, FEXCore::Utils::FEX_PAGE_SIZE);
  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    // TODO
  }
}

} // namespace FEX::HLE
