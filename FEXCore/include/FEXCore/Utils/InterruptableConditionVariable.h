// SPDX-License-Identifier: MIT
#pragma once

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#if defined(__linux__)
#include <linux/futex.h>
#include <sys/syscall.h>
#elif defined(_WIN32)
#include <errhandlingapi.h>
#include <synchapi.h>
#include <winerror.h>
#elif defined(__APPLE__)
// macOS: use os_unfair_lock for synchronization
#include <os/lock.h>
#include <errno.h>
#endif
#include <unistd.h>

namespace FEXCore {
/**
 * @brief A condition variable that is robust against use of longjmp in signal handlers.
 *
 * This is opposed to common `std::condition_variable` implementations:
 * Longjmp'ing in a signal handler while interrupting a pending `wait_for()`
 * call can leave the condition variable in an invalid state that breaks later
 * uses of that object and may cause hangs as a consequence.
 */
#if defined(__linux__)
class InterruptableConditionVariable final {
public:
  bool Wait(struct timespec* Timeout = nullptr) {
    while (true) {
      uint32_t Expected = SIGNALED;
      uint32_t Desired = UNSIGNALED;

      // If the mutex was already signaled then we can early exit
      if (Mutex.compare_exchange_strong(Expected, Desired)) {
        return true;
      }

      constexpr int Op = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
      // WAIT will keep sleeping on the futex word while it is `val`
      int Result = ::syscall(SYS_futex, &Mutex, Op,
                             Desired, // val
                             Timeout, // Timeout/val2
                             nullptr, // Addr2
                             0);      // val3

      if (Timeout && Result == -1 && errno == ETIMEDOUT) {
        return false;
      }
    }
  }

  template<class Rep, class Period>
  bool WaitFor(const std::chrono::duration<Rep, Period>& time) {
    struct timespec Timeout {};
    auto SecondsDuration = std::chrono::duration_cast<std::chrono::seconds>(time);
    Timeout.tv_sec = SecondsDuration.count();
    Timeout.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(time - SecondsDuration).count();
    return Wait(&Timeout);
  }

  void NotifyOne() {
    DoNotify(1);
  }

  void NotifyAll() {
    // Maximum number of waiters
    DoNotify(INT_MAX);
  }

private:
  std::atomic<uint32_t> Mutex {};
  constexpr static uint32_t SIGNALED = 1;
  constexpr static uint32_t UNSIGNALED = 0;

  void DoNotify(int Waiters) {
    uint32_t Expected = UNSIGNALED;
    uint32_t Desired = SIGNALED;

    // If the mutex was in an unsignaled state then signal
    if (Mutex.compare_exchange_strong(Expected, Desired)) {
      constexpr int Op = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

      ::syscall(SYS_futex, &Mutex, Op,
                Waiters, // val - Number of waiters to wake
                0,       // val2
                &Mutex,  // Addr2 - Mutex to do the operation on
                0);      // val3
    }
  }
};
#elif defined(__APPLE__)
// macOS implementation using spin-wait with atomic operations
// macOS doesn't have Linux futex, so we use a simple spin-wait approach
class InterruptableConditionVariable final {
public:
  bool Wait(struct timespec* Timeout = nullptr) {
    auto TimeoutNS =
      Timeout ? std::chrono::seconds(Timeout->tv_sec) + std::chrono::nanoseconds(Timeout->tv_nsec) : std::chrono::nanoseconds::max();
    auto Start = std::chrono::steady_clock::now();

    while (true) {
      uint32_t Expected = SIGNALED;
      uint32_t Desired = UNSIGNALED;

      // If the mutex was already signaled then we can early exit
      if (Mutex.compare_exchange_strong(Expected, Desired)) {
        return true;
      }

      // Check timeout
      if (Timeout) {
        auto Now = std::chrono::steady_clock::now();
        if ((Now - Start) >= TimeoutNS) {
          return false;
        }
      }

      // Spin-wait with a short sleep to avoid burning CPU
      usleep(100);
    }
  }

  template<class Rep, class Period>
  bool WaitFor(const std::chrono::duration<Rep, Period>& time) {
    struct timespec Timeout {};
    auto SecondsDuration = std::chrono::duration_cast<std::chrono::seconds>(time);
    Timeout.tv_sec = SecondsDuration.count();
    Timeout.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(time - SecondsDuration).count();
    return Wait(&Timeout);
  }

  void NotifyOne() {
    DoNotify();
  }

  void NotifyAll() {
    DoNotify();
  }

private:
  std::atomic<uint32_t> Mutex {};
  constexpr static uint32_t SIGNALED = 1;
  constexpr static uint32_t UNSIGNALED = 0;

  void DoNotify() {
    uint32_t Expected = UNSIGNALED;
    uint32_t Desired = SIGNALED;

    // If the mutex was in an unsignaled state then signal
    Mutex.compare_exchange_strong(Expected, Desired);
    // Note: On macOS, we don't have a way to wake specific waiters like futex WAKE,
    // but the spin-wait loop will eventually see the changed value.
  }
};
#else // _WIN32
class InterruptableConditionVariable final {
public:
  bool Wait(struct timespec* Timeout = nullptr) {
    while (true) {
      uint32_t Expected = SIGNALED;
      uint32_t Desired = UNSIGNALED;

      // If the mutex was already signaled then we can early exit
      if (Mutex.compare_exchange_strong(Expected, Desired)) {
        return true;
      }
      // Windows only supports millisecond granularity.
      const uint32_t TimeoutMS = Timeout ? Timeout->tv_sec * 1000 + (Timeout->tv_nsec / 1000000) : 0;

      // WaitOnAddress returns when the value at `Address` differs from the value at `CompareAddress`.
      bool Result = WaitOnAddress(&Mutex, &Desired, 4, TimeoutMS);

      if (Timeout && Result == false && GetLastError() == ERROR_TIMEOUT) {
        return false;
      }
    }
  }

  template<class Rep, class Period>
  bool WaitFor(const std::chrono::duration<Rep, Period>& time) {
    struct timespec Timeout {};
    auto SecondsDuration = std::chrono::duration_cast<std::chrono::seconds>(time);
    Timeout.tv_sec = SecondsDuration.count();
    Timeout.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(time - SecondsDuration).count();
    return Wait(&Timeout);
  }

  void NotifyOne() {
    DoNotify(false);
  }

  void NotifyAll() {
    // Maximum number of waiters
    DoNotify(true);
  }

private:
  std::atomic<uint32_t> Mutex {};
  constexpr static uint32_t SIGNALED = 1;
  constexpr static uint32_t UNSIGNALED = 0;

  void DoNotify(bool All) {
    uint32_t Expected = UNSIGNALED;
    uint32_t Desired = SIGNALED;

    // If the mutex was in an unsignaled state then signal
    if (Mutex.compare_exchange_strong(Expected, Desired)) {
      if (All) {
        WakeByAddressAll(&Mutex);
      } else {
        WakeByAddressSingle(&Mutex);
      }
    }
  }
};

#endif
} // namespace FEXCore
