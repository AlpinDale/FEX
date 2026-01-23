// SPDX-License-Identifier: MIT
#include <signal.h>

int fex_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact) {
    return sigaction(signum, act, oldact);
}
