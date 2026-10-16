/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Local namespace test probe, never installed into a PAM service. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
static int inject_untrusted_peer;
static int probe_getsockopt(int fd, int level, int option, void *value, socklen_t *size)
{
    int rc = getsockopt(fd, level, option, value, size);
    if (rc == 0 && inject_untrusted_peer && level == SOL_SOCKET && option == SO_PEERCRED &&
        *size == sizeof(struct ucred))
        ((struct ucred *)value)->uid = 1;
    return rc;
}
#define getsockopt probe_getsockopt
#include "contact.h"
int main(int argc, char **argv)
{
    inject_untrusted_peer = argc == 2 && strcmp(argv[1], "inject-untrusted-peer") == 0;
    char observed[129];
    localpin_m1_current_type(observed);
    printf("%d\n", localpin_m1_contact());
    return 0;
}
