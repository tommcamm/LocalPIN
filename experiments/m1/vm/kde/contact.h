/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Fixed synthetic contact only. No credential bytes enter this interface. */
#ifndef LOCALPIN_M1_KDE_CONTACT_H
#define LOCALPIN_M1_KDE_CONTACT_H
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define LOCALPIN_M1_CONTACT_SOCKET "/run/localpin-m1/contact.sock"
#define LOCALPIN_M1_CONTACT_BUDGET_NS UINT64_C(250000000)

enum localpin_m1_contact_outcome {
    M1_CONTACT_OK = 0,
    M1_CONTACT_CLOCK = 1,
    M1_CONTACT_SOCKET = 2,
    M1_CONTACT_CONNECT = 3,
    M1_CONTACT_TIMEOUT = 4,
    M1_CONTACT_PEER = 5,
    M1_CONTACT_SEND = 6,
    M1_CONTACT_RECEIVE = 7,
    M1_CONTACT_PROTOCOL = 8,
};

static uint64_t localpin_m1_now(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

/* Return 1 ready, 0 deadline, -1 I/O failure; retries use the same deadline. */
static int localpin_m1_wait(int fd, short events, uint64_t deadline)
{
    for (;;) {
        uint64_t now = localpin_m1_now();
        if (now == 0 || now >= deadline)
            return 0;
        int remaining = (int)((deadline - now + UINT64_C(999999)) / UINT64_C(1000000));
        struct pollfd pending = {.fd = fd, .events = events};
        int result = poll(&pending, 1, remaining);
        if (result < 0 && errno == EINTR)
            continue;
        if (result < 0)
            return -1;
        if (result == 0)
            continue;
        if (pending.revents & events)
            return 1;
        if (pending.revents & (POLLERR | POLLHUP | POLLNVAL))
            return -1;
    }
}

static int localpin_m1_contact(void)
{
    uint64_t start = localpin_m1_now();
    if (start == 0)
        return M1_CONTACT_CLOCK;
    uint64_t deadline = start + LOCALPIN_M1_CONTACT_BUDGET_NS;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return M1_CONTACT_SOCKET;
    int outcome = M1_CONTACT_CONNECT;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    _Static_assert(sizeof(LOCALPIN_M1_CONTACT_SOCKET) <= sizeof(address.sun_path), "fixed contact path fits");
    memcpy(address.sun_path, LOCALPIN_M1_CONTACT_SOCKET, sizeof(LOCALPIN_M1_CONTACT_SOCKET));
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (errno != EINPROGRESS)
            goto done;
        int ready = localpin_m1_wait(fd, POLLOUT, deadline);
        if (ready <= 0) {
            outcome = ready == 0 ? M1_CONTACT_TIMEOUT : M1_CONTACT_CONNECT;
            goto done;
        }
        int error = 0;
        socklen_t size = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0 ||
            size != sizeof(error) || error != 0)
            goto done;
    }
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
        size != sizeof(peer) || peer.uid != 0) {
        outcome = M1_CONTACT_PEER;
        goto done;
    }
    const char request[4] = {'P', 'I', 'N', 'G'};
    size_t sent = 0;
    while (sent < sizeof(request)) {
        int ready = localpin_m1_wait(fd, POLLOUT, deadline);
        if (ready <= 0) {
            outcome = ready == 0 ? M1_CONTACT_TIMEOUT : M1_CONTACT_SEND;
            goto done;
        }
        ssize_t count = send(fd, request + sent, sizeof(request) - sent, MSG_NOSIGNAL);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        if (count <= 0) {
            outcome = M1_CONTACT_SEND;
            goto done;
        }
        sent += (size_t)count;
    }
    char response[4];
    size_t received = 0;
    while (received < sizeof(response)) {
        int ready = localpin_m1_wait(fd, POLLIN, deadline);
        if (ready <= 0) {
            outcome = ready == 0 ? M1_CONTACT_TIMEOUT : M1_CONTACT_RECEIVE;
            goto done;
        }
        ssize_t count = recv(fd, response + received, sizeof(response) - received, 0);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        if (count <= 0) {
            outcome = M1_CONTACT_RECEIVE;
            goto done;
        }
        received += (size_t)count;
    }
    outcome = memcmp(response, "PONG", 4) == 0 ? M1_CONTACT_OK : M1_CONTACT_PROTOCOL;
    uint64_t end = localpin_m1_now();
    if (end == 0 || end >= deadline)
        outcome = M1_CONTACT_TIMEOUT;
done:
    close(fd);
    return outcome;
}

static void localpin_m1_current_type(char observed[129])
{
    memcpy(observed, "unavailable", sizeof("unavailable"));
    char context[256] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return;
    ssize_t size = read(fd, context, sizeof(context) - 1);
    close(fd);
    if (size <= 0)
        return;
    char *first = strchr(context, ':');
    char *second = first == NULL ? NULL : strchr(first + 1, ':');
    char *third = second == NULL ? NULL : strchr(second + 1, ':');
    if (third == NULL || third <= second + 1 || third - second - 1 > 128)
        return;
    size_t length = (size_t)(third - second - 1);
    for (size_t i = 0; i < length; ++i) {
        unsigned char byte = (unsigned char)second[i + 1];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9') || byte == '_'))
            return;
    }
    memcpy(observed, second + 1, length);
    observed[length] = '\0';
}
#endif
