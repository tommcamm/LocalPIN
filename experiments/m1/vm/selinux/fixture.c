/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Disposable-VM SELinux fixture. No real password or product protocol exists. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define SOCKET_PATH "/run/localpin-m1/contact.sock"
#define CANARY_PATH "/run/localpin-m1-canary/public-marker"
#define PRIVATE_PATH "/var/lib/localpin-m1/private-marker"
#define PAM_DIR "/etc/localpin-m1-pam"
#define MISSING_ACCOUNT "localpin_m1_missing_account"

static void fail(const char *reason)
{
    /* Fixed diagnostics only: never echo data, a PAM prompt or an exception. */
    fprintf(stderr, "M1 fixture failure: %s\n", reason);
    exit(1);
}

static void domain(const char *expected)
{
    char context[256] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fail("context unavailable");
    ssize_t length = read(fd, context, sizeof(context) - 1);
    close(fd);
    if (length <= 0)
        fail("context unavailable");
    char observed[129] = "invalid";
    char *first = strchr(context, ':');
    char *second = first ? strchr(first + 1, ':') : NULL;
    char *third = second ? strchr(second + 1, ':') : NULL;
    if (second && third && third > second + 1 && (size_t)(third - second - 1) < sizeof(observed)) {
        size_t size = (size_t)(third - second - 1);
        bool valid = true;
        for (size_t index = 0; index < size; ++index) {
            unsigned char byte = (unsigned char)second[1 + index];
            if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                  (byte >= '0' && byte <= '9') || byte == '_'))
                valid = false;
        }
        if (valid) {
            memcpy(observed, second + 1, size);
            observed[size] = '\0';
        }
    }
    if (strcmp(observed, expected) != 0) {
        /* Only bounded policy type names, never a full context/user/range. */
        fprintf(stderr, "M1 fixture failure: wrong process domain; observed_type=%s expected_type=%s\n",
                observed, expected);
        exit(1);
    }
}

static int stream(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct timeval timeout = {.tv_sec = 2};
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        fail("socket setup");
    return fd;
}

static struct sockaddr_un address(void)
{
    struct sockaddr_un result = {.sun_family = AF_UNIX};
    _Static_assert(sizeof(SOCKET_PATH) <= sizeof(result.sun_path), "socket path fits");
    memcpy(result.sun_path, SOCKET_PATH, sizeof(SOCKET_PATH));
    return result;
}

static void require_denied(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        fail("private marker unexpectedly readable");
    }
    if (errno != EACCES && errno != EPERM)
        fail("marker denial baseline unavailable");
}

static void broker(uid_t expected_uid)
{
    domain("localpin_m1_broker_t");
    int marker = open(PRIVATE_PATH, O_RDONLY | O_CLOEXEC);
    if (marker < 0)
        fail("broker private marker unavailable");
    close(marker);
    int fd = stream();
    struct sockaddr_un addr = address();
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        chmod(SOCKET_PATH, 0666) != 0 || listen(fd, 4) != 0)
        fail("broker listen");
    for (unsigned int count = 0; count < 16; ++count) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        int result = poll(&ready, 1, 30000);
        if (result <= 0)
            break;
        int peer = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        if (peer < 0)
            fail("broker accept");
        struct ucred credentials;
        socklen_t size = sizeof(credentials);
        char candidate[4];
        if (getsockopt(peer, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0 &&
            size == sizeof(credentials) && credentials.uid == expected_uid &&
            recv(peer, candidate, sizeof(candidate), MSG_WAITALL) == 4 &&
            memcmp(candidate, "PING", 4) == 0) {
            if (send(peer, "PONG", 4, MSG_NOSIGNAL) != 4)
                fail("broker fixed response");
        }
        close(peer);
    }
    close(fd);
}

static void client(bool denied)
{
    domain(denied ? "localpin_m1_denied_t" : "localpin_m1_client_t");
    require_denied(CANARY_PATH); /* world-readable DAC baseline, MAC still denies */
    require_denied(PRIVATE_PATH); /* separate root-only DAC baseline */
    int fd = stream();
    struct sockaddr_un addr = address();
    int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (denied) {
        if (result == 0 || (errno != EACCES && errno != EPERM))
            fail("expected SELinux contact denial absent");
        close(fd);
        return;
    }
    if (result != 0)
        fail("allowed contact failed");
    struct ucred credentials;
    socklen_t size = sizeof(credentials);
    char response[4];
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 ||
        size != sizeof(credentials) || credentials.uid != 0 ||
        send(fd, "PING", 4, MSG_NOSIGNAL) != 4 ||
        recv(fd, response, sizeof(response), MSG_WAITALL) != 4 ||
        memcmp(response, "PONG", 4) != 0)
        fail("fixed echo or root-peer check failed");
    close(fd);
}

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data)
{
    (void)count;
    (void)messages;
    (void)responses;
    (void)data;
    return PAM_CONV_ERR; /* permit/deny baselines must never request a secret */
}

static void pam_baseline(const char *service, int expected)
{
    struct pam_conv conv = {.conv = conversation, .appdata_ptr = NULL};
    pam_handle_t *handle = NULL;
    int result = pam_start_confdir(service, MISSING_ACCOUNT, &conv, PAM_DIR, &handle);
    if (result != PAM_SUCCESS)
        fail("private PAM start baseline");
    result = pam_authenticate(handle, 0);
    int ended = pam_end(handle, result);
    if (result != expected || ended != PAM_SUCCESS)
        fail("private PAM result baseline");
}

static void helper_baseline(void)
{
    int input[2], error_pipe[2];
    if (pipe2(input, O_CLOEXEC) != 0 || pipe2(error_pipe, O_CLOEXEC) != 0)
        fail("helper pipes");
    pid_t child = fork();
    if (child < 0)
        fail("helper fork");
    if (child == 0) {
        close(input[1]);
        close(error_pipe[0]);
        if (dup2(input[0], STDIN_FILENO) < 0)
            _exit(126);
        close(input[0]);
        execl("/usr/sbin/unix_chkpwd", "unix_chkpwd", MISSING_ACCOUNT, "nonull", (char *)NULL);
        int failure = errno;
        ssize_t ignored = write(error_pipe[1], &failure, sizeof(failure));
        (void)ignored;
        _exit(127);
    }
    close(input[0]);
    close(error_pipe[1]);
    /* Public test bytes, never a real credential or a user-selected candidate. */
    static const char public_candidate[] = "m1-public-fixture-only";
    if (write(input[1], public_candidate, sizeof(public_candidate)) != (ssize_t)sizeof(public_candidate))
        fail("helper fixture input");
    close(input[1]);
    int execution_error = 0;
    ssize_t received = read(error_pipe[0], &execution_error, sizeof(execution_error));
    close(error_pipe[0]);
    int status = 0;
    if (waitpid(child, &status, 0) != child || received != 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != PAM_AUTHINFO_UNAVAIL)
        fail("native helper missing-account baseline");
}

int main(int argc, char **argv)
{
    alarm(35); /* systemd also bounds lifetime; no indefinitely blocked test */
    if (argc == 3 && strcmp(argv[1], "broker") == 0) {
        char *end = NULL;
        unsigned long uid = strtoul(argv[2], &end, 10);
        if (!end || *end || uid == 0 || uid > 0x7fffffffUL || getuid() != 0)
            fail("invalid broker fixture UID");
        broker((uid_t)uid);
    } else if (argc == 2 && strcmp(argv[1], "client") == 0) {
        client(false);
    } else if (argc == 2 && strcmp(argv[1], "denied") == 0) {
        client(true);
    } else if (argc == 2 && strcmp(argv[1], "worker") == 0 && getuid() == 0) {
        domain("localpin_m1_worker_t");
        pam_baseline("permit", PAM_SUCCESS);
        pam_baseline("deny", PAM_AUTH_ERR);
        helper_baseline();
    } else {
        fail("fixed test mode required");
    }
    return 0;
}
