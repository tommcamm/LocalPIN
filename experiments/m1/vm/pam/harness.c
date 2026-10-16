/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "common.h"

static void stop(const char *message)
{
    fprintf(stderr, "VM HARNESS: %s\n", message);
    exit(77);
}

static size_t read_file(const char *path, char *out, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        stop("guard input unavailable");
    ssize_t n = read(fd, out, capacity - 1);
    char extra;
    if (n < 0 || read(fd, &extra, 1) != 0)
        stop("guard input invalid");
    close(fd);
    out[n] = '\0';
    return (size_t)n;
}

static void guard(const char *dir)
{
    if (getuid() != 0 || geteuid() != 0)
        stop("start as guest root; privilege is dropped before PAM");
    pid_t child = fork();
    if (child == 0) {
        execl("/usr/bin/systemd-detect-virt", "systemd-detect-virt", "--vm", "--quiet", (char *)NULL);
        _exit(127);
    }
    int child_status;
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
        stop("a disposable VM is required");
    struct stat st;
    const char *marker = "/etc/localpin-m1-vm-guard";
    if (lstat(marker, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_gid != 0 || (st.st_mode & 0777) != 0600 || st.st_nlink != 1)
        stop("root-owned VM guard marker missing or unsafe");
    char uuid[128], actual[512], expected[512], enforcing[8];
    read_file("/sys/class/dmi/id/product_uuid", uuid, sizeof(uuid));
    uuid[strcspn(uuid, "\r\n")] = '\0';
    if (strlen(uuid) != 36)
        stop("VM UUID invalid");
    snprintf(expected, sizeof(expected),
             "LOCALPIN-M1-DISPOSABLE-VM\ntarget=localpintest\nuuid=%s\n", uuid);
    read_file(marker, actual, sizeof(actual));
    if (strcmp(actual, expected) != 0)
        stop("VM marker does not match this guest");
    read_file("/sys/fs/selinux/enforce", enforcing, sizeof(enforcing));
    if (strcmp(enforcing, "1") != 0 && strcmp(enforcing, "1\n") != 0)
        stop("SELinux must be Enforcing");
    if (dir[0] != '/' || lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 0022) != 0)
        stop("private config directory is unsafe");
    struct passwd *pw = getpwnam("localpintest");
    if (pw == NULL || pw->pw_uid < 1000 || pw->pw_uid >= 60000)
        stop("dedicated ordinary localpintest account required");
    uid_t uid = pw->pw_uid;
    gid_t gid = pw->pw_gid;
    FILE *passwd = fopen("/etc/passwd", "r");
    if (passwd == NULL)
        stop("local account inventory unavailable");
    int found = 0;
    struct passwd *local;
    while ((local = fgetpwent(passwd)) != NULL)
        if (strcmp(local->pw_name, "localpintest") == 0 && local->pw_uid == uid && local->pw_gid == gid)
            ++found;
    fclose(passwd);
    if (found != 1)
        stop("target is not the dedicated local account");
    gid_t groups[256];
    int group_count = 256;
    if (getgrouplist("localpintest", gid, groups, &group_count) < 0)
        stop("group list exceeds fixture bound");
    const char *privileged[] = {"root", "wheel", "sudo"};
    for (size_t i = 0; i < 3; ++i) {
        struct group *group = getgrnam(privileged[i]);
        if (group != NULL)
            for (int j = 0; j < group_count; ++j)
                if (groups[j] == group->gr_gid)
                    stop("target must not belong to privileged groups");
    }
    if (initgroups("localpintest", gid) != 0 || setresgid(gid, gid, gid) != 0 ||
        setresuid(uid, uid, uid) != 0 || getuid() != uid || geteuid() != uid)
        stop("could not drop privileges to localpintest");
}

static void read_exact(int fd, void *data, size_t size)
{
    unsigned char *p = data;
    while (size != 0) {
        ssize_t n = read(fd, p, size);
        if (n <= 0)
            stop("protected candidate pipe ended early");
        p += n;
        size -= (size_t)n;
    }
}

static int converse(int n, const struct pam_message **messages,
                    struct pam_response **responses, void *data)
{
    struct vm_conversation *s = data;
    *responses = NULL;
    if (n <= 0 || n > 32 || messages == NULL || s == NULL)
        return PAM_CONV_ERR;
    struct pam_response *r = calloc((size_t)n, sizeof(*r));
    if (r == NULL)
        return PAM_BUF_ERR;
    for (int i = 0; i < n; ++i) {
        if (messages[i] == NULL)
            goto fail;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            if (++s->prompts > 1)
                goto fail;
            r[i].resp = strdup(s->candidate);
            if (r[i].resp == NULL)
                goto fail;
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            break;
        default:
            goto fail;
        }
    }
    *responses = r;
    return PAM_SUCCESS;
fail:
    for (int i = 0; i < n; ++i) {
        if (r[i].resp != NULL) {
            explicit_bzero(r[i].resp, strlen(r[i].resp));
            free(r[i].resp);
        }
    }
    free(r);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv)
{
    if (argc != 6)
        stop("expected private config directory, mode, inherited pipe FD, attempt count, and account observation mode");
    if (strcmp(argv[2], "baseline") && strcmp(argv[2], "capture") && strcmp(argv[2], "naive"))
        stop("unknown private service mode");
    if (strcmp(argv[5], "account") && strcmp(argv[5], "auth-only"))
        stop("invalid account observation mode");
    char *end = NULL;
    long pipe_fd = strtol(argv[3], &end, 10);
    if (*end != '\0' || pipe_fd < 3 || pipe_fd > INT_MAX)
        stop("invalid inherited pipe FD");
    long attempts = strtol(argv[4], &end, 10);
    if (*end != '\0' || attempts < 1 || attempts > 8)
        stop("invalid attempt count");
    struct stat pipe_stat;
    if (fstat((int)pipe_fd, &pipe_stat) != 0 || !S_ISFIFO(pipe_stat.st_mode))
        stop("candidate input must be an inherited pipe");
    guard(argv[1]);
    struct vm_conversation s = {0};
    struct pam_conv conv = {converse, &s};
    pam_handle_t *pamh = NULL;
    int rc = pam_start_confdir(argv[2], "localpintest", &conv, argv[1], &pamh);
    if (rc != PAM_SUCCESS)
        stop("pam_start_confdir failed");
    puts("[");
    for (long i = 0; i < attempts; ++i) {
        uint32_t encoded;
        read_exact((int)pipe_fd, &encoded, sizeof(encoded));
        size_t size = ntohl(encoded);
        if (size == 0 || size > 511)
            stop("candidate length outside fixture bound");
        char candidate[512];
        read_exact((int)pipe_fd, candidate, size);
        if (memchr(candidate, '\0', size) != NULL)
            stop("embedded NUL outside PAM representation");
        candidate[size] = '\0';
        s = (struct vm_conversation){.candidate = candidate};
        int auth = pam_authenticate(pamh, 0);
        /* Observation only: KDE does not make this call. Never equate auth alone
           with account eligibility. No password-changing call is made. */
        int account = strcmp(argv[5], "account") == 0 ? pam_acct_mgmt(pamh, 0) : -1;
        int cred = auth == PAM_SUCCESS ? pam_setcred(pamh, PAM_REFRESH_CRED) : -1;
        explicit_bzero(candidate, sizeof(candidate));
        s.candidate = NULL;
        printf("%s{\"auth\":%d,\"account\":%d,\"setcred\":%d,\"prompts\":%d,\"capture_calls\":%d,\"naive_success\":%d}\n",
               i == 0 ? "" : ",", auth, account, cred, s.prompts, s.module_calls, s.pin_success);
    }
    puts("]");
    close((int)pipe_fd);
    if (pam_end(pamh, PAM_SUCCESS) != PAM_SUCCESS)
        stop("pam_end failed");
    return 0;
}
