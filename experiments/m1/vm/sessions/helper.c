/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Guest-only logind metadata fixture. No authentication or desktop is created. */
#define _GNU_SOURCE
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t closing;
static void interrupted(int number) { (void)number; closing = 1; }
static void fail(const char *stage)
{
    fprintf(stderr, "M1 session helper failure: %s\n", stage);
    exit(1);
}
static void read_text(const char *path, char *out, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        fail("guard read");
    ssize_t size = read(fd, out, capacity - 1);
    char extra;
    if (size < 0 || read(fd, &extra, 1) != 0)
        fail("guard size");
    close(fd);
    out[size] = '\0';
}
static void guard(const char *directory)
{
    if (getuid() != 0 || geteuid() != 0)
        fail("guest root required");
    struct stat info;
    const char *marker = "/etc/localpin-m1-vm-guard";
    if (lstat(marker, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid || info.st_gid ||
        info.st_nlink != 1 || (info.st_mode & 07777) != 0600)
        fail("unsafe VM marker");
    char uuid[128], actual[512], expected[512], enforce[8];
    read_text("/sys/class/dmi/id/product_uuid", uuid, sizeof(uuid));
    uuid[strcspn(uuid, "\r\n")] = '\0';
    if (strlen(uuid) != 36)
        fail("invalid VM UUID");
    snprintf(expected, sizeof(expected), "LOCALPIN-M1-DISPOSABLE-VM\ntarget=localpintest\nuuid=%s\n", uuid);
    read_text(marker, actual, sizeof(actual));
    read_text("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
    if (strcmp(actual, expected) || (strcmp(enforce, "1") && strcmp(enforce, "1\n")))
        fail("VM marker or Enforcing mismatch");
    if (directory[0] != '/' || lstat(directory, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid || info.st_gid || (info.st_mode & 07777) != 0700)
        fail("unsafe private directory");
    pid_t child = fork();
    if (child == 0) {
        execl("/usr/bin/systemd-detect-virt", "systemd-detect-virt", "--vm", "--quiet", (char *)NULL);
        _exit(127);
    }
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        fail("VM detection");
}
static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data)
{
    (void)count; (void)messages; (void)responses; (void)data;
    return PAM_CONV_ERR; /* This fixture never requests any credential. */
}
static void env(pam_handle_t *handle, const char *value)
{
    if (pam_putenv(handle, value) != PAM_SUCCESS)
        fail("PAM metadata environment");
}
int main(int argc, char **argv)
{
    alarm(60);
    if (argc != 5)
        fail("fixed mode, config directory, case directory, spare VT required");
    const char *mode = argv[1], *config = argv[2], *directory = argv[3];
    bool tty = !strcmp(mode, "tty"), remote = !strcmp(mode, "remote-metadata");
    bool greeter = !strcmp(mode, "greeter-metadata"), root = !strcmp(mode, "root-metadata");
    if (!tty && !remote && !greeter && !root && strcmp(mode, "graphical-metadata"))
        fail("unknown mode");
    char *end;
    long vt = strtol(argv[4], &end, 10);
    if (*end || vt < 3 || vt > 15)
        fail("invalid spare VT");
    guard(directory);
    guard(config);
    struct sigaction action = {.sa_handler = interrupted};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL))
        fail("signal setup");
    if (clearenv() || setenv("PATH", "/usr/sbin:/usr/bin", 1) || setenv("LC_ALL", "C", 1))
        fail("clean environment");
    struct pam_conv conv = {.conv = conversation};
    pam_handle_t *handle = NULL;
    if (pam_start_confdir("localpin-m1-session", root ? "root" : "localpintest", &conv, config, &handle) != PAM_SUCCESS)
        fail("private session PAM start");
    env(handle, tty ? "XDG_SESSION_TYPE=tty" : "XDG_SESSION_TYPE=wayland");
    env(handle, greeter ? "XDG_SESSION_CLASS=greeter" : "XDG_SESSION_CLASS=user");
    env(handle, tty ? "XDG_SESSION_DESKTOP=" : "XDG_SESSION_DESKTOP=KDE");
    env(handle, tty ? "XDG_SEAT=" : "XDG_SEAT=seat0");
    char vtnr[64];
    snprintf(vtnr, sizeof(vtnr), "XDG_VTNR=%ld", tty ? 0 : vt);
    env(handle, vtnr);
    int master = -1;
    if (tty) {
        master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        char path[128];
        if (master < 0 || grantpt(master) || unlockpt(master) || ptsname_r(master, path, sizeof(path)) ||
            pam_set_item(handle, PAM_TTY, path) != PAM_SUCCESS)
            fail("private PTY setup");
    }
    if (remote && pam_set_item(handle, PAM_RHOST, "localpin-m1-fixture.invalid") != PAM_SUCCESS)
        fail("remote metadata");
    /* A logind session moves the leader out of its launch service cgroup.
       Process limits and alarm remain attached to the leader after migration. */
    struct rlimit memory = {.rlim_cur = 128 * 1024 * 1024, .rlim_max = 128 * 1024 * 1024};
    struct rlimit cpu = {.rlim_cur = 10, .rlim_max = 10};
    if (setrlimit(RLIMIT_AS, &memory) || setrlimit(RLIMIT_CPU, &cpu))
        fail("process resource bounds");
    int opened = pam_open_session(handle, 0);
    if (opened != PAM_SUCCESS) {
        fprintf(stderr, "M1 session helper failure: open_session=%d\n", opened);
        pam_end(handle, opened);
        return 1;
    }
    const char *session = pam_getenv(handle, "XDG_SESSION_ID");
    if (!session || !*session || strlen(session) > 64)
        fail("missing registered session ID");
    for (const char *p = session; *p; ++p)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-')
            fail("invalid session ID");
    char ready[PATH_MAX], staged[PATH_MAX], release[PATH_MAX];
    if (snprintf(ready, sizeof(ready), "%s/ready.json", directory) >= (int)sizeof(ready) ||
        snprintf(staged, sizeof(staged), "%s/ready.tmp", directory) >= (int)sizeof(staged) ||
        snprintf(release, sizeof(release), "%s/release", directory) >= (int)sizeof(release))
        fail("private path bound");
    int fd = open(staged, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        fail("private readiness file");
    FILE *output = fdopen(fd, "w");
    if (!output || fprintf(output, "{\"session\":\"%s\",\"leader\":%ld,\"opened\":0}\n", session, (long)getpid()) < 0 ||
        fflush(output) || fsync(fd) || fclose(output))
        fail("readiness commit");
    if (rename(staged, ready))
        fail("readiness publication");
    for (unsigned count = 0; !closing && count < 600 && access(release, F_OK) != 0; ++count)
        usleep(50000);
    /* A close ends only this handle's freshly created session; no user/seat kill. */
    int closed = pam_close_session(handle, 0);
    int ended = pam_end(handle, closed);
    if (master >= 0)
        close(master);
    if (closed != PAM_SUCCESS || ended != PAM_SUCCESS)
        fail("private session close");
    return 0;
}
