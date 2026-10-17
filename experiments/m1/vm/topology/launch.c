/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Disposable clone only: a real VT/PAM session and stock classic Plasma. */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/vt.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <systemd/sd-login.h>
#include <time.h>
#include <unistd.h>

#define TARGET "localpintest"
#define CONTROL "/run/localpin-m1-topology"
#define BIN "/usr/libexec/localpin-m1-topology"
static volatile sig_atomic_t closing;
static void interrupted(int sig) { (void)sig; closing = 1; }
static void fail(const char *stage) { fprintf(stderr, "M1 topology helper failure: %s\n", stage); exit(77); }
static void text(const char *path, char *out, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) fail("guard input");
    ssize_t size = read(fd, out, capacity - 1); char extra;
    if (size < 0 || read(fd, &extra, 1)) fail("guard size");
    close(fd); out[size] = '\0';
}
static void owned(const char *path, mode_t type, mode_t mode)
{
    struct stat info;
    if (lstat(path, &info) || (info.st_mode & S_IFMT) != type || info.st_uid || info.st_gid ||
        (info.st_mode & 07777) != mode || (type == S_IFREG && info.st_nlink != 1)) fail("unsafe root path");
}
static void guard(void)
{
    if (getuid() || geteuid()) fail("guest root required");
    char uuid[128], expected[512], actual[512], enforcing[8], cgroup[4096];
    text("/sys/class/dmi/id/product_uuid", uuid, sizeof(uuid)); uuid[strcspn(uuid, "\r\n")] = '\0';
    if (strlen(uuid) != 36) fail("UUID");
    const char *paths[] = {"/etc/localpin-m1-vm-guard", "/etc/localpin-m1-topology-clone-guard"};
    const char *head[] = {"LOCALPIN-M1-DISPOSABLE-VM", "LOCALPIN-M1-TOPOLOGY-CLONE"};
    for (unsigned i = 0; i < 2; ++i) {
        owned(paths[i], S_IFREG, 0600); text(paths[i], actual, sizeof(actual));
        snprintf(expected, sizeof(expected), "%s\ntarget=" TARGET "\nuuid=%s\n", head[i], uuid);
        if (strcmp(expected, actual)) fail("clone marker mismatch");
    }
    text("/sys/fs/selinux/enforce", enforcing, sizeof(enforcing));
    if (strcmp(enforcing, "1") && strcmp(enforcing, "1\n")) fail("Enforcing required");
    text("/proc/self/cgroup", cgroup, sizeof(cgroup));
    if (strcmp(cgroup, "0::/system.slice/localpin-m1-topology-launch.service\n")) fail("fresh dedicated root unit required");
    owned(CONTROL, S_IFDIR, 0700); owned(CONTROL "/pam", S_IFDIR, 0700);
    owned(CONTROL "/pam/localpin-m1-topology", S_IFREG, 0600);
    owned(BIN "/private-session-bus.conf", S_IFREG, 0644);
    pid_t child = fork();
    if (!child) { execl("/usr/bin/systemd-detect-virt", "systemd-detect-virt", "--vm", "--quiet", (char *)NULL); _exit(127); }
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) fail("VM detection");
}
static int converse(int n, const struct pam_message **messages, struct pam_response **responses, void *data)
{
    (void)n; (void)messages; (void)responses; (void)data;
    return PAM_CONV_ERR; /* Root starts a session fixture; no authentication occurs. */
}
static void put(pam_handle_t *handle, const char *value)
{
    if (pam_putenv(handle, value) != PAM_SUCCESS) fail("session metadata");
}
static void environment(const char *name, const char *value)
{
    if (setenv(name, value, 1)) fail("child environment");
}
static void publish(const char *name, const char *value)
{
    char path[PATH_MAX], staging[PATH_MAX];
    if (snprintf(path, sizeof(path), CONTROL "/%s", name) >= (int)sizeof(path) ||
        snprintf(staging, sizeof(staging), CONTROL "/%s.tmp", name) >= (int)sizeof(staging)) fail("control path");
    int fd = open(staging, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail("control creation");
    size_t size = strlen(value);
    if (write(fd, value, size) != (ssize_t)size || fsync(fd) || close(fd) ||
        renameat2(AT_FDCWD, staging, AT_FDCWD, path, RENAME_NOREPLACE)) fail("control commit");
    fd = open(CONTROL, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fsync(fd) || close(fd)) fail("control directory commit");
}
static int close_session(pam_handle_t *handle, bool child_started, bool child_reaped, bool activated)
{
    int closed = pam_close_session(handle, 0), ended = pam_end(handle, closed);
    char result[512];
    snprintf(result, sizeof(result), "{\"pam_closed\":%d,\"pam_ended\":%d,\"desktop_child_started\":%s,\"direct_child_reaped\":%s,\"activation_verified_before_fork\":%s,\"scope_cleanup_requires_controller\":true}\n",
             closed, ended, child_started ? "true" : "false", child_reaped ? "true" : "false", activated ? "true" : "false");
    publish("closed.json", result);
    return closed == PAM_SUCCESS && ended == PAM_SUCCESS ? 0 : 1;
}
int main(int argc, char **argv)
{
    alarm(920); /* Independent scope ceiling is 15min; controller owns teardown. */
    if (argc != 2) fail("spare VT required");
    char *end; long vt = strtol(argv[1], &end, 10);
    if (*end || vt < 7 || vt > 15) fail("bounded spare VT");
    guard();
    int console = open("/dev/tty0", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    struct vt_stat state;
    if (console < 0 || ioctl(console, VT_GETSTATE, &state) || state.v_active == vt ||
        (state.v_state & (1U << vt))) fail("spare VT changed or occupied");
    close(console);
    struct passwd *account = getpwnam(TARGET);
    if (!account || account->pw_uid < 1000 || account->pw_uid >= 60000) fail("ordinary target account");
    uid_t uid = account->pw_uid; gid_t gid = account->pw_gid;
    char home[PATH_MAX];
    if (snprintf(home, sizeof(home), "%s", account->pw_dir) >= (int)sizeof(home)) fail("home bound");
    FILE *local = fopen("/etc/passwd", "r");
    if (!local) fail("local account");
    int found = 0; struct passwd *entry;
    while ((entry = fgetpwent(local))) if (!strcmp(entry->pw_name, TARGET) && entry->pw_uid == uid && entry->pw_gid == gid) ++found;
    fclose(local); if (found != 1) fail("local identity mismatch");
    gid_t groups[256]; int count = 256;
    if (getgrouplist(TARGET, gid, groups, &count) < 0) fail("group bound");
    const char *admin[] = {"root", "wheel", "sudo"};
    for (unsigned i = 0; i < 3; ++i) { struct group *g = getgrnam(admin[i]);
        if (g) for (int j = 0; j < count; ++j) if (groups[j] == g->gr_gid) fail("administrative target group"); }
    struct sigaction action = {.sa_handler = interrupted}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) fail("signal setup");
    if (clearenv()) fail("clean environment");
    struct pam_conv conv = {.conv = converse}; pam_handle_t *handle = NULL;
    if (pam_start_confdir("localpin-m1-topology", TARGET, &conv, CONTROL "/pam", &handle) != PAM_SUCCESS) fail("PAM start");
    put(handle, "XDG_SESSION_TYPE=wayland"); put(handle, "XDG_SESSION_CLASS=user");
    put(handle, "XDG_SESSION_DESKTOP=KDE"); put(handle, "XDG_SEAT=seat0");
    char vtnr[64], tty[64]; snprintf(vtnr, sizeof(vtnr), "XDG_VTNR=%ld", vt); put(handle, vtnr);
    snprintf(tty, sizeof(tty), "/dev/tty%ld", vt);
    if (pam_set_item(handle, PAM_TTY, tty) != PAM_SUCCESS) fail("PAM tty");
    int opened = pam_open_session(handle, 0);
    if (opened != PAM_SUCCESS) { pam_end(handle, opened); fail("PAM session registration"); }
    const char *registered = pam_getenv(handle, "XDG_SESSION_ID"), *runtime = pam_getenv(handle, "XDG_RUNTIME_DIR");
    char session[65], expected_runtime[128], private[PATH_MAX];
    if (!registered || !*registered || strlen(registered) > 64) fail("registered session ID");
    for (const char *p = registered; *p; ++p) if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') fail("session ID format");
    strcpy(session, registered);
    char ready[512]; snprintf(ready, sizeof(ready), "{\"session\":\"%s\",\"leader\":%ld,\"uid\":%lu,\"vt\":%ld,\"registration_only\":true}\n",
                             session, (long)getpid(), (unsigned long)uid, vt);
    publish("registered.json", ready);
    snprintf(expected_runtime, sizeof(expected_runtime), "/run/user/%lu", (unsigned long)uid);
    struct stat info;
    if (!runtime || strcmp(runtime, expected_runtime) || lstat(runtime, &info) || !S_ISDIR(info.st_mode) ||
        info.st_uid != uid || (info.st_mode & 07777) != 0700) fail("canonical actual user runtime");
    snprintf(private, sizeof(private), "%s/localpin-m1-topology", expected_runtime);
    int runtime_fd = open(runtime, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (runtime_fd < 0 || mkdirat(runtime_fd, "localpin-m1-topology", 0700)) fail("private target directory collision");
    int private_fd = openat(runtime_fd, "localpin-m1-topology", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(runtime_fd);
    if (private_fd < 0 || fchown(private_fd, uid, gid)) fail("private target directory owner");
    const char *names[] = {"config", "data", "cache", "state"};
    for (unsigned i = 0; i < 4; ++i) {
        if (mkdirat(private_fd, names[i], 0700)) fail("private XDG directory");
        int fd = openat(private_fd, names[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 || fchown(fd, uid, gid)) fail("private XDG owner");
        close(fd);
    }
    close(private_fd);
    /* Registration alone must not initialize libinput/DRM on an inactive VT.
       The controller first pins this new scope, deliberately activates it, and
       then atomically publishes a root-only gate. Cancellation never forks. */
    struct timespec wait = {.tv_nsec = 100000000};
    unsigned gate_ticks;
    for (gate_ticks = 0; !closing && gate_ticks < 1200 && access(CONTROL "/release", F_OK) &&
         access(CONTROL "/activate-approved", F_OK); ++gate_ticks) nanosleep(&wait, NULL);
    if (closing || !access(CONTROL "/release", F_OK) || gate_ticks == 1200)
        return close_session(handle, false, false, false);
    owned(CONTROL "/activate-approved", S_IFREG, 0600);
    char approval[128], expected_approval[128];
    text(CONTROL "/activate-approved", approval, sizeof(approval));
    snprintf(expected_approval, sizeof(expected_approval), "%s\n", session);
    console = open("/dev/tty0", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    bool active = !strcmp(approval, expected_approval) && console >= 0 &&
        !ioctl(console, VT_GETSTATE, &state) && state.v_active == vt && sd_session_is_active(session) > 0;
    if (console >= 0) close(console);
    if (!active) { close_session(handle, false, false, false); return 1; }
    pid_t child = fork();
    if (child < 0) fail("desktop fork");
    if (!child) {
        if (setsid() < 0) fail("child setsid");
        int fd = open(tty, O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (fd < 0 || ioctl(fd, TIOCSCTTY, 0) || dup2(fd, STDIN_FILENO) < 0) fail("controlling real VT");
        close(fd);
        if (initgroups(TARGET, gid) || setresgid(gid, gid, gid) || setresuid(uid, uid, uid) || getuid() != uid || geteuid() != uid) fail("desktop UID drop");
        environment("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/libexec"); environment("HOME", home);
        environment("USER", TARGET); environment("LOGNAME", TARGET); environment("LANG", "en_US.UTF-8");
        environment("XDG_RUNTIME_DIR", expected_runtime); environment("XDG_SESSION_ID", session);
        environment("XDG_SESSION_TYPE", "wayland"); environment("XDG_SESSION_CLASS", "user");
        environment("XDG_SESSION_DESKTOP", "KDE"); environment("XDG_CURRENT_DESKTOP", "KDE");
        environment("XDG_SEAT", "seat0"); environment("XDG_VTNR", argv[1]);
        environment("LOCALPIN_M1_TOPOLOGY", "clone-native-drm"); /* Cleanup observation only, never authorization. */
        environment("KDE_FULL_SESSION", "true"); environment("KDE_SESSION_VERSION", "6");
        char number[64]; snprintf(number, sizeof(number), "%lu", (unsigned long)uid); environment("KDE_SESSION_UID", number);
        const char *xdg[] = {"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"};
        for (unsigned i = 0; i < 4; ++i) { char value[PATH_MAX];
            if (snprintf(value, sizeof(value), "%s/%s", private, names[i]) >= (int)sizeof(value)) fail("XDG path bound");
            environment(xdg[i], value); }
        environment("XDG_CONFIG_DIRS", "/etc/xdg"); environment("XDG_DATA_DIRS", "/usr/local/share:/usr/share");
        environment("XDG_MENU_PREFIX", "plasma-");
        if (chdir(home)) fail("target home");
        /* No DISPLAY, WAYLAND_DISPLAY, fake runtime, systemd boot or nested flag.
           Classic plasma_session starts the stock KWin wrapper/DRM compositor.
           Its --no-lockscreen affects ksmserver; KWin's locker stays enabled. */
        execl("/usr/bin/dbus-run-session", "dbus-run-session", "--config-file=" BIN "/private-session-bus.conf",
              "--", "/usr/bin/plasma_session", "--no-lockscreen", (char *)NULL);
        fail("stock classic Plasma exec");
    }
    snprintf(ready, sizeof(ready), "{\"session\":\"%s\",\"leader\":%ld,\"child\":%ld,\"uid\":%lu,\"vt\":%ld,\"registration_only\":true,\"activation_verified_before_fork\":true}\n",
                             session, (long)getpid(), (long)child, (unsigned long)uid, vt);
    publish("ready.json", ready);
    int status = 0; bool reaped = false;
    for (unsigned tick = gate_ticks; !closing && tick < 8700 && access(CONTROL "/release", F_OK); ++tick) {
        if (waitpid(child, &status, WNOHANG) == child) { reaped = true; break; }
        nanosleep(&wait, NULL);
    }
    if (!reaped) { kill(child, SIGTERM);
        for (unsigned tick = 0; tick < 40; ++tick) { if (waitpid(child, &status, WNOHANG) == child) { reaped = true; break; } nanosleep(&wait, NULL); }
        if (!reaped) { kill(child, SIGKILL); if (waitpid(child, &status, 0) != child) fail("child reap"); }
    }
    return close_session(handle, true, true, true);
}
