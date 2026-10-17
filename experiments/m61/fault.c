/* M6.1 disposable-VM crash tracer. No injected library or modified authority.
 * Linux x86_64 ptrace observes the actual manager's kernel syscall boundaries,
 * including rustix's direct syscalls. It never reads account or secret bytes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t target;
static void finish(int sig) { (void)sig; if (target > 0) kill(target, SIGKILL); _exit(124); }
static void fail(const char *text) { perror(text); if (target > 0) kill(target, SIGKILL); exit(1); }
static bool fd_path(pid_t pid, unsigned long long fd, char *out, size_t size)
{
    char link[100];
    snprintf(link, sizeof(link), "/proc/%ld/fd/%llu", (long)pid, fd);
    ssize_t n = readlink(link, out, size - 1);
    if (n < 0 || (size_t)n >= size - 1) return false;
    out[n] = 0;
    return true;
}
static bool same_fd(pid_t pid, unsigned long long fd, const char *expected)
{
    char path[4096];
    return fd_path(pid, fd, path, sizeof(path)) && !strcmp(path, expected);
}
static bool match(pid_t pid, const struct user_regs_struct *r, const char *selector)
{
    if (!strcmp(selector, "tally-create"))
        return r->orig_rax == SYS_openat && (r->rdx & O_TMPFILE) == O_TMPFILE &&
               same_fd(pid, r->rdi, "/run/faillock");
    if (!strcmp(selector, "tally-link"))
        return r->orig_rax == SYS_linkat && same_fd(pid, r->rdx, "/run/faillock");
    if (!strcmp(selector, "tally-owned") || !strcmp(selector, "tally-canonical") ||
        !strcmp(selector, "tally-file-sync")) {
        unsigned long long call = !strcmp(selector, "tally-owned") ? SYS_fchown :
                                  !strcmp(selector, "tally-canonical") ? SYS_fchmod : SYS_fsync;
        char path[4096];
        return r->orig_rax == call && fd_path(pid, r->rdi, path, sizeof(path)) &&
               !strncmp(path, "/run/faillock/#", strlen("/run/faillock/#"));
    }
    if (!strcmp(selector, "freeze"))
        return r->orig_rax == SYS_ioctl && r->rsi == FS_IOC_SETFLAGS;
    if (!strcmp(selector, "registry-rename"))
        return (r->orig_rax == SYS_renameat || r->orig_rax == SYS_renameat2) &&
               same_fd(pid, r->rdi, "/var/lib/localpin-accounts");
    if (r->orig_rax != SYS_fsync) return false;
    if (!strcmp(selector, "registry-temp"))
        return same_fd(pid, r->rdi, "/var/lib/localpin-accounts/.pending");
    if (!strcmp(selector, "registry-dir"))
        return same_fd(pid, r->rdi, "/var/lib/localpin-accounts");
    if (!strcmp(selector, "tally-dir-sync"))
        return same_fd(pid, r->rdi, "/run/faillock");
    if (!strcmp(selector, "storage-temp")) {
        char path[4096];
        if (!fd_path(pid, r->rdi, path, sizeof(path))) return false;
        const char *prefix = "/var/lib/localpin/users/21061/";
        size_t n = strlen(path);
        return !strncmp(path, prefix, strlen(prefix)) && n > 9 &&
               !strcmp(path + n - 9, "/.pending");
    }
    return false;
}
static void guard(void)
{
    char dmi[100], marker[100], enforcing[8];
    const char *paths[] = {"/sys/class/dmi/id/product_uuid", "/run/localpin-m61-guard", "/sys/fs/selinux/enforce"};
    char *buffers[] = {dmi, marker, enforcing};
    size_t sizes[] = {sizeof(dmi), sizeof(marker), sizeof(enforcing)};
    if (getuid() || geteuid() || access("/dev/tpm0", F_OK) == 0 || access("/dev/tpmrm0", F_OK) == 0) fail("VM root guard");
    struct stat info;
    if (lstat(paths[1], &info) || !S_ISREG(info.st_mode) || info.st_uid || (info.st_mode & 022)) fail("marker metadata");
    for (unsigned i = 0; i < 3; ++i) {
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) fail("guard open");
        ssize_t n = read(fd, buffers[i], sizes[i] - 1);
        if (n <= 0) fail("guard read");
        buffers[i][n] = 0;
        close(fd);
    }
    if (strcmp(dmi, marker) || strcmp(enforcing, "1")) fail("guard identity");
}
int main(int argc, char **argv)
{
    if (argc != 5 || (strcmp(argv[1], "seal") && strcmp(argv[1], "begin-mutation")) ||
        (strcmp(argv[3], "before") && strcmp(argv[3], "after"))) return 2;
    const char *selectors[] = {"registry-temp", "registry-dir", "registry-rename", "freeze", "storage-temp",
        "tally-create", "tally-owned", "tally-canonical", "tally-file-sync", "tally-link", "tally-dir-sync"};
    bool valid = false;
    for (unsigned i = 0; i < sizeof(selectors) / sizeof(*selectors); ++i) valid |= !strcmp(argv[2], selectors[i]);
    char *end;
    long nth = strtol(argv[4], &end, 10);
    if (!valid || *end || nth < 1 || nth > 100) return 2;
    guard();
    signal(SIGALRM, finish); signal(SIGTERM, finish); signal(SIGINT, finish); alarm(25);
    target = fork();
    if (target < 0) fail("fork");
    if (!target) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(126);
        raise(SIGSTOP);
        if (!strcmp(argv[1], "seal"))
            execl("/usr/libexec/localpin/localpin-account", "localpin-account", "seal", "--uid", "21061", "--uid", "21062", (char *)0);
        else execl("/usr/libexec/localpin/localpin-account", "localpin-account", "begin-mutation", (char *)0);
        _exit(127);
    }
    int status;
    if (waitpid(target, &status, 0) != target || !WIFSTOPPED(status)) fail("trace initial stop");
    if (ptrace(PTRACE_SETOPTIONS, target, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) fail("trace options");
    bool entering = true, matched = false;
    long hits = 0;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, target, 0, 0)) fail("trace step");
        if (waitpid(target, &status, 0) != target) fail("trace wait");
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            fprintf(stderr, "fault boundary not reached (hits=%ld)\n", hits);
            return 3;
        }
        if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, target, 0, &regs)) fail("trace registers");
            if (entering) { matched = match(target, &regs, argv[2]); if (matched) ++hits; }
            bool selected = matched && hits == nth && (entering == !strcmp(argv[3], "before"));
            if (selected) {
                if (!entering && (long long)regs.rax < 0) fail("selected syscall failed");
                kill(target, SIGKILL);
                if (waitpid(target, &status, 0) != target || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) fail("trace kill verification");
                target = 0;
                printf("{\"triggered\":true,\"selector\":\"%s\",\"side\":\"%s\",\"nth\":%ld}\n", argv[2], argv[3], nth);
                return 0;
            }
            entering = !entering;
        } else if (WSTOPSIG(status) != SIGTRAP) {
            /* No target is allowed to escape a signal stop into unobserved work. */
            fail("unexpected target signal");
        }
    }
}
