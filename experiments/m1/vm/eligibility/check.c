/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Password-free root-private eligibility experiment; never an authorization IPC. */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "state.h"

#define TARGET "localpintest"
#define RECORD_BOUND 4096
#define TALLY_BOUND 65536
struct tally_snapshot { bool valid, exists; struct stat metadata; size_t size; unsigned char data[TALLY_BOUND]; };
static void stop(const char *reason) { fprintf(stderr, "M1 eligibility stopped: %s\n", reason); exit(77); }
static void text(const char *path, char *out, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) stop("guard input unavailable");
    ssize_t size = read(fd, out, capacity - 1);
    char extra;
    if (size < 0 || read(fd, &extra, 1) != 0) stop("guard input invalid");
    close(fd); out[size] = '\0';
}
static void guard(const char *directory)
{
    if (getuid() || geteuid()) stop("guest root required");
    struct stat info;
    if (lstat("/etc/localpin-m1-vm-guard", &info) || !S_ISREG(info.st_mode) ||
        info.st_uid || info.st_gid || info.st_nlink != 1 || (info.st_mode & 07777) != 0600)
        stop("unsafe VM marker");
    char uuid[128], actual[512], expected[512], enforcing[8];
    text("/sys/class/dmi/id/product_uuid", uuid, sizeof(uuid)); uuid[strcspn(uuid, "\r\n")] = '\0';
    if (strlen(uuid) != 36) stop("invalid VM UUID");
    snprintf(expected, sizeof(expected), "LOCALPIN-M1-DISPOSABLE-VM\ntarget=" TARGET "\nuuid=%s\n", uuid);
    text("/etc/localpin-m1-vm-guard", actual, sizeof(actual));
    text("/sys/fs/selinux/enforce", enforcing, sizeof(enforcing));
    if (strcmp(actual, expected) || (strcmp(enforcing, "1") && strcmp(enforcing, "1\n")))
        stop("VM marker or SELinux mismatch");
    if (directory[0] != '/' || lstat(directory, &info) || !S_ISDIR(info.st_mode) ||
        info.st_uid || info.st_gid || (info.st_mode & 07777) != 0700)
        stop("unsafe root-private directory");
    pid_t child = fork();
    if (child == 0) { execl("/usr/bin/systemd-detect-virt", "systemd-detect-virt", "--vm", "--quiet", (char *)NULL); _exit(127); }
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        stop("VM detection failed");
}
static bool local_record(const char *path, char out[RECORD_BOUND])
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (fd < 0) return false;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid || info.st_nlink != 1 || (info.st_mode & 0022)) {
        close(fd); return false;
    }
    FILE *input = fdopen(fd, "r");
    if (input == NULL) { close(fd); return false; }
    char line[RECORD_BOUND];
    size_t total = 0; int found = 0; bool valid = true;
    while (fgets(line, sizeof(line), input)) {
        size_t size = strlen(line); total += size;
        if (!size || line[size - 1] != '\n' || total > 1048576) { valid = false; break; }
        if (!strncmp(line, TARGET ":", sizeof(TARGET))) { memcpy(out, line, size + 1); ++found; }
        explicit_bzero(line, sizeof(line));
    }
    if (ferror(input)) valid = false;
    explicit_bzero(line, sizeof(line)); fclose(input);
    return valid && found == 1;
}
static bool number(const char *field, long *value)
{
    if (!*field) { *value = -1; return true; }
    char *end; errno = 0; *value = strtol(field, &end, 10);
    return !errno && !*end && *value >= -1 && *value <= 1000000;
}
static bool sha512_fixture_hash(const char *hash)
{
    if (strncmp(hash, "$6$", 3)) return false;
    const char *salt = hash + 3, *separator = strchr(salt, '$');
    if (!separator || separator == salt || separator - salt > 16 || strlen(separator + 1) != 86) return false;
    const char *alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (const char *p = salt; p != separator; ++p) if (!strchr(alphabet, *p)) return false;
    for (const char *p = separator + 1; *p; ++p) if (!strchr(alphabet, *p)) return false;
    return strchr("./01", separator[86]) != NULL;
}
/* Return 0 eligible raw fields; 1 identity; 2 locked/empty; 3 account expiry;
   4 password aging; 5 unavailable/malformed. PAM remains an additional gate. */
static int raw_policy(const char *directory, uid_t *uid, char passwd[RECORD_BOUND], char shadow[RECORD_BOUND])
{
    char expected[RECORD_BOUND], path[PATH_MAX]; struct stat info;
    if (snprintf(path, sizeof(path), "%s/identity", directory) >= (int)sizeof(path) ||
        lstat(path, &info) || !S_ISREG(info.st_mode) || info.st_uid || info.st_gid ||
        info.st_nlink != 1 || (info.st_mode & 07777) != 0600) return 1;
    text(path, expected, sizeof(expected));
    if (!local_record("/etc/passwd", passwd) || strcmp(passwd, expected)) return 1;
    struct passwd account, *resolved = NULL; char buffer[16384];
    if (getpwnam_r(TARGET, &account, buffer, sizeof(buffer), &resolved) || !resolved ||
        account.pw_uid < 1000 || account.pw_uid >= 60000 || strcmp(account.pw_passwd, "x")) return 1;
    *uid = account.pw_uid;
    char copy[RECORD_BOUND]; memcpy(copy, passwd, sizeof(copy)); char *cursor = copy, *fields[7];
    for (size_t i = 0; i < 7; ++i) { fields[i] = strsep(&cursor, ":"); if (!fields[i]) return 1; }
    long local_uid, local_gid;
    if (!number(fields[2], &local_uid) || !number(fields[3], &local_gid) ||
        local_uid != (long)account.pw_uid || local_gid != (long)account.pw_gid) return 1;
    int count = 256; gid_t groups[256];
    if (getgrouplist(TARGET, account.pw_gid, groups, &count) < 0) return 1;
    const char *privileged[] = {"root", "wheel", "sudo"};
    for (size_t i = 0; i < 3; ++i) { struct group *group = getgrnam(privileged[i]);
        if (group) for (int j = 0; j < count; ++j) if (groups[j] == group->gr_gid) return 1; }
    if (!local_record("/etc/shadow", shadow)) return 5;
    memcpy(copy, shadow, sizeof(copy)); copy[strcspn(copy, "\n")] = '\0'; cursor = copy; char *s[9];
    for (size_t i = 0; i < 9; ++i) { s[i] = strsep(&cursor, ":"); if (!s[i]) { explicit_bzero(copy, sizeof(copy)); return 5; } }
    int result = 0;
    if (!*s[1] || s[1][0] == '!' || s[1][0] == '*') result = 2;
    else if (!sha512_fixture_hash(s[1])) result = 5;
    long last, maximum, inactive, expires;
    if (!number(s[2], &last) || !number(s[4], &maximum) || !number(s[6], &inactive) || !number(s[7], &expires)) result = 5;
    else { time_t now = time(NULL); long today = now < 0 ? -1 : (long)(now / 86400);
        if (today < 0 || today > 1000000) result = 5;
        else if (expires >= 0 && today >= expires) result = 3;
        else if (last == 0 || last > today || (last >= 0 && maximum >= 0 && today - last >= maximum)) result = 4;
        (void)inactive; /* Expiry at max is already conservatively denied. */ }
    explicit_bzero(copy, sizeof(copy));
    return result;
}
static bool same_stat(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static struct tally_snapshot tally(uid_t uid, bool allow_missing)
{
    struct tally_snapshot s = {0}; struct stat directory;
    if (lstat("/run/faillock", &directory)) { s.valid = allow_missing && errno == ENOENT; return s; }
    if (!S_ISDIR(directory.st_mode) || directory.st_uid || directory.st_gid || (directory.st_mode & 0022)) return s;
    int fd = open("/run/faillock/" TARGET, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { s.valid = allow_missing && errno == ENOENT; return s; }
    s.exists = true;
    if (fstat(fd, &s.metadata) || !S_ISREG(s.metadata.st_mode) || s.metadata.st_uid != uid || s.metadata.st_gid ||
        s.metadata.st_nlink != 1 || (s.metadata.st_mode & 07777) != 0660 || s.metadata.st_size < 0 ||
        s.metadata.st_size > TALLY_BOUND || s.metadata.st_size % 64) { close(fd); return s; }
    while (s.size < (size_t)s.metadata.st_size) { ssize_t n = read(fd, s.data + s.size, (size_t)s.metadata.st_size - s.size);
        if (n <= 0) { close(fd); return s; } s.size += (size_t)n; }
    struct stat after;
    s.valid = fstat(fd, &after) == 0 && same_stat(&s.metadata, &after); close(fd); return s;
}
static bool same_tally(const struct tally_snapshot *a, const struct tally_snapshot *b)
{
    return a->valid && b->valid && a->exists == b->exists && (!a->exists ||
        (same_stat(&a->metadata, &b->metadata) && a->size == b->size && !memcmp(a->data, b->data, a->size)));
}
static bool same_policy_file(const char *actual_path, const char *expected_path)
{
    int a = open(actual_path, O_RDONLY | O_CLOEXEC), b = open(expected_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (a < 0 || b < 0) { if (a >= 0) close(a); if (b >= 0) close(b); return false; }
    struct stat sa, sb;
    bool equal = fstat(a, &sa) == 0 && fstat(b, &sb) == 0 && S_ISREG(sa.st_mode) && S_ISREG(sb.st_mode) &&
        !sa.st_uid && !sa.st_gid && !sb.st_uid && !sb.st_gid && !(sa.st_mode & 0022) &&
        (sb.st_mode & 07777) == 0600 && sa.st_nlink == 1 && sb.st_nlink == 1 &&
        sa.st_size >= 0 && sa.st_size <= 65536 && sa.st_size == sb.st_size;
    unsigned char first[1024], second[1024]; size_t remaining = equal ? (size_t)sa.st_size : 0;
    while (equal && remaining) {
        size_t chunk = remaining < sizeof(first) ? remaining : sizeof(first);
        ssize_t na = read(a, first, chunk), nb = read(b, second, chunk);
        if (na != (ssize_t)chunk || nb != (ssize_t)chunk || memcmp(first, second, chunk)) equal = false;
        remaining -= chunk;
    }
    struct stat after_a, after_b;
    equal = equal && fstat(a, &after_a) == 0 && fstat(b, &after_b) == 0 && same_stat(&sa, &after_a) && same_stat(&sb, &after_b);
    close(a); close(b); return equal;
}
static bool reviewed_policy(const char *directory)
{
    const char *actual[] = {"/etc/pam.d/kde", "/etc/pam.d/password-auth", "/etc/pam.d/postlogin", "/etc/security/faillock.conf"};
    const char *names[] = {"kde", "password-auth", "postlogin", "faillock.conf"};
    for (size_t i = 0; i < 4; ++i) {
        char expected[PATH_MAX];
        if (snprintf(expected, sizeof(expected), "%s/expected-%s", directory, names[i]) >= (int)sizeof(expected) ||
            !same_policy_file(actual[i], expected)) return false;
    }
    return true;
}
static int conversation(int n, const struct pam_message **message, struct pam_response **response, void *data)
{
    (void)n; (void)message; (void)response;
    ++((struct eligibility_fixture *)data)->conversation_calls;
    return PAM_CONV_ERR; /* No credentials, prompts or messages are accepted. */
}
int main(int argc, char **argv)
{
    alarm(20);
    if (argc != 3 || (strcmp(argv[2], "allow-missing-after-baseline") && strcmp(argv[2], "require-tally")))
        stop("private config and baseline-bound tally policy required");
    guard(argv[1]); bool missing = !strcmp(argv[2], "allow-missing-after-baseline");
    char passwd[RECORD_BOUND] = {0}, shadow[RECORD_BOUND] = {0}; uid_t uid = 0;
    int raw = raw_policy(argv[1], &uid, passwd, shadow);
    bool policy_before = reviewed_policy(argv[1]);
    /* If raw fields deny before UID resolution, independently resolve expected UID
       only for counter preservation; no authorization follows. */
    if (!uid) { struct passwd *p = getpwnam(TARGET); if (p) uid = p->pw_uid; }
    struct tally_snapshot before = tally(uid, missing);
    struct eligibility_fixture state = {.marker = ELIGIBILITY_FIXTURE_MARKER};
    struct pam_conv conv = {.conv = conversation, .appdata_ptr = &state};
    int preauth = -1, account = -1; pam_handle_t *handle = NULL;
    if (!raw && before.valid && policy_before) {
        preauth = pam_start_confdir("localpin-m1-preflight", TARGET, &conv, argv[1], &handle);
        if (preauth == PAM_SUCCESS) { preauth = pam_authenticate(handle, PAM_SILENT);
            if (preauth == PAM_SUCCESS) account = pam_acct_mgmt(handle, PAM_SILENT);
            if (pam_end(handle, preauth) != PAM_SUCCESS) stop("preflight cleanup"); }
    }
    char passwd_after[RECORD_BOUND] = {0}, shadow_after[RECORD_BOUND] = {0}; uid_t uid_after = 0;
    int after_raw = raw_policy(argv[1], &uid_after, passwd_after, shadow_after);
    bool identity_unchanged = uid == uid_after && raw == after_raw && !strcmp(passwd, passwd_after) && !strcmp(shadow, shadow_after);
    struct tally_snapshot after = tally(uid, missing);
    bool unchanged = same_tally(&before, &after);
    bool policy_unchanged = policy_before && reviewed_policy(argv[1]);
    state.eligible = policy_unchanged && !raw && preauth == PAM_SUCCESS && account == PAM_SUCCESS && unchanged && identity_unchanged && !state.conversation_calls;
    handle = NULL;
    int gated = pam_start_confdir("localpin-m1-gated", TARGET, &conv, argv[1], &handle);
    if (gated == PAM_SUCCESS) { gated = pam_authenticate(handle, PAM_SILENT);
        if (pam_end(handle, gated) != PAM_SUCCESS) stop("gated cleanup"); }
    printf("{\"raw_result\":%d,\"preauth\":%d,\"account\":%d,\"counter_valid\":%s,\"counter_unchanged\":%s,"
           "\"identity_unchanged\":%s,\"policy_unchanged\":%s,\"conversation_calls\":%d,\"eligible\":%s,\"gated_auth\":%d}\n",
           raw, preauth, account, before.valid ? "true" : "false", unchanged ? "true" : "false",
           identity_unchanged ? "true" : "false", policy_unchanged ? "true" : "false", state.conversation_calls, state.eligible ? "true" : "false", gated);
    explicit_bzero(shadow, sizeof(shadow)); explicit_bzero(shadow_after, sizeof(shadow_after));
    explicit_bzero(before.data, sizeof(before.data)); explicit_bzero(after.data, sizeof(after.data));
    return 0;
}
