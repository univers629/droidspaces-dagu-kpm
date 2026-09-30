/* SPDX-License-Identifier: GPL-2.0-only */
/* Check PID setns ancestry rules from a non-PID1 task in a fake namespace. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_setns
#define SYS_setns 268
#endif
#ifndef SYS_unshare
#define SYS_unshare 97
#endif
#ifndef SYS_getpid
#define SYS_getpid 172
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

struct probe_report {
    int result;
};

static int ns_link_for(pid_t pid, const char *name, char *out, size_t capacity)
{
    char path[128];
    ssize_t length;
    int count;
    if (pid > 0)
        count = snprintf(path, sizeof(path), "/proc/%ld/ns/%s", (long)pid, name);
    else
        count = snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
    if (count < 0 || (size_t)count >= sizeof(path) || capacity < 2U)
        return -1;
    length = readlink(path, out, capacity - 1U);
    if (length < 0 || (size_t)length >= capacity - 1U) {
        fprintf(stderr, "readlink %s: %s\n", path, strerror(errno));
        return -1;
    }
    out[length] = '\0';
    return 0;
}

static pid_t raw_getpid(void)
{
    return (pid_t)syscall(SYS_getpid);
}

static int nspid_last_is_one(void)
{
    FILE *file = fopen("/proc/self/status", "r");
    char line[512];
    int last = -1;
    if (!file)
        return 0;
    while (fgets(line, sizeof(line), file)) {
        const char *cursor;
        if (strncmp(line, "NSpid:", 6) != 0)
            continue;
        cursor = line + 6;
        while (*cursor) {
            int value = 0;
            while (*cursor == ' ' || *cursor == '\t')
                ++cursor;
            if (*cursor < '0' || *cursor > '9')
                break;
            while (*cursor >= '0' && *cursor <= '9') {
                value = value * 10 + (*cursor - '0');
                ++cursor;
            }
            last = value;
        }
        break;
    }
    fclose(file);
    return last == 1;
}

static int transfer_all(int fd, void *buffer, size_t length, int writing)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = writing
            ? write(fd, (const char *)buffer + offset, length - offset)
            : read(fd, (char *)buffer + offset, length - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count == 0) {
            errno = EPIPE;
            return -1;
        }
        if (count < 0)
            return -1;
        offset += (size_t)count;
    }
    return 0;
}

static pid_t waitpid_bounded(pid_t child, int *status, unsigned int timeout_ms)
{
    unsigned int elapsed = 0;
    while (elapsed < timeout_ms) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child || (result < 0 && errno != EINTR))
            return result;
        usleep(10000);
        elapsed += 10U;
    }
    errno = ETIMEDOUT;
    return 0;
}

static int check_link(const char *name, const char *expected)
{
    char actual[128];
    if (ns_link_for(0, name, actual, sizeof(actual)) != 0)
        return 0;
    return strcmp(actual, expected) == 0;
}

static int run_worker_target(int target_fd, const char *label, int active_fd,
                             const char *active_link, const char *children_link)
{
    pid_t worker = fork();
    int status = 0;
    if (worker < 0) {
        fprintf(stderr, "fork %s worker: %s\n", label, strerror(errno));
        return 0;
    }
    if (worker == 0) {
        int rc, saved_errno, restore_rc = 0;
        char active_before[128] = "unavailable";
        char pending_before[128] = "unavailable";
        char active_after[128] = "unavailable";
        char pending_after[128] = "unavailable";
        int state_ok;
        if (ns_link_for(0, "pid", active_before, sizeof(active_before)) != 0 ||
            ns_link_for(0, "pid_for_children", pending_before,
                        sizeof(pending_before)) != 0 ||
            strcmp(active_before, active_link) != 0 ||
            strcmp(pending_before, children_link) != 0)
            _exit(20);

        errno = 0;
        rc = (int)syscall(SYS_setns, target_fd, CLONE_NEWPID);
        saved_errno = errno;
        /* A rejected direction must not alter state. If the implementation
         * incorrectly accepts it, restore pending A and never fork again. */
        if (rc == 0)
            restore_rc = (int)syscall(SYS_setns, active_fd, CLONE_NEWPID);
        state_ok = ns_link_for(0, "pid", active_after, sizeof(active_after)) == 0 &&
                   ns_link_for(0, "pid_for_children", pending_after,
                               sizeof(pending_after)) == 0 &&
                   strcmp(active_after, active_link) == 0 &&
                   strcmp(pending_after, children_link) == 0;
        printf("active_pid_setns_%s rc=%d errno=%d restore_rc=%d active=%s pending=%s state_restored=%d\n",
               label, rc, saved_errno, restore_rc, active_after, pending_after,
               state_ok);
        fflush(stdout);
        _exit(rc < 0 && saved_errno == EINVAL && restore_rc == 0 && state_ok ? 0 : 21);
    }

    if (waitpid_bounded(worker, &status, 5000U) != worker) {
        fprintf(stderr, "wait %s worker: %s\n", label, strerror(errno));
        kill(worker, SIGKILL);
        while (waitpid(worker, &status, 0) < 0 && errno == EINTR) {}
        return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int check_descendant_switch(int active_fd, const char *active_link)
{
    char active_after[128] = "unavailable";
    char child_pending[128] = "unavailable";
    char restored_pending[128] = "unavailable";
    int child_ns_fd = -1;
    pid_t child;
    int status = 0;
    int ok = 1;

    if (syscall(SYS_unshare, CLONE_NEWPID) != 0) {
        fprintf(stderr, "unshare descendant PID namespace: %s\n", strerror(errno));
        return 0;
    }
    if (ns_link_for(0, "pid_for_children", child_pending,
                    sizeof(child_pending)) != 0 ||
        strcmp(child_pending, active_link) == 0)
        return 0;
    child_ns_fd = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC);
    if (child_ns_fd < 0) {
        fprintf(stderr, "open descendant pid_for_children: %s\n", strerror(errno));
        return 0;
    }
    if (syscall(SYS_setns, child_ns_fd, CLONE_NEWPID) != 0) {
        fprintf(stderr, "setns descendant PID namespace: %s (errno=%d)\n",
                strerror(errno), errno);
        close(child_ns_fd);
        return 0;
    }
    if (ns_link_for(0, "pid", active_after, sizeof(active_after)) != 0 ||
        strcmp(active_after, active_link) != 0 ||
        !check_link("pid_for_children", child_pending))
        ok = 0;

    child = fork();
    if (child < 0) {
        fprintf(stderr, "fork descendant PID1: %s\n", strerror(errno));
        ok = 0;
    } else if (child == 0) {
        char active_child[128] = "unavailable";
        int child_ok = raw_getpid() == 1 &&
            ns_link_for(0, "pid", active_child, sizeof(active_child)) == 0 &&
            strcmp(active_child, child_pending) == 0 && nspid_last_is_one();
        printf("descendant_child_raw_pid=%ld active=%s target=%s NSpid_last_is_1=%d\n",
               (long)raw_getpid(), active_child, child_pending,
               nspid_last_is_one());
        fflush(stdout);
        _exit(child_ok ? 0 : 30);
    } else if (waitpid_bounded(child, &status, 5000U) != child ||
               !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "descendant PID1 probe did not exit cleanly\n");
        if (kill(child, SIGKILL) != 0 && errno != ESRCH)
            fprintf(stderr, "kill descendant probe: %s\n", strerror(errno));
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        ok = 0;
    }

    if (syscall(SYS_setns, active_fd, CLONE_NEWPID) != 0) {
        fprintf(stderr, "restore active A pid_for_children: %s\n", strerror(errno));
        ok = 0;
    }
    if (ns_link_for(0, "pid_for_children", restored_pending,
                    sizeof(restored_pending)) != 0 ||
        strcmp(restored_pending, active_link) != 0 ||
        !check_link("pid", active_link))
        ok = 0;
    printf("descendant_setns=%s active=%s pending_before=%s restored=%s\n",
           ok ? "pass" : "fail", active_after, child_pending, restored_pending);
    fflush(stdout);
    close(child_ns_fd);
    return ok;
}

static void pid1_main(int host_fd, int sibling_fd, int status_write,
                      int release_read, const char *expected_active)
{
    struct probe_report report = {0};
    char active[128] = "unavailable";
    char pending[128] = "unavailable";
    int active_fd = -1;
    char release_byte;
    int status = 0;
    int ok = 1;

    if (raw_getpid() != 1 ||
        ns_link_for(0, "pid", active, sizeof(active)) != 0 ||
        ns_link_for(0, "pid_for_children", pending, sizeof(pending)) != 0 ||
        strcmp(active, expected_active) != 0 || strcmp(pending, expected_active) != 0) {
        fprintf(stderr, "fake PID1 did not start in expected A: active=%s pending=%s target=%s\n",
                active, pending, expected_active);
        ok = 0;
    }
    active_fd = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
    if (active_fd < 0) {
        fprintf(stderr, "open active A pid namespace: %s\n", strerror(errno));
        ok = 0;
    }
    if (ok) {
        pid_t worker;
        /* PID1 stays alive and reaps every worker. The worker is PID2 so an
         * incorrectly accepted ancestor/sibling switch cannot affect reaping. */
        worker = fork();
        if (worker < 0) {
            fprintf(stderr, "fork PID2 ancestry worker: %s\n", strerror(errno));
            ok = 0;
        } else if (worker == 0) {
            int worker_ok;
            char worker_active[128] = "unavailable";
            char worker_pending[128] = "unavailable";
            int state_ok;
            if (raw_getpid() != 2 ||
                ns_link_for(0, "pid", worker_active, sizeof(worker_active)) != 0 ||
                ns_link_for(0, "pid_for_children", worker_pending,
                            sizeof(worker_pending)) != 0 ||
                strcmp(worker_active, expected_active) != 0 ||
                strcmp(worker_pending, expected_active) != 0)
                _exit(40);

            errno = 0;
            if (syscall(SYS_setns, active_fd, CLONE_NEWPID) != 0 || errno != 0)
                _exit(41);
            state_ok = check_link("pid", expected_active) &&
                       check_link("pid_for_children", expected_active);
            printf("active_pid_setns_same rc=0 active=%s pending=%s state_unchanged=%d\n",
                   worker_active, worker_pending, state_ok);
            fflush(stdout);
            worker_ok = state_ok &&
                        check_descendant_switch(active_fd, expected_active);
            /* No fork occurs after the ancestor or sibling probes below. */
            if (!run_worker_target(host_fd, "ancestor_host", active_fd,
                                   expected_active, expected_active))
                worker_ok = 0;
            if (!run_worker_target(sibling_fd, "sibling_B", active_fd,
                                   expected_active, expected_active))
                worker_ok = 0;
            _exit(worker_ok ? 0 : 42);
        }
        if (waitpid_bounded(worker, &status, 15000U) != worker ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "PID2 ancestry worker failed or timed out\n");
            if (kill(worker, SIGKILL) != 0 && errno != ESRCH)
                fprintf(stderr, "kill ancestry worker: %s\n", strerror(errno));
            while (waitpid(worker, &status, 0) < 0 && errno == EINTR) {}
            ok = 0;
        }
    }
    if (active_fd >= 0)
        close(active_fd);
    report.result = ok ? 0 : 1;
    if (transfer_all(status_write, &report, sizeof(report), 1) != 0)
        ok = 0;
    close(status_write);
    if (transfer_all(release_read, &release_byte, sizeof(release_byte), 0) != 0)
        ok = 0;
    close(release_read);
    _exit(ok ? 0 : 1);
}

int main(void)
{
    char host_active[128] = "unavailable";
    char host_children[128] = "unavailable";
    char a_children[128] = "unavailable";
    char b_children[128] = "unavailable";
    int host_fd = -1, a_fd = -1, b_fd = -1;
    int status_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    int failed = 1, restored = 0;
    pid_t pid1 = -1;
    struct probe_report report = {1};
    int child_status = 0;

    signal(SIGPIPE, SIG_IGN);
    if (ns_link_for(0, "pid", host_active, sizeof(host_active)) != 0 ||
        ns_link_for(0, "pid_for_children", host_children,
                    sizeof(host_children)) != 0)
        goto cleanup;
    host_fd = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC);
    if (host_fd < 0) {
        fprintf(stderr, "open host pid_for_children: %s\n", strerror(errno));
        goto cleanup;
    }
    if (syscall(SYS_unshare, CLONE_NEWPID) != 0) {
        fprintf(stderr, "unshare fake A: %s (errno=%d)\n", strerror(errno), errno);
        goto cleanup;
    }
    if (ns_link_for(0, "pid_for_children", a_children,
                    sizeof(a_children)) != 0 ||
        strcmp(a_children, host_children) == 0)
        goto cleanup;
    a_fd = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC);
    if (a_fd < 0)
        goto cleanup;
    if (syscall(SYS_setns, host_fd, CLONE_NEWPID) != 0 ||
        !check_link("pid_for_children", host_children)) {
        fprintf(stderr, "restore host pending after creating A: %s\n", strerror(errno));
        goto cleanup;
    }
    if (syscall(SYS_unshare, CLONE_NEWPID) != 0) {
        fprintf(stderr, "unshare sibling B: %s (errno=%d)\n", strerror(errno), errno);
        goto cleanup;
    }
    if (ns_link_for(0, "pid_for_children", b_children,
                    sizeof(b_children)) != 0 ||
        strcmp(b_children, host_children) == 0 || strcmp(b_children, a_children) == 0)
        goto cleanup;
    b_fd = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC);
    if (b_fd < 0)
        goto cleanup;
    if (syscall(SYS_setns, a_fd, CLONE_NEWPID) != 0 ||
        !check_link("pid_for_children", a_children)) {
        fprintf(stderr, "restore pending A before PID1 fork: %s\n", strerror(errno));
        goto cleanup;
    }
    if (pipe(status_pipe) != 0 || pipe(release_pipe) != 0) {
        fprintf(stderr, "create PID1 pipes: %s\n", strerror(errno));
        goto cleanup;
    }
    pid1 = fork();
    if (pid1 < 0) {
        fprintf(stderr, "fork fake PID1 A: %s\n", strerror(errno));
        goto cleanup;
    }
    if (pid1 == 0) {
        close(status_pipe[0]);
        close(release_pipe[1]);
        pid1_main(host_fd, b_fd, status_pipe[1], release_pipe[0], a_children);
    }
    close(status_pipe[1]); status_pipe[1] = -1;
    close(release_pipe[0]); release_pipe[0] = -1;

    if (syscall(SYS_setns, host_fd, CLONE_NEWPID) != 0 ||
        !check_link("pid_for_children", host_children)) {
        fprintf(stderr, "restore host pending after PID1 fork: %s\n", strerror(errno));
        goto cleanup;
    }
    restored = 1;
    if (transfer_all(status_pipe[0], &report, sizeof(report), 0) != 0) {
        fprintf(stderr, "read PID1 ancestry status: %s\n", strerror(errno));
        goto cleanup;
    }
    if (report.result != 0)
        goto cleanup;
    {
        const char release_byte = 'x';
        if (transfer_all(release_pipe[1], (void *)&release_byte,
                         sizeof(release_byte), 1) != 0) {
            fprintf(stderr, "release fake PID1: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    close(release_pipe[1]); release_pipe[1] = -1;
    if (waitpid_bounded(pid1, &child_status, 5000U) != pid1 ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        fprintf(stderr, "fake PID1 did not exit cleanly\n");
        goto cleanup;
    }
    pid1 = -1;
    if (!check_link("pid", host_active) ||
        !check_link("pid_for_children", host_children))
        goto cleanup;
    failed = 0;

cleanup:
    if (pid1 > 0) {
        const char release_byte = 'x';
        if (release_pipe[1] >= 0)
            (void)transfer_all(release_pipe[1], (void *)&release_byte,
                               sizeof(release_byte), 1);
        kill(pid1, SIGKILL);
        while (waitpid(pid1, &child_status, 0) < 0 && errno == EINTR) {}
    }
    if (status_pipe[0] >= 0)
        close(status_pipe[0]);
    if (status_pipe[1] >= 0)
        close(status_pipe[1]);
    if (release_pipe[0] >= 0)
        close(release_pipe[0]);
    if (release_pipe[1] >= 0)
        close(release_pipe[1]);
    if (!restored && host_fd >= 0) {
        if (syscall(SYS_setns, host_fd, CLONE_NEWPID) == 0)
            restored = 1;
    }
    if (host_fd >= 0)
        close(host_fd);
    if (a_fd >= 0)
        close(a_fd);
    if (b_fd >= 0)
        close(b_fd);
    printf("setns_pid_ancestry=%s host=%s A=%s B=%s pid1_status=%d host_pending_restored=%d\n",
           failed ? "fail" : "pass", host_children, a_children, b_children,
           report.result, restored);
    return failed ? 1 : 0;
}
