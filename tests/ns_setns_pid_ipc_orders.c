/* SPDX-License-Identifier: GPL-2.0-only */
/* Check both PID/IPC setns orders before forking namespace PID 1. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
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
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

struct holder_report {
    int result;
    int error;
    char pending_pid[128];
};

struct child_report {
    long raw_pid;
    int nspid_last_one;
    int queue_id;
    int tag_received;
    char pid_link[128];
    char ipc_link[128];
    char nspid[512];
};

struct test_message {
    long type;
    char text[96];
};

static int link_for(pid_t pid, const char *name, char *out, size_t capacity)
{
    char path[128];
    int length;
    ssize_t result;
    if (pid > 0)
        length = snprintf(path, sizeof(path), "/proc/%ld/ns/%s", (long)pid, name);
    else
        length = snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
    if (length < 0 || (size_t)length >= sizeof(path) || capacity < 2U)
        return -1;
    result = readlink(path, out, capacity - 1U);
    if (result < 0 || (size_t)result >= capacity - 1U) {
        fprintf(stderr, "readlink %s: %s\n", path, strerror(errno));
        return -1;
    }
    out[result] = '\0';
    return 0;
}

static pid_t raw_getpid(void)
{
    return (pid_t)syscall(SYS_getpid);
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
        if (count <= 0) {
            if (count == 0)
                errno = EPIPE;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int release_process(int fd)
{
    char byte = 'x';
    return transfer_all(fd, &byte, sizeof(byte), 1);
}

static int read_bounded(int fd, void *buffer, size_t length, int timeout_ms)
{
    struct pollfd event = {fd, POLLIN, 0};
    int ready;
    do {
        ready = poll(&event, 1, timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0) {
        if (ready == 0)
            errno = ETIMEDOUT;
        return -1;
    }
    return transfer_all(fd, buffer, length, 0);
}

static pid_t wait_bounded(pid_t child, int *status, unsigned int timeout_ms)
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

static int nspid_last_is_one(char *saved, size_t capacity)
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
        if (capacity > 0U) {
            size_t length = strlen(line);
            if (length >= capacity)
                length = capacity - 1U;
            memcpy(saved, line, length);
            saved[length] = '\0';
        }
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

static int send_tag(int queue, const char *tag)
{
    struct test_message message;
    memset(&message, 0, sizeof(message));
    message.type = 1;
    if (snprintf(message.text, sizeof(message.text), "%s", tag) < 0)
        return 0;
    return msgsnd(queue, &message, sizeof(message.text), IPC_NOWAIT) == 0;
}

static int receive_tag(int queue, const char *expected)
{
    struct test_message message;
    ssize_t length;
    memset(&message, 0, sizeof(message));
    length = msgrcv(queue, &message, sizeof(message.text), 1, IPC_NOWAIT);
    if (length < 0 || strcmp(message.text, expected) != 0) {
        fprintf(stderr, "receive expected=%s actual=%s errno=%d (%s)\n",
                expected, length < 0 ? "<no-message>" : message.text,
                errno, strerror(errno));
        return 0;
    }
    return 1;
}

static int setns_ipc(int fd, const char *expected, const char *step)
{
    char actual[128] = "unavailable";
    if (syscall(SYS_setns, fd, CLONE_NEWIPC) != 0 ||
        link_for(0, "ipc", actual, sizeof(actual)) != 0 ||
        strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s setns IPC mismatch: expected=%s actual=%s errno=%d (%s)\n",
                step, expected, actual, errno, strerror(errno));
        return 0;
    }
    return 1;
}

static int check_pid_state(const char *active, const char *pending,
                           const char *step)
{
    char actual_active[128] = "unavailable";
    char actual_pending[128] = "unavailable";
    if (link_for(0, "pid", actual_active, sizeof(actual_active)) != 0 ||
        link_for(0, "pid_for_children", actual_pending,
                 sizeof(actual_pending)) != 0 ||
        strcmp(actual_active, active) != 0 || strcmp(actual_pending, pending) != 0) {
        fprintf(stderr, "%s PID state mismatch: active=%s/%s pending=%s/%s\n",
                step, actual_active, active, actual_pending, pending);
        return 0;
    }
    return 1;
}

static void holder_main(int status_write, int release_read)
{
    struct holder_report report = {0, 0, "unavailable"};
    char release_byte;
    if (syscall(SYS_unshare, CLONE_NEWPID) != 0) {
        report.result = -1;
        report.error = errno;
    } else if (link_for(0, "pid_for_children", report.pending_pid,
                        sizeof(report.pending_pid)) != 0) {
        report.result = -1;
        report.error = errno ? errno : EIO;
    }
    if (transfer_all(status_write, &report, sizeof(report), 1) != 0)
        _exit(101);
    close(status_write);
    if (read_bounded(release_read, &release_byte, sizeof(release_byte), 15000) != 0)
        _exit(102);
    close(release_read);
    _exit(report.result == 0 ? 0 : 103);
}

static void kill_and_reap(pid_t child)
{
    int status;
    if (child <= 0)
        return;
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
}

static int prepare_pid_target(int host_children_fd, pid_t *holder,
                              int *holder_release_fd, int *target_fd,
                              char *pending_link, size_t pending_capacity)
{
    int status_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    struct holder_report reply = {-1, 0, "unavailable"};
    char target_path[128];
    *holder = -1;
    *holder_release_fd = -1;
    *target_fd = -1;
    if (pipe(status_pipe) != 0 || pipe(release_pipe) != 0) {
        fprintf(stderr, "create holder pipes: %s\n", strerror(errno));
        if (status_pipe[0] >= 0) close(status_pipe[0]);
        if (status_pipe[1] >= 0) close(status_pipe[1]);
        if (release_pipe[0] >= 0) close(release_pipe[0]);
        if (release_pipe[1] >= 0) close(release_pipe[1]);
        return 0;
    }
    *holder = fork();
    if (*holder < 0) {
        fprintf(stderr, "fork PID holder: %s\n", strerror(errno));
        close(status_pipe[0]); close(status_pipe[1]);
        close(release_pipe[0]); close(release_pipe[1]);
        *holder = -1;
        return 0;
    }
    if (*holder == 0) {
        close(status_pipe[0]);
        close(release_pipe[1]);
        close(host_children_fd);
        holder_main(status_pipe[1], release_pipe[0]);
    }
    close(status_pipe[1]);
    close(release_pipe[0]);
    if (read_bounded(status_pipe[0], &reply, sizeof(reply), 5000) != 0 ||
        reply.result != 0) {
        fprintf(stderr, "PID holder failed: errno=%d (%s)\n",
                reply.error, strerror(reply.error));
        close(status_pipe[0]);
        close(release_pipe[1]);
        kill_and_reap(*holder);
        *holder = -1;
        return 0;
    }
    close(status_pipe[0]);
    snprintf(target_path, sizeof(target_path),
             "/proc/%ld/ns/pid_for_children", (long)*holder);
    *target_fd = open(target_path, O_RDONLY | O_CLOEXEC);
    if (*target_fd < 0 || strlen(reply.pending_pid) >= pending_capacity) {
        fprintf(stderr, "open target PID namespace %s: %s\n",
                target_path, strerror(errno));
        if (*target_fd >= 0) close(*target_fd);
        *target_fd = -1;
        close(release_pipe[1]);
        kill_and_reap(*holder);
        *holder = -1;
        return 0;
    }
    memcpy(pending_link, reply.pending_pid, strlen(reply.pending_pid) + 1U);
    *holder_release_fd = release_pipe[1];
    return 1;
}

static int inspect_child(pid_t child, int ready_read,
                         const char *expected_pid, const char *expected_ipc,
                         const char *expected_tag, struct child_report *reply)
{
    char child_pid_link[128] = "unavailable";
    char child_ipc_link[128] = "unavailable";
    int ok;
    memset(reply, 0, sizeof(*reply));
    if (read_bounded(ready_read, reply, sizeof(*reply), 5000) != 0) {
        fprintf(stderr, "read child namespace report: %s\n", strerror(errno));
        return 0;
    }
    ok = reply->raw_pid == 1 && reply->nspid_last_one &&
         reply->queue_id >= 0 && reply->tag_received &&
         strcmp(reply->pid_link, expected_pid) == 0 &&
         strcmp(reply->ipc_link, expected_ipc) == 0;
    if (link_for(child, "pid", child_pid_link, sizeof(child_pid_link)) != 0 ||
        link_for(child, "ipc", child_ipc_link, sizeof(child_ipc_link)) != 0 ||
        strcmp(child_pid_link, expected_pid) != 0 ||
        strcmp(child_ipc_link, expected_ipc) != 0)
        ok = 0;
    printf("child_tag=%s raw_pid=%ld pid=%s ipc=%s NSpid_last_is_1=%d queue=%d tag_received=%d host_proc_pid=%s host_proc_ipc=%s\n",
           expected_tag, reply->raw_pid, reply->pid_link, reply->ipc_link,
           reply->nspid_last_one, reply->queue_id, reply->tag_received,
           child_pid_link, child_ipc_link);
    fflush(stdout);
    return ok;
}

static int check_child_stable(pid_t child, const char *expected_pid,
                              const char *expected_ipc, const char *step,
                              int *already_reaped)
{
    char child_pid_link[128] = "unavailable";
    char child_ipc_link[128] = "unavailable";
    int status;
    pid_t waited;
    if (*already_reaped)
        return 0;
    if (link_for(child, "pid", child_pid_link, sizeof(child_pid_link)) != 0 ||
        link_for(child, "ipc", child_ipc_link, sizeof(child_ipc_link)) != 0 ||
        strcmp(child_pid_link, expected_pid) != 0 ||
        strcmp(child_ipc_link, expected_ipc) != 0) {
        fprintf(stderr, "%s child namespace changed: pid=%s ipc=%s\n",
                step, child_pid_link, child_ipc_link);
        return 0;
    }
    do {
        waited = waitpid(child, &status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == child) {
        *already_reaped = 1;
        fprintf(stderr, "%s child exited before release, status=%d\n", step, status);
        return 0;
    }
    if (waited < 0) {
        fprintf(stderr, "%s waitpid child: %s\n", step, strerror(errno));
        return 0;
    }
    return 1;
}

static int check_parent_and_child(pid_t child, const char *active_pid,
                                  const char *pending_pid, const char *ipc,
                                  const char *child_pid, const char *child_ipc,
                                  const char *step, int *already_reaped)
{
    char actual_ipc[128] = "unavailable";
    if (link_for(0, "ipc", actual_ipc, sizeof(actual_ipc)) != 0 ||
        strcmp(actual_ipc, ipc) != 0) {
        fprintf(stderr, "%s parent IPC mismatch: expected=%s actual=%s\n",
                step, ipc, actual_ipc);
        return 0;
    }
    return check_pid_state(active_pid, pending_pid, step) &&
           check_child_stable(child, child_pid, child_ipc, step, already_reaped);
}

static int remove_queue(key_t key, int queue, const char *step)
{
    int found;
    if (msgctl(queue, IPC_RMID, 0) != 0) {
        fprintf(stderr, "%s IPC_RMID qid=%d: %s\n", step, queue, strerror(errno));
        return 0;
    }
    errno = 0;
    found = msgget(key, 0);
    if (found >= 0 || errno != ENOENT) {
        fprintf(stderr, "%s queue survived removal qid=%d errno=%d\n",
                step, found, errno);
        return 0;
    }
    return 1;
}

static int run_order(const char *order, int first_is_ipc,
                     int host_ipc_fd, const char *host_ipc,
                     int ipc_a_fd, const char *ipc_a,
                     int ipc_b_fd, const char *ipc_b,
                     int host_children_fd, const char *host_pid,
                     const char *host_pending, int target_ipc_fd,
                     const char *target_ipc, const char *tag, key_t key)
{
    pid_t holder = -1, child = -1;
    int holder_release_fd = -1, target_pid_fd = -1;
    int ready_pipe[2] = {-1, -1}, child_release_pipe[2] = {-1, -1};
    char target_pending[128] = "unavailable";
    int child_status = 0, holder_status = 0;
    int ok = 1, child_reaped = 0, child_released = 0, holder_released = 0;
    struct child_report reply;

    if (!prepare_pid_target(host_children_fd, &holder, &holder_release_fd,
                            &target_pid_fd, target_pending, sizeof(target_pending)))
        return 0;
    if (first_is_ipc) {
        if (!setns_ipc(target_ipc_fd, target_ipc, "IPC-before-PID") ||
            syscall(SYS_setns, target_pid_fd, CLONE_NEWPID) != 0 ||
            !check_pid_state(host_pid, target_pending, "IPC-then-PID")) {
            fprintf(stderr, "IPC-then-PID transition failed: errno=%d (%s)\n",
                    errno, strerror(errno));
            ok = 0;
        }
    } else if (syscall(SYS_setns, target_pid_fd, CLONE_NEWPID) != 0 ||
               !check_pid_state(host_pid, target_pending, "PID-before-IPC") ||
               !setns_ipc(target_ipc_fd, target_ipc, "PID-before-IPC")) {
        fprintf(stderr, "PID-then-IPC transition failed: errno=%d (%s)\n",
                errno, strerror(errno));
        ok = 0;
    }
    if (ok && !check_pid_state(host_pid, target_pending, "before-fork"))
        ok = 0;
    if (ok) {
        char actual_ipc[128] = "unavailable";
        if (link_for(0, "ipc", actual_ipc, sizeof(actual_ipc)) != 0 ||
            strcmp(actual_ipc, target_ipc) != 0) {
            fprintf(stderr, "before-fork IPC mismatch: expected=%s actual=%s\n",
                    target_ipc, actual_ipc);
            ok = 0;
        }
    }
    if (!ok)
        goto cleanup;

    if (pipe(ready_pipe) != 0 || pipe(child_release_pipe) != 0) {
        fprintf(stderr, "create child report pipes: %s\n", strerror(errno));
        ok = 0;
        goto cleanup;
    }
    child = fork();
    if (child < 0) {
        fprintf(stderr, "fork namespace PID1 for %s: %s\n", order, strerror(errno));
        ok = 0;
        goto cleanup;
    }
    if (child == 0) {
        struct child_report report;
        char release_byte;
        int queue;
        close(ready_pipe[0]);
        close(child_release_pipe[1]);
        memset(&report, 0, sizeof(report));
        report.raw_pid = (long)raw_getpid();
        report.nspid_last_one = nspid_last_is_one(report.nspid, sizeof(report.nspid));
        if (link_for(0, "pid", report.pid_link, sizeof(report.pid_link)) != 0)
            strcpy(report.pid_link, "unavailable");
        if (link_for(0, "ipc", report.ipc_link, sizeof(report.ipc_link)) != 0)
            strcpy(report.ipc_link, "unavailable");
        queue = msgget(key, 0);
        report.queue_id = queue;
        report.tag_received = queue >= 0 && receive_tag(queue, tag);
        if (transfer_all(ready_pipe[1], &report, sizeof(report), 1) != 0)
            _exit(31);
        close(ready_pipe[1]);
        if (read_bounded(child_release_pipe[0], &release_byte,
                         sizeof(release_byte), 10000) != 0)
            _exit(32);
        close(child_release_pipe[0]);
        _exit(report.raw_pid == 1 && report.nspid_last_one &&
              report.tag_received && strcmp(report.pid_link, target_pending) == 0 &&
              strcmp(report.ipc_link, target_ipc) == 0 ? 0 : 33);
    }
    close(ready_pipe[1]); ready_pipe[1] = -1;
    close(child_release_pipe[0]); child_release_pipe[0] = -1;
    if (!inspect_child(child, ready_pipe[0], target_pending, target_ipc, tag, &reply))
        ok = 0;
    if (!check_parent_and_child(child, host_pid, target_pending, target_ipc,
                                target_pending, target_ipc, "parent-after-fork",
                                &child_reaped))
        ok = 0;
    /* Change only the parent's IPC namespace while the child remains PID 1 in P. */
    if (!setns_ipc(host_ipc_fd, host_ipc, "parent-IPC-host") ||
        !check_parent_and_child(child, host_pid, target_pending, host_ipc,
                                target_pending, target_ipc, "parent-IPC-host",
                                &child_reaped))
        ok = 0;
    if (!setns_ipc(ipc_a_fd, ipc_a, "parent-IPC-A") ||
        !check_parent_and_child(child, host_pid, target_pending, ipc_a,
                                target_pending, target_ipc, "parent-IPC-A",
                                &child_reaped))
        ok = 0;
    if (!setns_ipc(ipc_b_fd, ipc_b, "parent-IPC-B") ||
        !check_parent_and_child(child, host_pid, target_pending, ipc_b,
                                target_pending, target_ipc, "parent-IPC-B",
                                &child_reaped))
        ok = 0;
    if (!setns_ipc(target_ipc_fd, target_ipc, "parent-IPC-target") ||
        !check_parent_and_child(child, host_pid, target_pending, target_ipc,
                                target_pending, target_ipc, "parent-IPC-target",
                                &child_reaped))
        ok = 0;

cleanup:
    if (host_children_fd >= 0 &&
        (syscall(SYS_setns, host_children_fd, CLONE_NEWPID) != 0 ||
         !check_pid_state(host_pid, host_pending, "restore-host-PID-pending"))) {
        fprintf(stderr, "restore host PID-for-children failed in %s: %s\n",
                order, strerror(errno));
        ok = 0;
    }
    if (host_ipc_fd >= 0 && !setns_ipc(host_ipc_fd, host_ipc, "restore-host-IPC"))
        ok = 0;
    if (child > 0 && !child_reaped) {
        if (child_release_pipe[1] >= 0 && release_process(child_release_pipe[1]) == 0)
            child_released = 1;
        if (child_released && wait_bounded(child, &child_status, 5000U) == child) {
            child_reaped = 1;
            if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
                ok = 0;
        } else {
            fprintf(stderr, "%s child failed bounded cleanup; killing PID %ld\n",
                    order, (long)child);
            kill_and_reap(child);
            child_reaped = 1;
            ok = 0;
        }
    }
    if (ready_pipe[0] >= 0) close(ready_pipe[0]);
    if (ready_pipe[1] >= 0) close(ready_pipe[1]);
    if (child_release_pipe[0] >= 0) close(child_release_pipe[0]);
    if (child_release_pipe[1] >= 0) close(child_release_pipe[1]);
    if (!check_pid_state(host_pid, host_pending, "cleanup-host-PID"))
        ok = 0;
    if (holder > 0) {
        if (holder_release_fd >= 0 && release_process(holder_release_fd) == 0)
            holder_released = 1;
        if (holder_released && wait_bounded(holder, &holder_status, 5000U) == holder) {
            if (!WIFEXITED(holder_status) || WEXITSTATUS(holder_status) != 0)
                ok = 0;
        } else {
            fprintf(stderr, "PID holder %ld failed bounded cleanup\n", (long)holder);
            kill_and_reap(holder);
            ok = 0;
        }
    }
    if (holder_release_fd >= 0) close(holder_release_fd);
    if (target_pid_fd >= 0) close(target_pid_fd);
    printf("pid_ipc_order_%s=%s target_pid=%s target_ipc=%s child_pid=%ld host_state_restored=%d\n",
           order, ok ? "pass" : "fail", target_pending, target_ipc,
           (long)child, check_pid_state(host_pid, host_pending, "order-final-host"));
    fflush(stdout);
    return ok;
}

int main(void)
{
    char host_pid[128] = "unavailable";
    char host_pending[128] = "unavailable";
    char host_ipc[128] = "unavailable";
    char ipc_a[128] = "unavailable";
    char ipc_b[128] = "unavailable";
    int host_children_fd = -1, host_ipc_fd = -1;
    int ipc_a_fd = -1, ipc_b_fd = -1;
    int host_queue = -1, ipc_a_queue = -1, ipc_b_queue = -1;
    key_t key = (key_t)(0x52000000U | ((unsigned int)getpid() & 0x000fffffU));
    int failed = 1;
    int order_a_ok = 0, order_b_ok = 0;
    int host_restored = 0;
    int host_cleaned = 1, a_cleaned = 1, b_cleaned = 1;

    signal(SIGPIPE, SIG_IGN);
    if (link_for(0, "pid", host_pid, sizeof(host_pid)) != 0 ||
        link_for(0, "pid_for_children", host_pending, sizeof(host_pending)) != 0 ||
        link_for(0, "ipc", host_ipc, sizeof(host_ipc)) != 0)
        goto cleanup;
    host_children_fd = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC);
    host_ipc_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (host_children_fd < 0 || host_ipc_fd < 0)
        goto cleanup;
    {
        unsigned int attempt;
        for (attempt = 0; attempt < 64U; ++attempt) {
            host_queue = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
            if (host_queue >= 0)
                break;
            if (errno != EEXIST)
                break;
            ++key;
        }
        if (host_queue < 0 || attempt == 64U || !send_tag(host_queue, "host-ipc-pid"))
            goto cleanup;
    }

    if (syscall(SYS_unshare, CLONE_NEWIPC) != 0 ||
        link_for(0, "ipc", ipc_a, sizeof(ipc_a)) != 0 ||
        strcmp(ipc_a, host_ipc) == 0)
        goto cleanup;
    ipc_a_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (ipc_a_fd < 0)
        goto cleanup;
    errno = 0;
    if (msgget(key, 0) >= 0 || errno != ENOENT)
        goto cleanup;
    ipc_a_queue = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    if (ipc_a_queue < 0 || !send_tag(ipc_a_queue, "A-ipc-pid") ||
        !setns_ipc(host_ipc_fd, host_ipc, "setup-A-to-host"))
        goto cleanup;

    if (syscall(SYS_unshare, CLONE_NEWIPC) != 0 ||
        link_for(0, "ipc", ipc_b, sizeof(ipc_b)) != 0 ||
        strcmp(ipc_b, host_ipc) == 0 || strcmp(ipc_b, ipc_a) == 0)
        goto cleanup;
    ipc_b_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (ipc_b_fd < 0)
        goto cleanup;
    errno = 0;
    if (msgget(key, 0) >= 0 || errno != ENOENT)
        goto cleanup;
    ipc_b_queue = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    if (ipc_b_queue < 0 || !send_tag(ipc_b_queue, "B-pid-ipc") ||
        !setns_ipc(host_ipc_fd, host_ipc, "setup-B-to-host"))
        goto cleanup;

    order_a_ok = run_order("IPC_then_PID", 1,
                           host_ipc_fd, host_ipc, ipc_a_fd, ipc_a, ipc_b_fd, ipc_b,
                           host_children_fd, host_pid, host_pending,
                           ipc_a_fd, ipc_a, "A-ipc-pid", key);
    order_b_ok = run_order("PID_then_IPC", 0,
                           host_ipc_fd, host_ipc, ipc_a_fd, ipc_a, ipc_b_fd, ipc_b,
                           host_children_fd, host_pid, host_pending,
                           ipc_b_fd, ipc_b, "B-pid-ipc", key);

    if (!setns_ipc(host_ipc_fd, host_ipc, "main-host-final") ||
        !receive_tag(host_queue, "host-ipc-pid") ||
        !send_tag(host_queue, "host-final") || !receive_tag(host_queue, "host-final"))
        goto cleanup;
    {
        char actual_ipc[128] = "unavailable";
        host_restored = check_pid_state(host_pid, host_pending, "main-host-final") &&
                        link_for(0, "ipc", actual_ipc, sizeof(actual_ipc)) == 0 &&
                        strcmp(actual_ipc, host_ipc) == 0;
    }
    failed = !(order_a_ok && order_b_ok && host_restored);

cleanup:
    if (ipc_a_queue >= 0)
        a_cleaned = ipc_a_fd >= 0 && setns_ipc(ipc_a_fd, ipc_a, "cleanup-A") &&
                    remove_queue(key, ipc_a_queue, "cleanup-A");
    if (ipc_b_queue >= 0)
        b_cleaned = ipc_b_fd >= 0 && setns_ipc(ipc_b_fd, ipc_b, "cleanup-B") &&
                    remove_queue(key, ipc_b_queue, "cleanup-B");
    if (host_queue >= 0)
        host_cleaned = host_ipc_fd >= 0 &&
                       setns_ipc(host_ipc_fd, host_ipc, "cleanup-host") &&
                       remove_queue(key, host_queue, "cleanup-host");
    if (host_children_fd >= 0)
        (void)syscall(SYS_setns, host_children_fd, CLONE_NEWPID);
    if (host_ipc_fd >= 0 && setns_ipc(host_ipc_fd, host_ipc, "final-host-restore"))
        host_restored = check_pid_state(host_pid, host_pending, "final-host-state");
    if (host_children_fd >= 0) close(host_children_fd);
    if (host_ipc_fd >= 0) close(host_ipc_fd);
    if (ipc_a_fd >= 0) close(ipc_a_fd);
    if (ipc_b_fd >= 0) close(ipc_b_fd);
    failed = failed || !(order_a_ok && order_b_ok && host_restored &&
                         host_cleaned && a_cleaned && b_cleaned);
    printf("setns_pid_ipc_orders=%s IPC_then_PID=%s PID_then_IPC=%s host_pid=%s host_pending=%s host_restored=%d queues_cleaned=%d/%d/%d key=%ld qid_host=%d qid_A=%d qid_B=%d\n",
           !failed ? "pass" : "fail", order_a_ok ? "pass" : "fail",
           order_b_ok ? "pass" : "fail", host_pid, host_pending,
           host_restored, host_cleaned, a_cleaned, b_cleaned,
           (long)key, host_queue, ipc_a_queue, ipc_b_queue);
    return !failed ? 0 : 1;
}
