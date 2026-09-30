/* SPDX-License-Identifier: GPL-2.0-only */
/* Verify setns(pid_for_children) makes the next child PID 1 on Android ARM64. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

struct holder_reply {
    int result;
    int error;
};

static int ns_link_for(pid_t pid, const char *name, char *out, size_t capacity)
{
    char path[128];
    ssize_t length;
    if (pid > 0)
        snprintf(path, sizeof(path), "/proc/%ld/ns/%s", (long)pid, name);
    else
        snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
    length = readlink(path, out, capacity - 1);
    if (length < 0) {
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

static int read_nspid(char *out, size_t capacity)
{
    FILE *file = fopen("/proc/self/status", "r");
    char line[512];
    if (!file)
        return -1;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "NSpid:", 6) == 0) {
            size_t length = strlen(line);
            if (length >= capacity)
                length = capacity - 1;
            memcpy(out, line, length);
            out[length] = '\0';
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    errno = ENOENT;
    return -1;
}

static int nspid_last_is_one(const char *line)
{
    const char *cursor = strchr(line, ':');
    long value = -1;
    if (!cursor)
        return 0;
    ++cursor;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r')
            ++cursor;
        if (!*cursor || *cursor == '\n')
            break;
        if (*cursor < '0' || *cursor > '9')
            return 0;
        value = 0;
        while (*cursor >= '0' && *cursor <= '9') {
            value = value * 10 + (*cursor - '0');
            ++cursor;
        }
        if (*cursor && *cursor != '\n' && *cursor != '\r' &&
            *cursor != ' ' && *cursor != '\t')
            return 0;
    }
    return value == 1;
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

static pid_t waitpid_intr(pid_t child, int *status)
{
    pid_t result;
    do {
        result = waitpid(child, status, 0);
    } while (result < 0 && errno == EINTR);
    return result;
}

static pid_t waitpid_bounded(pid_t child, int *status, unsigned int timeout_ms)
{
    unsigned int elapsed = 0;
    while (elapsed < timeout_ms) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child || (result < 0 && errno != EINTR))
            return result;
        usleep(10000);
        elapsed += 10;
    }
    errno = ETIMEDOUT;
    return 0;
}

static int read_holder_reply(int fd, struct holder_reply *reply)
{
    struct pollfd event = {fd, POLLIN, 0};
    int ready;
    do {
        ready = poll(&event, 1, 10000);
    } while (ready < 0 && errno == EINTR);
    if (ready == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    if (ready < 0)
        return -1;
    return transfer_all(fd, reply, sizeof(*reply), 0);
}

static void close_if_open(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static void holder_main(int status_write, int release_read)
{
    struct holder_reply reply = {0, 0};
    char release_byte;
    ssize_t count;

    if (syscall(SYS_unshare, CLONE_NEWPID) != 0) {
        reply.result = -1;
        reply.error = errno;
    }
    if (transfer_all(status_write, &reply, sizeof(reply), 1) != 0)
        _exit(120);
    close(status_write);

    do {
        count = read(release_read, &release_byte, sizeof(release_byte));
    } while (count < 0 && errno == EINTR);
    close(release_read);
    if (count < 0)
        _exit(121);
    _exit(reply.result == 0 ? 0 : 122);
}

static int restore_host_pending(int host_fd, const char *host_link)
{
    char restored[128] = "unavailable";
    if (syscall(SYS_setns, host_fd, CLONE_NEWPID) != 0) {
        fprintf(stderr, "restore host pid_for_children: %s\n", strerror(errno));
        return -1;
    }
    if (ns_link_for(0, "pid_for_children", restored, sizeof(restored)) != 0 ||
        strcmp(host_link, restored) != 0) {
        fprintf(stderr, "host pid_for_children restore mismatch: expected=%s actual=%s\n",
                host_link, restored);
        return -1;
    }
    return 0;
}

int main(void)
{
    char host_children[128] = "unavailable";
    char target_children[128] = "unavailable";
    char pending_after_setns[128] = "unavailable";
    char restored_children[128] = "unavailable";
    char target_path[128];
    int status_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    int host_fd = -1, target_fd = -1;
    int failed = 0, restore_needed = 0;
    int holder_reaped = 0, probe_reaped = 0;
    pid_t holder = -1, probe = -1;
    struct holder_reply reply = {-1, 0};
    int holder_status = 0, probe_status = 0;

    signal(SIGPIPE, SIG_IGN);

    if (ns_link_for(0, "pid_for_children", host_children,
                    sizeof(host_children)) != 0) {
        failed = 1;
        goto cleanup;
    }
    host_fd = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC);
    if (host_fd < 0) {
        fprintf(stderr, "open host pid_for_children: %s\n", strerror(errno));
        failed = 1;
        goto cleanup;
    }
    if (pipe(status_pipe) != 0 || pipe(release_pipe) != 0) {
        fprintf(stderr, "create holder pipes: %s\n", strerror(errno));
        failed = 1;
        goto cleanup;
    }

    holder = fork();
    if (holder < 0) {
        fprintf(stderr, "fork holder: %s\n", strerror(errno));
        failed = 1;
        goto cleanup;
    }
    if (holder == 0) {
        close(status_pipe[0]);
        close(release_pipe[1]);
        close(host_fd);
        holder_main(status_pipe[1], release_pipe[0]);
    }

    close_if_open(&status_pipe[1]);
    close_if_open(&release_pipe[0]);
    if (read_holder_reply(status_pipe[0], &reply) != 0) {
        fprintf(stderr, "read holder status: %s\n", strerror(errno));
        failed = 1;
        goto cleanup;
    }
    close_if_open(&status_pipe[0]);
    if (reply.result != 0) {
        fprintf(stderr, "holder unshare(CLONE_NEWPID): %s (errno=%d)\n",
                strerror(reply.error), reply.error);
        failed = 1;
        goto cleanup;
    }

    snprintf(target_path, sizeof(target_path),
             "/proc/%ld/ns/pid_for_children", (long)holder);
    if (ns_link_for(holder, "pid_for_children", target_children,
                    sizeof(target_children)) != 0) {
        failed = 1;
        goto cleanup;
    }
    if (strcmp(host_children, target_children) == 0) {
        fprintf(stderr, "holder pid_for_children did not differ from host: %s\n",
                target_children);
        failed = 1;
        goto cleanup;
    }
    target_fd = open(target_path, O_RDONLY | O_CLOEXEC);
    if (target_fd < 0) {
        fprintf(stderr, "open %s: %s\n", target_path, strerror(errno));
        failed = 1;
        goto cleanup;
    }
    if (syscall(SYS_setns, target_fd, CLONE_NEWPID) != 0) {
        fprintf(stderr, "setns holder pid_for_children: %s (errno=%d)\n",
                strerror(errno), errno);
        failed = 1;
        goto cleanup;
    }
    restore_needed = 1;
    if (ns_link_for(0, "pid_for_children", pending_after_setns,
                    sizeof(pending_after_setns)) != 0 ||
        strcmp(target_children, pending_after_setns) != 0) {
        fprintf(stderr, "setns pending namespace mismatch: target=%s current=%s\n",
                target_children, pending_after_setns);
        failed = 1;
        goto cleanup;
    }

    probe = fork();
    if (probe < 0) {
        fprintf(stderr, "fork PID1 probe: %s\n", strerror(errno));
        failed = 1;
        goto cleanup;
    }
    if (probe == 0) {
        char active_pid[128] = "unavailable";
        char nspid[512] = "NSpid: unavailable\n";
        pid_t raw_pid = raw_getpid();
        int pid_link_ok = ns_link_for(0, "pid", active_pid,
                                      sizeof(active_pid)) == 0;
        int nspid_ok = read_nspid(nspid, sizeof(nspid)) == 0;
        int ok = raw_pid == 1 && pid_link_ok &&
                 strcmp(active_pid, target_children) == 0 &&
                 nspid_ok && nspid_last_is_one(nspid);
        printf("setns_pid_for_children_child_raw_pid=%ld pidns=%s target=%s %s",
               (long)raw_pid, active_pid, target_children, nspid);
        fflush(stdout);
        _exit(ok ? 0 : 10);
    }

    if (restore_host_pending(host_fd, host_children) == 0)
        restore_needed = 0;
    else
        failed = 1;

    {
        pid_t waited = waitpid_bounded(probe, &probe_status, 5000);
        if (waited == probe) {
        probe_reaped = 1;
        if (!WIFEXITED(probe_status) || WEXITSTATUS(probe_status) != 0) {
            fprintf(stderr, "PID1 probe child failed: status=0x%x\n", probe_status);
            failed = 1;
        }
        } else {
            fprintf(stderr, "waitpid PID1 probe%s: %s\n",
                    waited == 0 ? " timed out" : "", strerror(errno));
            failed = 1;
            goto cleanup;
        }
    }

cleanup:
    if (restore_needed && host_fd >= 0) {
        if (restore_host_pending(host_fd, host_children) == 0)
            restore_needed = 0;
        else
            failed = 1;
    }
    if (host_fd >= 0 && !restore_needed) {
        if (ns_link_for(0, "pid_for_children", restored_children,
                        sizeof(restored_children)) != 0) {
            failed = 1;
        } else if (strcmp(host_children, restored_children) != 0) {
            fprintf(stderr, "final host pid_for_children mismatch: expected=%s actual=%s\n",
                    host_children, restored_children);
            failed = 1;
        }
    }

    if (probe > 0 && !probe_reaped) {
        int status;
        if (kill(probe, SIGKILL) != 0 && errno != ESRCH)
            fprintf(stderr, "kill probe child: %s\n", strerror(errno));
        if (waitpid_intr(probe, &status) == probe)
            probe_reaped = 1;
        else {
            fprintf(stderr, "reap probe child: %s\n", strerror(errno));
            failed = 1;
        }
    }

    if (release_pipe[1] >= 0) {
        const char release_byte = 'x';
        if (transfer_all(release_pipe[1], (void *)&release_byte,
                         sizeof(release_byte), 1) != 0) {
            fprintf(stderr, "release holder: %s\n", strerror(errno));
            if (holder > 0)
                kill(holder, SIGKILL);
            failed = 1;
        }
        close_if_open(&release_pipe[1]);
    }
    if (holder > 0 && !holder_reaped) {
        pid_t waited = waitpid_bounded(holder, &holder_status, 5000);
        if (waited == holder) {
            holder_reaped = 1;
            if (!WIFEXITED(holder_status) || WEXITSTATUS(holder_status) != 0) {
                fprintf(stderr, "holder exited abnormally: status=0x%x\n",
                        holder_status);
                failed = 1;
            }
        } else {
            fprintf(stderr, "waitpid holder%s: %s\n",
                    waited == 0 ? " timed out" : "", strerror(errno));
            kill(holder, SIGKILL);
            if (waitpid_intr(holder, &holder_status) == holder)
                holder_reaped = 1;
            failed = 1;
        }
    }

    close_if_open(&status_pipe[0]);
    close_if_open(&status_pipe[1]);
    close_if_open(&release_pipe[0]);
    close_if_open(&release_pipe[1]);
    if (target_fd >= 0)
        close_if_open(&target_fd);
    if (host_fd >= 0)
        close_if_open(&host_fd);

    printf("setns_pid_for_children=%s host_children=%s target_children=%s "
           "pending_after_setns=%s restored=%s holder_reaped=%d probe_reaped=%d\n",
           failed ? "fail" : "pass", host_children, target_children,
           pending_after_setns, restored_children, holder_reaped, probe_reaped);
    return failed ? 1 : 0;
}
