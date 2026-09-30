/* SPDX-License-Identifier: GPL-2.0-only */
/* Short-lived, isolated PID/IPC namespace semantics test for Android ARM64. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int ns_link(const char *name, char *out, size_t capacity)
{
    char path[64];
    ssize_t n;
    snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
    n = readlink(path, out, capacity - 1);
    if (n < 0) {
        fprintf(stderr, "readlink %s: %s\n", path, strerror(errno));
        return -1;
    }
    out[n] = '\0';
    return 0;
}

static int check_ipc(void)
{
    char before[128], after[128];
    if (ns_link("ipc", before, sizeof(before)) != 0)
        return 2;
    if (syscall(SYS_unshare, CLONE_NEWIPC) != 0) {
        fprintf(stderr, "unshare(CLONE_NEWIPC): %s\n", strerror(errno));
        return 3;
    }
    if (ns_link("ipc", after, sizeof(after)) != 0)
        return 4;
    printf("ipc before=%s after=%s\n", before, after);
    return strcmp(before, after) == 0 ? 5 : 0;
}

static int check_net(void)
{
    char before[128], after[128];
    if (ns_link("net", before, sizeof(before)) != 0)
        return 2;
    if (syscall(SYS_unshare, CLONE_NEWNET) != 0) {
        fprintf(stderr, "unshare(CLONE_NEWNET): %s\n", strerror(errno));
        return 3;
    }
    if (ns_link("net", after, sizeof(after)) != 0)
        return 4;
    printf("net before=%s after=%s\n", before, after);
    return strcmp(before, after) == 0 ? 5 : 0;
}

static int check_pid(void)
{
    char before[128];
    pid_t child;
    int status;
    if (ns_link("pid", before, sizeof(before)) != 0)
        return 2;
    if (syscall(SYS_unshare, CLONE_NEWPID) != 0) {
        fprintf(stderr, "unshare(CLONE_NEWPID): %s\n", strerror(errno));
        return 3;
    }
    child = fork();
    if (child < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return 4;
    }
    if (child == 0) {
        char after[128];
        int ok = ns_link("pid", after, sizeof(after)) == 0 &&
                 strcmp(before, after) != 0 && getpid() == 1;
        printf("pid before=%s after=%s child_pid=%ld\n",
               before, ok ? after : "(unavailable)", (long)getpid());
        fflush(stdout);
        _exit(ok ? 0 : 5);
    }
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
        return 6;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 7;
}

static int check_ipc_object(void)
{
    const key_t key = 0x44534b50;
    int host_id, status, ok = 0;
    pid_t child;
    struct msqid_ds details;
    struct {
        long type;
        char text[16];
    } message = {1, "host"}, received = {0, ""};

    host_id = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    if (host_id < 0) {
        fprintf(stderr, "host msgget: %s\n", strerror(errno));
        return 2;
    }
    if (msgsnd(host_id, &message, sizeof(message.text), 0) != 0) {
        fprintf(stderr, "host msgsnd: %s\n", strerror(errno));
        goto cleanup;
    }
    child = fork();
    if (child < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        goto cleanup;
    }
    if (child == 0) {
        int isolated_id;
        if (syscall(SYS_unshare, CLONE_NEWIPC) != 0) {
            fprintf(stderr, "unshare(CLONE_NEWIPC): %s\n", strerror(errno));
            _exit(3);
        }
        if (msgget(key, 0) >= 0 || errno != ENOENT) {
            fprintf(stderr, "host message queue visible in new IPC namespace\n");
            _exit(4);
        }
        isolated_id = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
        if (isolated_id < 0) {
            fprintf(stderr, "isolated msgget: %s\n", strerror(errno));
            _exit(5);
        }
        if (msgrcv(isolated_id, &received, sizeof(received.text), 0, IPC_NOWAIT) >= 0 ||
            errno != ENOMSG)
            _exit(9);
        memcpy(message.text, "child", sizeof("child"));
        if (msgsnd(isolated_id, &message, sizeof(message.text), 0) != 0 ||
            msgrcv(isolated_id, &received, sizeof(received.text), 0, IPC_NOWAIT) !=
                (ssize_t)sizeof(received.text) ||
            received.type != 1 || strcmp(received.text, "child") != 0)
            _exit(10);
        if (msgctl(isolated_id, IPC_RMID, NULL) != 0)
            _exit(6);
        _exit(0);
    }
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
        goto cleanup;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        msgctl(host_id, IPC_STAT, &details) == 0 &&
        msgrcv(host_id, &received, sizeof(received.text), 0, IPC_NOWAIT) ==
            (ssize_t)sizeof(received.text) &&
        received.type == 1 && strcmp(received.text, "host") == 0)
        ok = 1;
cleanup:
    if (msgctl(host_id, IPC_RMID, NULL) != 0) {
        fprintf(stderr, "host queue cleanup: %s\n", strerror(errno));
        return 8;
    }
    return ok ? 0 : 7;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s ipc|net|pid|ipc_object\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "ipc") == 0)
        return check_ipc();
    if (strcmp(argv[1], "net") == 0)
        return check_net();
    if (strcmp(argv[1], "pid") == 0)
        return check_pid();
    if (strcmp(argv[1], "ipc_object") == 0)
        return check_ipc_object();
    return 1;
}
