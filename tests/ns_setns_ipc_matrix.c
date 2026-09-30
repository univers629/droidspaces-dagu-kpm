/* SPDX-License-Identifier: GPL-2.0-only */
/* Exercise IPC setns across host and two fake namespaces with same-key queues. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SYS_setns
#define SYS_setns 268
#endif
#ifndef SYS_unshare
#define SYS_unshare 97
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

struct test_message {
    long type;
    char text[96];
};

static int ipc_link(char *out, size_t capacity)
{
    ssize_t length = readlink("/proc/self/ns/ipc", out, capacity - 1U);
    if (length < 0 || (size_t)length >= capacity - 1U) {
        fprintf(stderr, "readlink /proc/self/ns/ipc: %s\n", strerror(errno));
        return -1;
    }
    out[length] = '\0';
    return 0;
}

static int require_link(const char *expected, const char *step)
{
    char actual[128] = "unavailable";
    if (ipc_link(actual, sizeof(actual)) != 0 || strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s IPC link mismatch: expected=%s actual=%s\n",
                step, expected, actual);
        return 0;
    }
    return 1;
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
        fprintf(stderr, "queue receive expected=%s actual=%s errno=%d (%s)\n",
                expected, length < 0 ? "<no-message>" : message.text,
                errno, strerror(errno));
        return 0;
    }
    return 1;
}

static int expect_absent(key_t key, const char *step)
{
    int queue;
    errno = 0;
    queue = msgget(key, 0);
    if (queue >= 0 || errno != ENOENT) {
        fprintf(stderr, "%s expected same-key queue ENOENT, qid=%d errno=%d\n",
                step, queue, errno);
        return 0;
    }
    return 1;
}

static int expect_queue(key_t key, int expected, const char *tag,
                        const char *step)
{
    int queue = msgget(key, 0);
    if (queue < 0 || queue != expected) {
        fprintf(stderr, "%s queue mismatch: expected=%d actual=%d errno=%d\n",
                step, expected, queue, errno);
        return 0;
    }
    if (!receive_tag(queue, tag)) {
        fprintf(stderr, "%s failed tagged receive\n", step);
        return 0;
    }
    return 1;
}

static int remove_queue(key_t key, int queue, const char *step)
{
    int found;
    if (msgctl(queue, IPC_RMID, 0) != 0) {
        fprintf(stderr, "%s IPC_RMID qid=%d: %s\n",
                step, queue, strerror(errno));
        return 0;
    }
    errno = 0;
    found = msgget(key, 0);
    if (found >= 0 || errno != ENOENT) {
        fprintf(stderr, "%s queue survived IPC_RMID: qid=%d errno=%d\n",
                step, found, errno);
        return 0;
    }
    return 1;
}

static int switch_ipc(int fd, const char *expected, const char *step)
{
    if (syscall(SYS_setns, fd, CLONE_NEWIPC) != 0) {
        fprintf(stderr, "setns %s: %s (errno=%d)\n", step, strerror(errno), errno);
        return 0;
    }
    return require_link(expected, step);
}

int main(void)
{
    char host[128] = "unavailable";
    char ns_a[128] = "unavailable";
    char ns_b[128] = "unavailable";
    int host_fd = -1, a_fd = -1, b_fd = -1;
    int host_queue = -1, a_queue = -1, b_queue = -1;
    key_t key = (key_t)(0x51000000U | ((unsigned int)getpid() & 0x000fffffU));
    int failed = 1;
    int state_restored = 0;
    int host_cleaned = 1, a_cleaned = 1, b_cleaned = 1;

    if (ipc_link(host, sizeof(host)) != 0)
        goto cleanup;
    host_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (host_fd < 0) {
        fprintf(stderr, "open host IPC namespace: %s\n", strerror(errno));
        goto cleanup;
    }
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
        if (host_queue < 0 || attempt == 64U) {
            fprintf(stderr, "create host same-key queue: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    if (!send_tag(host_queue, "host-initial")) {
        fprintf(stderr, "send host marker: %s\n", strerror(errno));
        goto cleanup;
    }

    errno = 0;
    if (syscall(SYS_setns, -1, CLONE_NEWIPC) != -1 || errno != EBADF ||
        !require_link(host, "invalid-fd")) {
        fprintf(stderr, "invalid IPC fd did not return EBADF without state change; errno=%d\n",
                errno);
        goto cleanup;
    }
    errno = 0;
    if (syscall(SYS_setns, host_fd, CLONE_NEWPID) != -1 || errno != EINVAL ||
        !require_link(host, "mismatched-flags-host")) {
        fprintf(stderr, "IPC fd with CLONE_NEWPID did not return EINVAL; errno=%d\n", errno);
        goto cleanup;
    }

    if (syscall(SYS_unshare, CLONE_NEWIPC) != 0 ||
        ipc_link(ns_a, sizeof(ns_a)) != 0 || strcmp(host, ns_a) == 0) {
        fprintf(stderr, "create IPC namespace A failed: %s\n", strerror(errno));
        goto cleanup;
    }
    a_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (a_fd < 0 || !expect_absent(key, "A-before-create"))
        goto cleanup;
    a_queue = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    if (a_queue < 0 || !send_tag(a_queue, "A-initial")) {
        fprintf(stderr, "create/send A same-key queue: %s\n", strerror(errno));
        goto cleanup;
    }
    if (!switch_ipc(a_fd, ns_a, "same-A") ||
        !expect_queue(key, a_queue, "A-initial", "same-A") ||
        !switch_ipc(host_fd, host, "A-to-host") ||
        !expect_queue(key, host_queue, "host-initial", "A-to-host"))
        goto cleanup;

    if (syscall(SYS_unshare, CLONE_NEWIPC) != 0 ||
        ipc_link(ns_b, sizeof(ns_b)) != 0 || strcmp(host, ns_b) == 0 ||
        strcmp(ns_a, ns_b) == 0) {
        fprintf(stderr, "create IPC namespace B failed: %s\n", strerror(errno));
        goto cleanup;
    }
    b_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (b_fd < 0 || !expect_absent(key, "B-before-create"))
        goto cleanup;
    b_queue = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    if (b_queue < 0 || !send_tag(b_queue, "B-initial")) {
        fprintf(stderr, "create/send B same-key queue: %s\n", strerror(errno));
        goto cleanup;
    }
    if (!switch_ipc(b_fd, ns_b, "same-B") ||
        !expect_queue(key, b_queue, "B-initial", "same-B"))
        goto cleanup;

    errno = 0;
    if (syscall(SYS_setns, a_fd, CLONE_NEWPID) != -1 || errno != EINVAL ||
        !require_link(ns_b, "mismatched-flags-B")) {
        fprintf(stderr, "IPC fd with CLONE_NEWPID did not return EINVAL in B; errno=%d\n",
                errno);
        goto cleanup;
    }
    errno = 0;
    if (syscall(SYS_setns, -1, CLONE_NEWIPC) != -1 || errno != EBADF ||
        !require_link(ns_b, "invalid-fd-B")) {
        fprintf(stderr, "invalid IPC fd did not return EBADF in B; errno=%d\n", errno);
        goto cleanup;
    }

    if (!send_tag(b_queue, "B-after-switch") ||
        !switch_ipc(a_fd, ns_a, "B-to-A") ||
        !send_tag(a_queue, "A-after-switch") ||
        !expect_queue(key, a_queue, "A-after-switch", "B-to-A") ||
        !switch_ipc(b_fd, ns_b, "A-to-B") ||
        !expect_queue(key, b_queue, "B-after-switch", "A-to-B") ||
        !switch_ipc(host_fd, host, "B-to-host") ||
        !send_tag(host_queue, "host-after-switch") ||
        !expect_queue(key, host_queue, "host-after-switch", "B-to-host"))
        goto cleanup;

    failed = 0;

cleanup:
    /* Attempt to remove each queue only while installed in its own namespace. */
    if (a_queue >= 0)
        a_cleaned = a_fd >= 0 && switch_ipc(a_fd, ns_a, "cleanup-A") &&
                    remove_queue(key, a_queue, "cleanup-A");
    if (b_queue >= 0)
        b_cleaned = b_fd >= 0 && switch_ipc(b_fd, ns_b, "cleanup-B") &&
                    remove_queue(key, b_queue, "cleanup-B");
    if (host_queue >= 0)
        host_cleaned = host_fd >= 0 && switch_ipc(host_fd, host, "cleanup-host") &&
                       remove_queue(key, host_queue, "cleanup-host");
    if (host_fd >= 0 && switch_ipc(host_fd, host, "host-state-restored"))
        state_restored = require_link(host, "host-state-restored");
    if (!state_restored && host_fd >= 0 && switch_ipc(host_fd, host, "final-host-restore"))
        state_restored = 1;
    if (host_fd >= 0)
        close(host_fd);
    if (a_fd >= 0)
        close(a_fd);
    if (b_fd >= 0)
        close(b_fd);
    printf("setns_ipc_matrix=%s host=%s A=%s B=%s key=%ld qid_host=%d qid_A=%d qid_B=%d host_restored=%d queues_cleaned=%d/%d/%d\n",
           !failed && state_restored && host_cleaned && a_cleaned && b_cleaned
               ? "pass" : "fail",
           host, ns_a, ns_b, (long)key, host_queue, a_queue, b_queue,
           state_restored, host_cleaned, a_cleaned, b_cleaned);
    return (!failed && state_restored && host_cleaned && a_cleaned && b_cleaned)
               ? 0 : 1;
}
