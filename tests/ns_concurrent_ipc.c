/* SPDX-License-Identifier: GPL-2.0-only */
/* Probe SysV queue isolation between two concurrently running fake IPC ns. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SYS_setns
#define SYS_setns 268
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif

struct queue_message {
    long type;
    char text[128];
};

static int parse_positive(const char *text, long maximum, long *value)
{
    char *end = NULL;
    long parsed;
    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno || !end || *end || parsed <= 0 || parsed > maximum)
        return -1;
    *value = parsed;
    return 0;
}

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

static int enter_ipc(int fd, const char *expected_link)
{
    char actual[128];
    if (syscall(SYS_setns, fd, CLONE_NEWIPC) != 0) {
        fprintf(stderr, "setns ipc: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    if (ns_link_for(0, "ipc", actual, sizeof(actual)) != 0 ||
        strcmp(actual, expected_link) != 0) {
        fprintf(stderr, "ipc link mismatch: expected=%s actual=%s\n",
                expected_link, actual);
        return -1;
    }
    return 0;
}

static int require_absent(key_t key)
{
    int id;
    errno = 0;
    id = msgget(key, 0);
    if (id >= 0) {
        fprintf(stderr, "queue unexpectedly visible: key=%d id=%d\n",
                (int)key, id);
        return -1;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "msgget absent probe: expected ENOENT, got %s (%d)\n",
                strerror(errno), errno);
        return -1;
    }
    return 0;
}

static int create_and_send(key_t key, const char *payload)
{
    struct queue_message message;
    size_t length = strlen(payload) + 1U;
    int id;
    if (length > sizeof(message.text)) {
        fprintf(stderr, "payload too long\n");
        return -1;
    }
    id = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    if (id < 0) {
        fprintf(stderr, "msgget create key=%d: %s\n", (int)key, strerror(errno));
        return -1;
    }
    memset(&message, 0, sizeof(message));
    message.type = 1;
    memcpy(message.text, payload, length);
    if (msgsnd(id, &message, length, IPC_NOWAIT) != 0) {
        fprintf(stderr, "msgsnd key=%d: %s\n", (int)key, strerror(errno));
        msgctl(id, IPC_RMID, NULL);
        return -1;
    }
    printf("queue_created key=%d id=%d payload=%s\n", (int)key, id, payload);
    return id;
}

static int consume_and_send(key_t key, const char *expected, const char *next)
{
    struct queue_message message;
    size_t next_length = strlen(next) + 1U;
    ssize_t received;
    int id = msgget(key, 0);
    if (id < 0) {
        fprintf(stderr, "msgget verify key=%d: %s\n", (int)key, strerror(errno));
        return -1;
    }
    memset(&message, 0, sizeof(message));
    received = msgrcv(id, &message, sizeof(message.text), 0, IPC_NOWAIT);
    if (received < 0) {
        fprintf(stderr, "msgrcv key=%d: %s\n", (int)key, strerror(errno));
        return -1;
    }
    if (message.type != 1 || strcmp(message.text, expected) != 0) {
        fprintf(stderr, "message mismatch key=%d expected=%s actual=%s\n",
                (int)key, expected, message.text);
        return -1;
    }
    if (next_length > sizeof(message.text)) {
        fprintf(stderr, "next payload too long\n");
        return -1;
    }
    memset(&message, 0, sizeof(message));
    message.type = 1;
    memcpy(message.text, next, next_length);
    if (msgsnd(id, &message, next_length, IPC_NOWAIT) != 0) {
        fprintf(stderr, "msgsnd keep key=%d: %s\n", (int)key, strerror(errno));
        return -1;
    }
    printf("queue_message_verified key=%d id=%d consumed=%s retained=%s\n",
           (int)key, id, expected, next);
    return 0;
}

static int host_absent(key_t key)
{
    char link[128];
    if (ns_link_for(0, "ipc", link, sizeof(link)) != 0 || require_absent(key) != 0)
        return 1;
    printf("host_queue_absent key=%d ipc=%s\n", (int)key, link);
    return 0;
}

static int prepare_pair(pid_t pid_a, pid_t pid_b, key_t key,
                        const char *marker_a, const char *marker_b)
{
    int host_fd = -1, a_fd = -1, b_fd = -1, host_id = -1;
    char host_link[128] = "unavailable";
    char a_link[128] = "unavailable";
    char b_link[128] = "unavailable";
    int failed = 1;
    if (ns_link_for(0, "ipc", host_link, sizeof(host_link)) != 0)
        goto done;
    host_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (host_fd < 0) {
        fprintf(stderr, "open host namespace fd: %s\n", strerror(errno));
        goto done;
    }
    if (ns_link_for(pid_a, "ipc", a_link, sizeof(a_link)) != 0 ||
        ns_link_for(pid_b, "ipc", b_link, sizeof(b_link)) != 0 ||
        strcmp(host_link, a_link) == 0 || strcmp(host_link, b_link) == 0 ||
        strcmp(a_link, b_link) == 0) {
        fprintf(stderr, "namespace links are not pairwise unique: host=%s A=%s B=%s\n",
                host_link, a_link, b_link);
        goto done;
    }
    /* Open the per-container namespace links after recording their identities. */
    {
        char path_a[128], path_b[128];
        if (snprintf(path_a, sizeof(path_a), "/proc/%ld/ns/ipc", (long)pid_a) >=
                (int)sizeof(path_a) ||
            snprintf(path_b, sizeof(path_b), "/proc/%ld/ns/ipc", (long)pid_b) >=
                (int)sizeof(path_b))
            goto done;
        a_fd = open(path_a, O_RDONLY | O_CLOEXEC);
        b_fd = open(path_b, O_RDONLY | O_CLOEXEC);
        if (a_fd < 0 || b_fd < 0) {
            fprintf(stderr, "open container IPC namespace: %s\n", strerror(errno));
            goto done;
        }
    }
    if (enter_ipc(a_fd, a_link) != 0 || require_absent(key) != 0 ||
        create_and_send(key, marker_a) < 0)
        goto done;
    if (enter_ipc(b_fd, b_link) != 0 || require_absent(key) != 0 ||
        create_and_send(key, marker_b) < 0)
        goto done;
    if (enter_ipc(a_fd, a_link) != 0 ||
        consume_and_send(key, marker_a, "A-live-after-peer-probe") != 0)
        goto done;
    if (enter_ipc(b_fd, b_link) != 0 ||
        consume_and_send(key, marker_b, "B-live-after-peer-probe") != 0)
        goto done;
    if (enter_ipc(host_fd, host_link) != 0 || require_absent(key) != 0)
        goto done;
    host_id = create_and_send(key, "host-isolated") ;
    if (host_id < 0 || consume_and_send(key, "host-isolated", "host-cleanup") != 0)
        goto done;
    if (msgctl(host_id, IPC_RMID, NULL) != 0) {
        fprintf(stderr, "host queue cleanup: %s\n", strerror(errno));
        goto done;
    }
    host_id = -1;
    printf("pair_ipc_isolation=pass host=%s A=%s B=%s key=%d\n",
           host_link, a_link, b_link, (int)key);
    failed = 0;
done:
    if (host_fd >= 0) {
        if (enter_ipc(host_fd, host_link) != 0)
            failed = 1;
    }
    if (host_id >= 0)
        msgctl(host_id, IPC_RMID, NULL);
    if (a_fd >= 0)
        close(a_fd);
    if (b_fd >= 0)
        close(b_fd);
    if (host_fd >= 0)
        close(host_fd);
    return failed ? 1 : 0;
}

static int verify_container(pid_t pid, key_t key,
                            const char *expected, const char *next)
{
    int host_fd = -1, target_fd = -1, failed = 1;
    char host_link[128] = "unavailable", target_link[128] = "unavailable";
    char path[128];
    if (ns_link_for(0, "ipc", host_link, sizeof(host_link)) != 0 ||
        ns_link_for(pid, "ipc", target_link, sizeof(target_link)) != 0)
        goto done;
    host_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (snprintf(path, sizeof(path), "/proc/%ld/ns/ipc", (long)pid) >= (int)sizeof(path))
        goto done;
    target_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (host_fd < 0 || target_fd < 0) {
        fprintf(stderr, "open verification namespace: %s\n", strerror(errno));
        goto done;
    }
    if (enter_ipc(target_fd, target_link) != 0 ||
        consume_and_send(key, expected, next) != 0)
        goto done;
    printf("container_ipc_survived pid=%ld ipc=%s key=%d\n",
           (long)pid, target_link, (int)key);
    failed = 0;
done:
    if (host_fd >= 0 && enter_ipc(host_fd, host_link) != 0)
        failed = 1;
    if (target_fd >= 0)
        close(target_fd);
    if (host_fd >= 0)
        close(host_fd);
    return failed ? 1 : 0;
}

static int create_fresh_container_queue(pid_t pid, key_t key, const char *payload)
{
    int host_fd = -1, target_fd = -1, failed = 1;
    char host_link[128] = "unavailable", target_link[128] = "unavailable";
    char path[128];
    if (ns_link_for(0, "ipc", host_link, sizeof(host_link)) != 0 ||
        ns_link_for(pid, "ipc", target_link, sizeof(target_link)) != 0)
        goto done;
    host_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (snprintf(path, sizeof(path), "/proc/%ld/ns/ipc", (long)pid) >= (int)sizeof(path))
        goto done;
    target_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (host_fd < 0 || target_fd < 0) {
        fprintf(stderr, "open fresh namespace: %s\n", strerror(errno));
        goto done;
    }
    if (enter_ipc(target_fd, target_link) != 0 || require_absent(key) != 0 ||
        create_and_send(key, payload) < 0)
        goto done;
    printf("fresh_container_ipc=pass pid=%ld ipc=%s key=%d\n",
           (long)pid, target_link, (int)key);
    failed = 0;
done:
    if (host_fd >= 0 && enter_ipc(host_fd, host_link) != 0)
        failed = 1;
    if (target_fd >= 0)
        close(target_fd);
    if (host_fd >= 0)
        close(host_fd);
    return failed ? 1 : 0;
}

int main(int argc, char **argv)
{
    long value_a, value_b, value_key;
    if (argc == 3 && strcmp(argv[1], "host-absent") == 0) {
        if (parse_positive(argv[2], INT_MAX, &value_key) != 0)
            return 2;
        return host_absent((key_t)value_key);
    }
    if (argc == 7 && strcmp(argv[1], "prepare-pair") == 0) {
        if (parse_positive(argv[2], INT_MAX, &value_a) != 0 ||
            parse_positive(argv[3], INT_MAX, &value_b) != 0 ||
            parse_positive(argv[4], INT_MAX, &value_key) != 0)
            return 2;
        return prepare_pair((pid_t)value_a, (pid_t)value_b, (key_t)value_key,
                            argv[5], argv[6]);
    }
    if (argc == 6 && strcmp(argv[1], "verify") == 0) {
        if (parse_positive(argv[2], INT_MAX, &value_a) != 0 ||
            parse_positive(argv[3], INT_MAX, &value_key) != 0)
            return 2;
        return verify_container((pid_t)value_a, (key_t)value_key, argv[4], argv[5]);
    }
    if (argc == 5 && strcmp(argv[1], "fresh") == 0) {
        if (parse_positive(argv[2], INT_MAX, &value_a) != 0 ||
            parse_positive(argv[3], INT_MAX, &value_key) != 0)
            return 2;
        return create_fresh_container_queue((pid_t)value_a, (key_t)value_key, argv[4]);
    }
    fprintf(stderr, "usage: %s host-absent KEY | prepare-pair PID_A PID_B KEY MARKER_A MARKER_B | verify PID KEY EXPECTED NEXT | fresh PID KEY PAYLOAD\n",
            argv[0]);
    return 2;
}
