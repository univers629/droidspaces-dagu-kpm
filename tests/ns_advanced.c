/* SPDX-License-Identifier: GPL-2.0-only */
/* Extended behavior probes for Dagu's fake PID/IPC namespaces. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_setns
#define SYS_setns 268
#endif
#ifndef SYS_unshare
#define SYS_unshare 97
#endif
#ifndef SYS_clone
#define SYS_clone 220
#endif
#ifndef SYS_mq_open
#define SYS_mq_open 180
#endif
#ifndef SYS_mq_unlink
#define SYS_mq_unlink 181
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

struct dagu_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

struct dagu_mq_attr {
    long flags;
    long maxmsg;
    long msgsize;
    long curmsgs;
    long reserved[4];
};

static int ns_link_for(pid_t pid, const char *name, char *out, size_t capacity)
{
    char path[96];
    ssize_t n;
    if (pid > 0)
        snprintf(path, sizeof(path), "/proc/%ld/ns/%s", (long)pid, name);
    else
        snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
    n = readlink(path, out, capacity - 1);
    if (n < 0) {
        fprintf(stderr, "readlink %s: %s\n", path, strerror(errno));
        return -1;
    }
    out[n] = '\0';
    return 0;
}

/* Raw syscall avoids Bionic's cached getpid value after a direct clone syscall. */
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

static int wait_child_ok(pid_t child)
{
    int status;
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
        return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int check_clone_pid(void)
{
    char host_pid[128], host_ipc[128];
    pid_t child;
    int ok;
    if (ns_link_for(0, "pid", host_pid, sizeof(host_pid)) != 0 ||
        ns_link_for(0, "ipc", host_ipc, sizeof(host_ipc)) != 0)
        return 2;
    child = (pid_t)syscall(SYS_clone, (unsigned long)(CLONE_NEWPID | CLONE_NEWIPC | SIGCHLD),
                           0, 0, 0, 0);
    if (child < 0) {
        printf("clone_pid=failed errno=%d (%s)\n", errno, strerror(errno));
        return 3;
    }
    if (child == 0) {
        char child_pid_ns[128], child_ipc_ns[128], nspid[512];
        pid_t kernel_pid = raw_getpid();
        int pid_ok = ns_link_for(0, "pid", child_pid_ns, sizeof(child_pid_ns)) == 0;
        int ipc_ok = ns_link_for(0, "ipc", child_ipc_ns, sizeof(child_ipc_ns)) == 0;
        int nspid_ok = read_nspid(nspid, sizeof(nspid)) == 0;
        int pid_changed = pid_ok && strcmp(host_pid, child_pid_ns) != 0;
        int ipc_changed = ipc_ok && strcmp(host_ipc, child_ipc_ns) != 0;
        int nspid_one = nspid_ok && nspid_last_is_one(nspid);
        ok = pid_ok && ipc_ok && nspid_ok &&
             pid_changed && kernel_pid == 1 && ipc_changed && nspid_one;
        if (!ok)
            fprintf(stderr, "clone checks failed: pid_ok=%d pid_changed=%d raw=%ld ipc_ok=%d ipc_changed=%d nspid_ok=%d nspid_one=%d host_pid=%s child_pid=%s host_ipc=%s child_ipc=%s\n",
                    pid_ok, pid_changed, (long)kernel_pid, ipc_ok, ipc_changed,
                    nspid_ok, nspid_one, host_pid,
                    pid_ok ? child_pid_ns : "unavailable", host_ipc,
                    ipc_ok ? child_ipc_ns : "unavailable");
        printf("clone_child_pid=%ld libc_getpid=%ld raw_getpid=%ld host_pidns=%s pidns=%s host_ipcns=%s ipcns=%s %s",
               (long)kernel_pid, (long)getpid(), (long)kernel_pid,
               host_pid, pid_ok ? child_pid_ns : "unavailable", host_ipc,
               ipc_ok ? child_ipc_ns : "unavailable",
               nspid_ok ? nspid : "NSpid: unavailable\n");
        fflush(stdout);
        _exit(ok ? 0 : 4);
    }
    ok = wait_child_ok(child);
    printf("clone_pid=%s parent_child_pid=%ld\n", ok ? "pass" : "fail", (long)child);
    return ok ? 0 : 5;
}

static int check_setns_ipc(void)
{
    char host_ns[128];
    int host_fd;
    pid_t child;
    if (ns_link_for(0, "ipc", host_ns, sizeof(host_ns)) != 0)
        return 2;
    host_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
    if (host_fd < 0) {
        fprintf(stderr, "open host ipc ns: %s\n", strerror(errno));
        return 3;
    }
    child = fork();
    if (child < 0) {
        close(host_fd);
        return 4;
    }
    if (child == 0) {
        char fake_ns[128], same_ns[128], restored_ns[128];
        int same_fd, ok = 1;
        if (syscall(SYS_unshare, CLONE_NEWIPC) != 0) {
            fprintf(stderr, "unshare ipc: %s\n", strerror(errno));
            _exit(5);
        }
        if (ns_link_for(0, "ipc", fake_ns, sizeof(fake_ns)) != 0 ||
            strcmp(host_ns, fake_ns) == 0)
            ok = 0;
        same_fd = open("/proc/self/ns/ipc", O_RDONLY | O_CLOEXEC);
        if (same_fd < 0 || syscall(SYS_setns, same_fd, CLONE_NEWIPC) != 0) {
            fprintf(stderr, "setns same fake ipc: %s\n", strerror(errno));
            ok = 0;
        }
        if (same_fd >= 0)
            close(same_fd);
        if (ns_link_for(0, "ipc", same_ns, sizeof(same_ns)) != 0 ||
            strcmp(fake_ns, same_ns) != 0)
            ok = 0;
        if (syscall(SYS_setns, host_fd, CLONE_NEWIPC) != 0) {
            fprintf(stderr, "setns host ipc: %s\n", strerror(errno));
            ok = 0;
        }
        if (ns_link_for(0, "ipc", restored_ns, sizeof(restored_ns)) != 0 ||
            strcmp(host_ns, restored_ns) != 0)
            ok = 0;
        printf("setns_ipc=%s host=%s fake=%s same=%s restored=%s\n",
               ok ? "pass" : "fail", host_ns, fake_ns, same_ns, restored_ns);
        fflush(stdout);
        _exit(ok ? 0 : 6);
    }
    close(host_fd);
    return wait_child_ok(child) ? 0 : 7;
}

static int check_setns_pid(void)
{
    char host_children[128];
    int host_fd;
    pid_t child;
    if (ns_link_for(0, "pid_for_children", host_children, sizeof(host_children)) != 0)
        return 2;
    host_fd = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC);
    if (host_fd < 0) {
        fprintf(stderr, "open host pid_for_children: %s\n", strerror(errno));
        return 3;
    }
    child = fork();
    if (child < 0) {
        close(host_fd);
        return 4;
    }
    if (child == 0) {
        char fake_children[128] = "unavailable", restored[128] = "unavailable";
        char active_pid[128] = "unavailable", nspid[512] = "NSpid: unavailable\n";
        int read_fake, ok = 1;
        pid_t grandchild;
        if (syscall(SYS_unshare, CLONE_NEWPID) != 0) {
            fprintf(stderr, "unshare pid: %s\n", strerror(errno));
            _exit(5);
        }
        read_fake = ns_link_for(0, "pid_for_children", fake_children, sizeof(fake_children));
        if (read_fake != 0 || strcmp(host_children, fake_children) == 0)
            ok = 0;
        if (syscall(SYS_setns, host_fd, CLONE_NEWPID) != 0) {
            fprintf(stderr, "setns host pid_for_children: %s\n", strerror(errno));
            _exit(6);
        }
        if (ns_link_for(0, "pid_for_children", restored, sizeof(restored)) != 0 ||
            strcmp(host_children, restored) != 0)
            ok = 0;
        grandchild = fork();
        if (grandchild < 0)
            _exit(7);
        if (grandchild == 0) {
            int child_ok = raw_getpid() > 1 &&
                ns_link_for(0, "pid", active_pid, sizeof(active_pid)) == 0 &&
                read_nspid(nspid, sizeof(nspid)) == 0 && !nspid_last_is_one(nspid);
            printf("setns_pid_child_pid=%ld pidns=%s %s",
                   (long)raw_getpid(), active_pid, nspid);
            fflush(stdout);
            _exit(child_ok ? 0 : 8);
        }
        if (!wait_child_ok(grandchild))
            ok = 0;
        printf("setns_pid=%s host_children=%s fake_children=%s restored=%s active=%s\n",
               ok ? "pass" : "fail", host_children, fake_children, restored,
               ns_link_for(0, "pid", active_pid, sizeof(active_pid)) == 0 ? active_pid : "unavailable");
        fflush(stdout);
        _exit(ok ? 0 : 9);
    }
    close(host_fd);
    return wait_child_ok(child) ? 0 : 10;
}

static int check_clone3(void)
{
    struct dagu_clone_args args = {0};
    pid_t child;
    args.flags = CLONE_NEWPID | CLONE_NEWIPC;
    args.exit_signal = SIGCHLD;
    child = (pid_t)syscall(SYS_clone3, &args, sizeof(args));
    if (child < 0 && errno == ENOSYS) {
        printf("clone3=unsupported errno=ENOSYS\n");
        return 0;
    }
    if (child < 0) {
        printf("clone3=failed errno=%d (%s)\n", errno, strerror(errno));
        return 11;
    }
    if (child == 0) {
        char pid_ns[128], nspid[512];
        /* Bionic caches getpid(); use the raw syscall like check_clone_pid does. */
        pid_t kernel_pid = raw_getpid();
        int ok = kernel_pid == 1 && ns_link_for(0, "pid", pid_ns, sizeof(pid_ns)) == 0 &&
                 read_nspid(nspid, sizeof(nspid)) == 0 && nspid_last_is_one(nspid);
        printf("clone3_child_pid=%ld libc_getpid=%ld pidns=%s %s",
               (long)kernel_pid, (long)getpid(), pid_ns, nspid);
        fflush(stdout);
        _exit(ok ? 0 : 12);
    }
    if (!wait_child_ok(child))
        return 13;
    printf("clone3=pass\n");
    return 0;
}

static int check_ipc_facilities(void)
{
    key_t key = (key_t)(0x44000000U | ((unsigned int)getpid() & 0x000fffffU));
    int semid, shmid;
    char mq_name[64];
    long queue;
    struct dagu_mq_attr attr = {0, 4, 64, 0, {0, 0, 0, 0}};
    errno = 0;
    semid = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600);
    printf("semget_host=%s errno=%d\n", semid < 0 ? "unsupported-or-failed" : "available", errno);
    if (semid >= 0)
        semctl(semid, 0, IPC_RMID);
    errno = 0;
    shmid = shmget(key + 1, 4096, IPC_CREAT | IPC_EXCL | 0600);
    printf("shmget_host=%s errno=%d\n", shmid < 0 ? "unsupported-or-failed" : "available", errno);
    if (shmid >= 0)
        shmctl(shmid, IPC_RMID, 0);
    snprintf(mq_name, sizeof(mq_name), "/dagu_kpm_%ld", (long)getpid());
    errno = 0;
    queue = syscall(SYS_mq_open, mq_name, O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
    printf("mq_open_host=%s errno=%d\n", queue < 0 ? "unsupported-or-failed" : "available", errno);
    if (queue >= 0) {
        close((int)queue);
        syscall(SYS_mq_unlink, mq_name);
    }
    return 0;
}

static int check_stress(void)
{
    char host_pid[128], host_ipc[128];
    int i;
    if (ns_link_for(0, "pid", host_pid, sizeof(host_pid)) != 0 ||
        ns_link_for(0, "ipc", host_ipc, sizeof(host_ipc)) != 0)
        return 2;
    for (i = 0; i < 32; ++i) {
        pid_t child = fork();
        if (child < 0)
            return 3;
        if (child == 0) {
            char ipc_ns[128];
            pid_t init;
            if (syscall(SYS_unshare, CLONE_NEWPID | CLONE_NEWIPC) != 0) {
                fprintf(stderr, "stress iteration %d unshare failed: %s\n", i,
                        strerror(errno));
                _exit(4);
            }
            if (ns_link_for(0, "ipc", ipc_ns, sizeof(ipc_ns)) != 0 ||
                strcmp(ipc_ns, host_ipc) == 0) {
                fprintf(stderr, "stress iteration %d IPC namespace did not change: %s\n",
                        i, ipc_ns);
                _exit(5);
            }
            init = fork();
            if (init < 0) {
                fprintf(stderr, "stress iteration %d PID1 fork failed: %s\n", i,
                        strerror(errno));
                _exit(6);
            }
            if (init == 0) {
                char pid_ns[128], nspid[512];
                pid_t kernel_pid = raw_getpid();
                int pid_link_ok = ns_link_for(0, "pid", pid_ns, sizeof(pid_ns)) == 0;
                int nspid_ok = read_nspid(nspid, sizeof(nspid)) == 0;
                int pid_changed = pid_link_ok && strcmp(pid_ns, host_pid) != 0;
                int nspid_one = nspid_ok && nspid_last_is_one(nspid);
                int ok = kernel_pid == 1 && pid_changed && nspid_one;
                if (!ok)
                    fprintf(stderr, "stress iteration %d PID1 check failed: raw=%ld pid_link_ok=%d pid_changed=%d host_pidns=%s pidns=%s nspid_ok=%d nspid_one=%d nspid=%s",
                            i, (long)kernel_pid, pid_link_ok, pid_changed, host_pid,
                            pid_link_ok ? pid_ns : "unavailable", nspid_ok,
                            nspid_one, nspid_ok ? nspid : "unavailable\n");
                _exit(ok ? 0 : 7);
            }
            _exit(wait_child_ok(init) ? 0 : 8);
        }
        if (!wait_child_ok(child)) {
            fprintf(stderr, "stress iteration %d failed\n", i);
            return 9;
        }
    }
    printf("namespace_stress=pass iterations=%d\n", i);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s clone_pid|setns_ipc|setns_pid|clone3|ipc_facilities|stress\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "clone_pid") == 0)
        return check_clone_pid();
    if (strcmp(argv[1], "setns_ipc") == 0)
        return check_setns_ipc();
    if (strcmp(argv[1], "setns_pid") == 0)
        return check_setns_pid();
    if (strcmp(argv[1], "clone3") == 0)
        return check_clone3();
    if (strcmp(argv[1], "ipc_facilities") == 0)
        return check_ipc_facilities();
    if (strcmp(argv[1], "stress") == 0)
        return check_stress();
    return 1;
}
