#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/bpf.h>

#include "socket_redir.skel.h"
#include "syscall.h"

static const char *cgroup_path = "/sys/fs/cgroup/";

static volatile bool alive = true;

static void sig_handler(int _) {
    alive = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void program_setup() {
	libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
}

int main() {
    program_setup();

    struct socket_redir_bpf *skel = socket_redir_bpf__open_and_load();
    if (!skel) {
		puts("Failed to open and load skel");
        return 1;
    }

    int err = 0;

    // sock_ops attach to cgroup
    int cgrp = open(cgroup_path, O_RDONLY | __O_CLOEXEC);
    if (cgrp < 0) {
        puts("fail to open cgroup");
        err = 1;
        goto clean_skel;
    }

    skel->links.bpf_sockmap = bpf_program__attach_cgroup(skel->progs.bpf_sockmap, cgrp);
    if (!skel->links.bpf_sockmap) {
        puts("fail to attach to cgroup");
        err = 1;
        goto close_cgrp;
    }

    // msg_verdict attach to map sockmap_ops
    union bpf_attr attr = {
        .target_fd = bpf_map__fd(skel->maps.sockmap_ops),
        .attach_bpf_fd = bpf_program__fd(skel->progs.bpf_redir),
        .attach_type = BPF_SK_MSG_VERDICT};
    int redir_link = bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
    if (redir_link < 0) {
        puts("fail to attach to map");
        err = 1;
        goto close_cgrp;
    }

    puts("\nSuccess to activate program");
    while (alive) {
        puts(".");
        sleep(1);
    }

    memset(&attr, 0, sizeof(attr));
    attr.target_fd = bpf_program__fd(skel->progs.bpf_sockmap);
    attr.attach_type = BPF_SK_MSG_VERDICT;
    bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
close_cgrp:
    close(cgrp);
clean_skel:
    socket_redir_bpf__destroy(skel);
	return err;
}