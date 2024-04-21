#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include "socket_redir.skel.h"

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

    struct bpf_program *prog_sockops = skel->progs.bpf_sockmap;
    skel->links.bpf_sockmap = bpf_program__attach_cgroup(prog_sockops, cgrp);
    if (!skel->links.bpf_sockmap) {
        puts("fail to attach to cgroup");
        err = 1;
        goto close_cgrp;
    }

    // msg_verdict attach to map sockmap_ops
    struct bpf_program *prog_redir = skel->progs.bpf_redir;
    err = bpf_prog_attach(
        bpf_program__fd(prog_redir),
        bpf_map__fd(skel->maps.sockmap_ops),
        bpf_program__expected_attach_type(prog_redir), 0);
    if (err) {
        puts("fail to attach to map");
        err = 1;
        goto close_cgrp;
    }

    puts("\nSuccess to activate program");
    while (alive) {
        puts(".");
        sleep(1);
    }

    bpf_prog_detach2(
        bpf_program__fd(prog_redir),
        bpf_map__fd(skel->maps.sockmap_ops),
        bpf_program__expected_attach_type(prog_redir));
close_cgrp:
    close(cgrp);
clean_skel:
    socket_redir_bpf__destroy(skel);
	return err;
}