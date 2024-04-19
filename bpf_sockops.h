#ifndef BPF_SOCKOPS_H
#define BPF_SOCKOPS_H

#include <bpf/bpf_endian.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include "syscall.h"

struct sockmap_key {
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u16 remote_port;
    __u16 local_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct sockmap_key);
    __type(value, __u32);
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} sockmap_ops SEC(".maps");

#endif
