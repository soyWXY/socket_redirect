#ifndef __BPF_COMPILER_H_
#define __BPF_COMPILER_H_

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                      unsigned int size)
{
  return syscall(__NR_bpf, cmd, attr, size);
}

#endif /* __BPF_COMPILER_H_ */
