#include "bpf_sockops.h"

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{    
    struct sockmap_key skm_key = {
        .family = msg->family,
        .remote_ip4 = msg->remote_ip4,
        .local_ip4  = msg->local_ip4,
        .remote_port  = msg->local_port,
        .local_port = bpf_ntohl(msg->remote_port),
    };

    if (msg->family != AF_INET)
        return SK_PASS;

    if (msg->remote_ip4 != msg->local_ip4)
        return SK_PASS;
    
    int ret = bpf_msg_redirect_hash(msg, &sockmap_ops, &skm_key, BPF_F_INGRESS);
    if (ret != SK_PASS)
        bpf_printk("redirect failed\n");

    return SK_PASS;
}

static inline void update_sockmap_ops(struct bpf_sock_ops *skops)
{
    struct sockmap_key skm_key = {
        .family = skops->family,
        .remote_ip4 = skops->remote_ip4,
        .local_ip4  = skops->local_ip4,
        .remote_port  = bpf_ntohl(skops->remote_port),
        .local_port = skops->local_port,
    };
    
    int ret;
    ret = bpf_sock_hash_update(skops, &sockmap_ops, &skm_key, BPF_NOEXIST);
    
    if (ret) {
        bpf_printk("Update map failed. %d\n", -ret);
        return;
    }
}

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    /* Only support IPv4 */
    if (skops->family != AF_INET)
        return 0;

    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            update_sockmap_ops(skops);
            break;
        default:
            break;
    }

    return 0;
}

SEC("license") const char __license[] = "GPL";