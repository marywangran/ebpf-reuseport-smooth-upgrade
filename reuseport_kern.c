#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define MAX_WORKERS 4

struct session_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int); 
} size_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct session_key);
    __type(value, int); 
} session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, int);
    __type(value, __u32);
} refcnt_map SEC(".maps");

SEC("sk_reuseport")
int reuseport_prog(struct sk_reuseport_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return SK_DROP;

    data += sizeof(*eth);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end)
        return SK_DROP;

    data += ip->ihl * 4;
    struct udphdr *udp = data;
    if (data + sizeof(*udp) > data_end)
        return SK_DROP;

    struct session_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = udp->source,
        .dst_port = udp->dest
    };

    int key0 = 0;

    int *idx = bpf_map_lookup_elem(&session_map, &key);
    if (idx) {
        return *idx;
    }

    int *size = bpf_map_lookup_elem(&size_map, &key0);
    if (!size) {
        __u32 init_size = MAX_WORKERS;
        bpf_map_update_elem(&size_map, &key0, &init_size, BPF_NOEXIST);
    }
    static __u32 rr_counter = 0;
    int _idx = __sync_fetch_and_add(&rr_counter, 1) % MAX_WORKERS;
    int new_idx = size - _idx; // 新 session 只选择最后 MAX_WORKERS 个 worker，让前面 size - MAX_WORKERS 个 worker 自然老化
 
    bpf_map_update_elem(&session_map, &key, &new_idx, BPF_ANY);

    int refcnt_key = (1 << 16) | new_idx;
    __u32 *refcnt = bpf_map_lookup_elem(&refcnt_map, &refcnt_key);
    if (refcnt) {
        __sync_fetch_and_add(refcnt, 1);
    } else {
        __u32 init_refcnt = 1;
        bpf_map_update_elem(&refcnt_map, &refcnt_key, &init_refcnt, BPF_NOEXIST);
    }

    return new_idx;
}
