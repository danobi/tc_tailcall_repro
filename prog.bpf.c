#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TC_ACT_SHOT             2
#define TC_ACT_PIPE             3

/*
 * Index 0 prog: `second`
 * Index 1 prog: `third`
 */
struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 2);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
} progs SEC(".maps");

SEC("tc")
int third(struct __sk_buff *skb)
{
	return TC_ACT_PIPE;
}

SEC("tc")
int second(struct __sk_buff *skb)
{
	bpf_tail_call_static(skb, &progs, 1);
	return TC_ACT_SHOT;
}

SEC("tc")
int first(struct __sk_buff *skb)
{
	bpf_tail_call_static(skb, &progs, 0);
	return TC_ACT_SHOT;
}
