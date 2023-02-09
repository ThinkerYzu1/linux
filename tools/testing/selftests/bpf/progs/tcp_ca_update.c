// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int ca1_cnt = 0;
int ca2_cnt = 0;

#define USEC_PER_SEC 1000000UL

#define min(a, b) ((a) < (b) ? (a) : (b))

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

SEC("struct_ops/ca_update_1_cong_control")
void BPF_PROG(ca_update_1_cong_control, struct sock *sk,
	      const struct rate_sample *rs)
{
	ca1_cnt++;
}

SEC("struct_ops/ca_update_2_cong_control")
void BPF_PROG(ca_update_2_cong_control, struct sock *sk,
	      const struct rate_sample *rs)
{
	ca2_cnt++;
}

SEC("struct_ops/ca_update_ssthresh")
__u32 BPF_PROG(ca_update_ssthresh, struct sock *sk)
{
	return tcp_sk(sk)->snd_ssthresh;
}

SEC("struct_ops/ca_update_undo_cwnd")
__u32 BPF_PROG(ca_update_undo_cwnd, struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

SEC(".struct_ops.link")
struct tcp_congestion_ops ca_update_1 = {
	.cong_control = (void *)ca_update_1_cong_control,
	.ssthresh = (void *)ca_update_ssthresh,
	.undo_cwnd = (void *)ca_update_undo_cwnd,
	.name = "tcp_ca_update",
};

SEC(".struct_ops.link")
struct tcp_congestion_ops ca_update_2 = {
	.cong_control = (void *)ca_update_2_cong_control,
	.ssthresh = (void *)ca_update_ssthresh,
	.undo_cwnd = (void *)ca_update_undo_cwnd,
	.name = "tcp_ca_update",
};
