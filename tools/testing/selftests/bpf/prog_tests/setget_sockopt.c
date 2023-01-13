// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#define _GNU_SOURCE
#include <sched.h>
#include <linux/socket.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include "test_progs.h"
#include "cgroup_helpers.h"
#include "network_helpers.h"

#include "setget_sockopt.skel.h"

#define CG_NAME "/setget-sockopt-test"

static const char addr4_str[] = "127.0.0.1";
static const char addr6_str[] = "::1";
static struct setget_sockopt *skel;
static int cg_fd;

static int create_netns(void)
{
	if (!ASSERT_OK(unshare(CLONE_NEWNET), "create netns"))
		return -1;

	if (!ASSERT_OK(system("ip link set dev lo up"), "set lo up"))
		return -1;

	if (!ASSERT_OK(system("ip link add dev binddevtest1 type veth peer name binddevtest2"),
		       "add veth"))
		return -1;

	if (!ASSERT_OK(system("ip link set dev binddevtest1 up"),
		       "bring veth up"))
		return -1;

	return 0;
}

static void test_tcp(int family)
{
	struct setget_sockopt__bss *bss = skel->bss;
	int sfd, cfd;

	memset(bss, 0, sizeof(*bss));

	sfd = start_server(family, SOCK_STREAM,
			   family == AF_INET6 ? addr6_str : addr4_str, 0, 0);
	if (!ASSERT_GE(sfd, 0, "start_server"))
		return;

	cfd = connect_to_fd(sfd, 0);
	if (!ASSERT_GE(cfd, 0, "connect_to_fd_server")) {
		close(sfd);
		return;
	}
	close(sfd);
	close(cfd);

	ASSERT_EQ(bss->nr_listen, 1, "nr_listen");
	ASSERT_EQ(bss->nr_connect, 1, "nr_connect");
	ASSERT_EQ(bss->nr_active, 1, "nr_active");
	ASSERT_EQ(bss->nr_passive, 1, "nr_passive");
	ASSERT_EQ(bss->nr_socket_post_create, 2, "nr_socket_post_create");
	ASSERT_EQ(bss->nr_binddev, 2, "nr_bind");
}

static void test_udp(int family)
{
	struct setget_sockopt__bss *bss = skel->bss;
	int sfd;

	memset(bss, 0, sizeof(*bss));

	sfd = start_server(family, SOCK_DGRAM,
			   family == AF_INET6 ? addr6_str : addr4_str, 0, 0);
	if (!ASSERT_GE(sfd, 0, "start_server"))
		return;
	close(sfd);

	ASSERT_GE(bss->nr_socket_post_create, 1, "nr_socket_post_create");
	ASSERT_EQ(bss->nr_binddev, 1, "nr_bind");
}

static void test_ulp(void)
{
	struct setget_sockopt__bss *bss = skel->bss;
	struct tls12_crypto_info_aes_gcm_128 aes128;
	struct sockaddr_in addr;
	socklen_t len;
	int cfd, sfd, fd, ret;

	memset(bss, 0, sizeof(*bss));

	len = sizeof(addr);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = 0;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	sfd = socket(AF_INET, SOCK_STREAM, 0);

	ret = bind(sfd, &addr, sizeof(addr));
	ASSERT_EQ(ret, 0, "bind");
	ret = listen(sfd, 10);
	ASSERT_EQ(ret, 0, "listen");

	ret = getsockname(sfd, &addr, &len);
	ASSERT_EQ(ret, 0, "getsockname");

	ret = connect(fd, &addr, sizeof(addr));
	ASSERT_EQ(ret, 0, "connect");

	cfd = accept(sfd, &addr, &len);
	ASSERT_GE(cfd, 0, "accept");

	close(sfd);

	ASSERT_EQ(bss->nr_write_total, 1, "nr_write_total");
	ASSERT_EQ(bss->nr_write, 1, "nr_write");
	ret = setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls"));
	if (ret != 0) {
		ASSERT_EQ(errno, ENOENT, "setsockopt return ENOENT");
		printf("Failure setting TCP_ULP, testing without tls\n");
		return;
	}

	ret = setsockopt(cfd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls"));
	ASSERT_EQ(ret, 0, "setsockopt");

	ASSERT_EQ(bss->nr_write_total, 1, "nr_write_total");
	ASSERT_EQ(bss->nr_write, 1, "nr_write");
	memset(&aes128, 0, sizeof(aes128));
	aes128.info.version = TLS_1_2_VERSION;
	aes128.info.cipher_type = TLS_CIPHER_AES_GCM_128;

	ret = setsockopt(fd, SOL_TLS, TLS_TX, &aes128, sizeof(aes128));
	ASSERT_EQ(ret, 0, "setsockopt");

	ret = setsockopt(cfd, SOL_TLS, TLS_RX, &aes128, sizeof(aes128));
	ASSERT_EQ(ret, 0, "setsockopt");

	bss->nr_write_total = 0;
	bss->nr_write = 0;
	#if 0
	#elif 1
	char cbuf[CMSG_SPACE(sizeof(char))];
	int cmsg_len = sizeof(char);
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec vec;
	char data[] = "test_read";

	vec.iov_base = data;
	vec.iov_len = sizeof(data);
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_TLS;
	/* test sending non-record types. */
	cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
	cmsg->cmsg_len = CMSG_LEN(cmsg_len);
	*CMSG_DATA(cmsg) = 100;
	msg.msg_controllen = cmsg->cmsg_len;

	ret = sendmsg(fd, &msg, 0);
	ASSERT_GE(ret, 0, "sendmsg");
	#else
	char data[12];
	write(fd, data, sizeof(data));
	ret = read(cfd, data, sizeof(data));
	ASSERT_EQ(ret, sizeof(data), "read");
	#endif

	ASSERT_EQ(bss->nr_write_total, 1, "nr_write_total");
	ASSERT_EQ(bss->nr_write, 1, "nr_write");
	close(fd);
	close(cfd);

	ASSERT_EQ(bss->nr_listen, 1, "nr_listen");
	ASSERT_EQ(bss->nr_connect, 1, "nr_connect");
	ASSERT_EQ(bss->nr_active, 1, "nr_active");
	ASSERT_EQ(bss->nr_passive, 1, "nr_passive");
	ASSERT_EQ(bss->nr_socket_post_create, 2, "nr_socket_post_create");
	ASSERT_EQ(bss->nr_binddev, 2, "nr_bind");
	ASSERT_EQ(bss->nr_write_total, 1, "nr_write_total");
	ASSERT_EQ(bss->nr_write, 1, "nr_write");
}

void test_setget_sockopt(void)
{
	cg_fd = test__join_cgroup(CG_NAME);
	if (cg_fd < 0)
		return;

	if (create_netns())
		goto done;

	skel = setget_sockopt__open();
	if (!ASSERT_OK_PTR(skel, "open skel"))
		goto done;

	strcpy(skel->rodata->veth, "binddevtest1");
	skel->rodata->veth_ifindex = if_nametoindex("binddevtest1");
	if (!ASSERT_GT(skel->rodata->veth_ifindex, 0, "if_nametoindex"))
		goto done;

	if (!ASSERT_OK(setget_sockopt__load(skel), "load skel"))
		goto done;

	skel->links.skops_sockopt =
		bpf_program__attach_cgroup(skel->progs.skops_sockopt, cg_fd);
	if (!ASSERT_OK_PTR(skel->links.skops_sockopt, "attach cgroup"))
		goto done;

	skel->links.socket_post_create =
		bpf_program__attach_cgroup(skel->progs.socket_post_create, cg_fd);
	if (!ASSERT_OK_PTR(skel->links.socket_post_create, "attach_cgroup"))
		goto done;

	skel->links.socket_sock_rcv_skb =
		bpf_program__attach_cgroup(skel->progs.socket_sock_rcv_skb, cg_fd);
	if (!ASSERT_OK_PTR(skel->links.socket_sock_rcv_skb, "attach_cgroup"))
		goto done;

	test_tcp(AF_INET6);
	test_tcp(AF_INET);
	test_udp(AF_INET6);
	test_udp(AF_INET);
	test_ulp();

done:
	setget_sockopt__destroy(skel);
	close(cg_fd);
}
