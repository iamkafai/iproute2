/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * link_veth.c	veth driver module
 *
 * Authors:	Pavel Emelianov <xemul@openvz.org>
 */

#include <string.h>
#include <net/if.h>
#include <linux/veth.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpf_util.h"

#include "utils.h"
#include "ip_common.h"

/* META section */
enum {
    IFLA_META_UNSPEC,
    IFLA_META_PEER_INFO,
    IFLA_META_BPF_FD,
    IFLA_META_PEER_BPF_FD,
    IFLA_META_PRIMARY,
    __IFLA_META_MAX,
};

static void print_usage(FILE *f)
{
	printf("Usage: ip link <options> type meta [peer <options>]\n"
	       "To get <options> type 'ip link add help'\n");
}

static void usage(void)
{
	print_usage(stderr);
}

static int get_bpf_fd(struct link_util *lu, int argc, char **argv,
		      struct nlmsghdr *n)
{
	const char *pinned_file;
	int prog_fd;
	int attr;

	while (argc >= 2) {
		if (!strcmp(argv[0], "bpfpeer"))
			attr = IFLA_META_PEER_BPF_FD;
		else if (!strcmp(argv[0], "bpf"))
			attr = IFLA_META_BPF_FD;
		else
			break;

		pinned_file = argv[1];
		prog_fd = bpf_obj_get(pinned_file);
		if (prog_fd == -1) {
			fprintf(stderr, "cannot open pinned bpf file %s: %s\n", pinned_file, strerror(errno));
			return -1;
		}

		addattr_l(n, sizeof(struct iplink_req), attr, &prog_fd,
			  sizeof(prog_fd));
		argc -= 2;
		argv += 2;
	}

	if (argc) {
		fprintf(stderr, "unexpected arg %s\n", argv[0]);
		printf("Usage ip link set dev <ifname> bpf <pinned-bpf-tc-prog-file> bpfpeer <pinned-bpf-tc-prog-file>\n");
	}

	return argc;
}

static int meta_parse_opt(struct link_util *lu, int argc, char **argv,
			  struct nlmsghdr *n)
{
	char *type = NULL;
	int err;
	struct rtattr *data;
	struct ifinfomsg *ifm, *peer_ifm;
	unsigned int ifi_flags, ifi_change, ifi_index;

	if (!strcmp(argv[0], "bpf") || !strcmp(argv[0], "bpfpeer"))
		/* returning here is buggy...but temporary for testing */
		return get_bpf_fd(lu, argc, argv, n);

	if (strcmp(argv[0], "peer") != 0) {
		usage();
		return -1;
	}

	ifm = NLMSG_DATA(n);
	ifi_flags = ifm->ifi_flags;
	ifi_change = ifm->ifi_change;
	ifi_index = ifm->ifi_index;
	ifm->ifi_flags = 0;
	ifm->ifi_change = 0;
	ifm->ifi_index = 0;

	data = addattr_nest(n, 1024, IFLA_META_PEER_INFO);

	n->nlmsg_len += sizeof(struct ifinfomsg);

	err = iplink_parse(argc - 1, argv + 1, (struct iplink_req *)n, &type);
	if (err < 0)
		return err;

	if (type)
		duparg("type", argv[err]);

	peer_ifm = RTA_DATA(data);
	peer_ifm->ifi_index = ifm->ifi_index;
	peer_ifm->ifi_flags = ifm->ifi_flags;
	peer_ifm->ifi_change = ifm->ifi_change;
	ifm->ifi_flags = ifi_flags;
	ifm->ifi_change = ifi_change;
	ifm->ifi_index = ifi_index;

	addattr_nest_end(n, data);
	return argc - 1 - err;
}

static void meta_print_help(struct link_util *lu, int argc, char **argv,
	FILE *f)
{
	print_usage(f);
}

struct link_util meta_link_util = {
	.id = "meta",
	.parse_opt = meta_parse_opt,
	.print_help = meta_print_help,
};
