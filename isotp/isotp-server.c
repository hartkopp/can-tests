/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * isotp-server.c
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/isotp.h>
#include "testcases.h"

#define BUFSIZE 67000 /* size > 66000 kernel buf to test socket API internal checks */

void print_usage(char *prg)
{
	fprintf(stderr, "\nUsage: %s <CAN interface>\n", prg);
}

static void fill_tt_server(struct isotp_testcase *tt,
			   const struct isotp_testcase_description *tcd)
{
	memset(tt, 0, sizeof(*tt));

	tt->addr.can_addr.tp.tx_id = 0x222; /* @@@ */
	tt->addr.can_addr.tp.rx_id = 0x111; /* @@@ */

	if (tcd->blocksize)
		tt->fcopts.bs = tcd->blocksize & 0xF;

	/* check for optimized PDU */
	if (tcd->check_opt)
		tt->opts.flags |= CAN_ISOTP_RX_PADDING;

	/* padding */
	if (tcd->check_pad) {
		tt->opts.flags |= CAN_ISOTP_TX_PADDING;
		tt->opts.flags |= CAN_ISOTP_RX_PADDING;
		tt->opts.flags |= CAN_ISOTP_CHK_PAD_LEN;
		tt->opts.flags |= CAN_ISOTP_CHK_PAD_DATA;
		tt->opts.txpad_content = 0x55; /* @@@ */
		tt->opts.rxpad_content = 0xAA; /* @@@ */
	}

	/* extended addressing */
	if (tcd->extaddr) {
		/* use a different address for isotpdump */
		tt->addr.can_addr.tp.tx_id = 0x666; /* @@@ */
		tt->addr.can_addr.tp.rx_id = 0x555; /* @@@ */

		tt->opts.flags |= CAN_ISOTP_EXTEND_ADDR;
		tt->opts.flags |= CAN_ISOTP_RX_EXT_ADDR;
		tt->opts.ext_address = 0xDD; /* @@@ */
		tt->opts.rx_ext_address = 0xEE; /* @@@ */
	}

	/* CC/FD/XL specific settings */
	if (tcd->mtu == CAN_MTU) {
		tt->llopts.mtu = CANFD_MTU;
		tt->llopts.tx_dl = tcd->tx_dl;
	} else if (tcd->mtu == CANFD_MTU) {
		tt->llopts.mtu = CANFD_MTU;
		tt->llopts.tx_dl = tcd->tx_dl;
		if (tcd->brs)
			tt->llopts.tx_flags |= CANFD_BRS;
	} else if (tcd->mtu == CANXL_MTU) {
		tt->xlopts.tx_dl = tcd->tx_dl;

		tt->xlopts.tx_flags |= CANXL_XLF;
		if (tcd->sec)
			tt->xlopts.tx_flags |= CANXL_SEC;
		if (tcd->rrs)
			tt->xlopts.tx_flags |= CANXL_RRS;

		tt->xlopts.rx_flags = tt->xlopts.tx_flags;

		tt->xlopts.tx_addr = 0x80222222; /* @@@ */
		tt->xlopts.rx_addr = 0x80111111; /* @@@ */

		if (tcd->vcid) {
			tt->xlopts.tx_vcid = 0xCC; /* @@@ */
			tt->xlopts.rx_vcid = 0xBB; /* @@@ */
		}
	}
}

int main(int argc, char **argv)
{
	int s = 0;
	int r = 0;
	struct sockaddr_can addr;
	struct isotp_testcase tt;
	const struct can_filter rfilter = {
		.can_id = CRTL_CAN_ID,
		.can_mask = CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_SFF_MASK,
	};
	struct can_frame cf;
	unsigned char buf[BUFSIZE];
	int buflen = 0;
	int datalen = 0;
	unsigned int tx_dl = 0;
	int nbytes = 0;
	int t;
	int d;

	/* fill the buffer with the increasing pattern */
	for (buflen = 0; buflen < BUFSIZE; buflen++)
		buf[buflen] = ((buflen % 0xFF) + 1) & 0xFF;

	if (argc != 2) {
		print_usage(basename(argv[0]));
		exit(1);
	}

	addr.can_family = AF_CAN;
	addr.can_ifindex = if_nametoindex(argv[1]);
	if (!addr.can_ifindex) {
		perror("if_nametoindex");
		exit(1);
	}

	r = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (r < 0) {
		perror("raw socket");
		exit(1);
	}

	if (setsockopt(r, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter)) < 0) {
		perror("raw sockopt");
		exit(1);
	}

	if (bind(r, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("raw bind");
		close(s);
		exit(1);
	}

	while (1) {

		nbytes = read(r, &cf, sizeof(struct can_frame));
		if (nbytes < 0) {
			perror("raw read");
			return 1;
		}
		if (nbytes < sizeof(struct can_frame)) {
			fprintf(stderr, "read: incomplete CAN frame\n");
			return 1;
		}
		if (cf.len != 5) {
			fprintf(stderr, "read: wrong CAN length\n");
			return 1;
		}
		t = cf.data[0];
		if (t >= MAXTCD) {
			fprintf(stderr, "read: wrong test case %d\n", t);
			return 1;
		}
		d = cf.data[1];
		if (d >= MAXTESTLEN) {
			fprintf(stderr, "read: wrong length case %d\n", d);
			return 1;
		}

		datalen = cf.data[2] << 16;
		datalen += cf.data[3] << 8;
		datalen += cf.data[4];

		if (datalen >= BUFSIZE) {
			fprintf(stderr, "read: wrong datalen %d\n", datalen);
			return 1;
		}

		fill_tt_server(&tt, &tcd[t]);

		printf("Testcase %02d Lencase %02d (", t, d);

		s = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
		if (s < 0) {
			perror("isotp socket");
			exit(1);
		}

		if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_OPTS,
			       &tt.opts, sizeof(struct can_isotp_options)) < 0) {
			perror("sockopt opts");
			exit(1);
		}

		if (tt.fcopts.bs) {
			if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_RECV_FC,
			       &tt.fcopts, sizeof(struct can_isotp_fc_options)) < 0) {
				perror("sockopt fcopts");
				exit(1);
			}
		}

		if (tt.xlopts.tx_flags & CANXL_XLF) {
			tx_dl = tt.xlopts.tx_dl;
			if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS,
				       &tt.xlopts, sizeof(tt.xlopts)) < 0) {
				perror("XL link layer sockopt");
				exit(1);
			}
			printf("%s", (tt.xlopts.tx_flags & CANXL_XLF)?"XL":"--");
		} else if (tt.llopts.tx_dl) {
			tx_dl = tt.llopts.tx_dl;
			if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS,
				       &tt.llopts, sizeof(tt.llopts)) < 0) {
				perror("link layer sockopt");
				exit(1);
			}
			printf("%s", (tt.llopts.mtu == CANFD_MTU)?"FD":"CC");
		} else {
			printf("wrong LL opts!\n");
			exit(1);
		}

		printf(") TX_DL 0x%04X (%04d)", tx_dl, tx_dl);
		printf(" datalength 0x%04X (%04d) ... ", datalen, datalen);

		/* re-use addr content from raw socket */
		addr.can_addr.tp.tx_id = tt.addr.can_addr.tp.tx_id;
		addr.can_addr.tp.rx_id = tt.addr.can_addr.tp.rx_id;
		if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("bind");
			close(s);
			exit(1);
		}

		nbytes = write(s, buf, datalen);
		if (nbytes < 0) {
			perror("write");
			return nbytes;
		}

		if (nbytes != datalen)
			fprintf(stderr, "wrote only %d from %d byte\n", nbytes, datalen);

		/*
		 * due to a Kernel internal wait queue the PDU is sent completely
		 * before close() returns.
		 */
		close(s);

		printf("ok\n");
		fflush(stdout);
	}

	close(r);

	return 0;
}
