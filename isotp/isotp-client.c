/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * isotp-client.c
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

extern int optind, opterr, optopt;

void print_usage(char *prg)
{
	fprintf(stderr, "\nUsage: %s <CAN interface>\n", prg);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "	  -t <testcase>\n");
	fprintf(stderr, "	  -l <lencase>\n");
	fprintf(stderr, "\n");
}

static void fill_tt_client(struct isotp_testcase *tt,
			   const struct isotp_testcase_description *tcd)
{
	memset(tt, 0, sizeof(*tt));

	tt->addr.can_addr.tp.tx_id = 0x111; /* @@@ */
	tt->addr.can_addr.tp.rx_id = 0x222; /* @@@ */

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
		tt->opts.txpad_content = 0xAA; /* @@@ */
		tt->opts.rxpad_content = 0x55; /* @@@ */
	}

	/* extended addressing */
	if (tcd->extaddr) {
		/* use a different address for isotpdump */
		tt->addr.can_addr.tp.tx_id = 0x555; /* @@@ */
		tt->addr.can_addr.tp.rx_id = 0x666; /* @@@ */

		tt->opts.flags |= CAN_ISOTP_EXTEND_ADDR;
		tt->opts.flags |= CAN_ISOTP_RX_EXT_ADDR;
		tt->opts.ext_address = 0xEE; /* @@@ */
		tt->opts.rx_ext_address = 0xDD; /* @@@ */
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

		tt->xlopts.tx_addr = 0x80111111; /* @@@ */
		tt->xlopts.rx_addr = 0x80222222; /* @@@ */

		if (tcd->vcid) {
			tt->xlopts.tx_vcid = 0xBB; /* @@@ */
			tt->xlopts.rx_vcid = 0xCC; /* @@@ */
		}
	}
}

int main(int argc, char **argv)
{
	int s = 0;
	int r = 0;
	struct sockaddr_can addr;
	struct isotp_testcase tt;
	static struct can_frame cf = {
		.can_id = CRTL_CAN_ID,
		.len = 5
	};
	unsigned char refbuf[BUFSIZE];
	unsigned char buf[BUFSIZE];
	int buflen = 0;
	unsigned int datalen[MAXTESTLEN] = {};
	int tx_dl = 0;
	int opt, retval = 0;
	int testcase = -1;
	int lencase = -1;
	int t, d;

	/* fill the buffer with the increasing pattern */
	for (buflen = 0; buflen < BUFSIZE; buflen++)
		refbuf[buflen] = ((buflen % 0xFF) + 1) & 0xFF;

	while ((opt = getopt(argc, argv, "t:l:?")) != -1) {
		switch (opt) {
		case 't':
			testcase = atoi(optarg);
			if (testcase >= MAXTCD) {
				fprintf(stderr, "read: wrong test case %d\n", testcase);
				return 1;
			}
			break;

		case 'l':
			lencase = atoi(optarg);
			if (lencase >= MAXTESTLEN) {
				fprintf(stderr, "read: wrong length case %d\n", lencase);
				return 1;
			}
			break;

		case '?':
			break;

		default:
			fprintf(stderr, "Unknown option %c\n", opt);
			break;
		}
	}

	if (argc - optind != 1) {
		print_usage(basename(argv[0]));
		exit(0);
	}

	addr.can_family = AF_CAN;
	addr.can_ifindex = if_nametoindex(argv[optind]);
	if (!addr.can_ifindex) {
		perror("if_nametoindex");
		exit(1);
	}

	r = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (r < 0) {
		perror("raw socket");
		exit(1);
	}

	if (setsockopt(r, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0) < 0) {
		perror("raw sockopt");
		exit(1);
	}

	if (bind(r, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("raw bind");
		close(s);
		exit(1);
	}

	for (t = 0; t < MAXTCD; t++) {

		if (testcase >= 0)
			t = testcase;

		fill_tt_client(&tt, &tcd[t]);

		if (tt.llopts.tx_dl)
			tx_dl = tt.llopts.tx_dl;

		if (tt.xlopts.tx_flags & CANXL_XLF)
			tx_dl = tt.xlopts.tx_dl;

		/* generate relevant test length values */
		datalen[0] = 1;
		datalen[1] = 2;
		datalen[2] = 3;
		datalen[3] = 4;
		datalen[4] = tx_dl - 3;
		datalen[5] = tx_dl - 2;
		datalen[6] = tx_dl - 1;
		datalen[7] = tx_dl;
		datalen[8] = tx_dl + 1;
		datalen[9] = 4093;
		datalen[10] = 4094;
		datalen[11] = 4095;
		datalen[12] = 4096;
		datalen[13] = 4097;

		for (d = 0; d < MAXTESTLEN; d++) {

			if (lencase >= 0)
				d = lencase;

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
				if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS,
					       &tt.xlopts, sizeof(tt.xlopts)) < 0) {
					perror("XL link layer sockopt");
					exit(1);
				}
				printf("%s", (tt.xlopts.tx_flags & CANXL_XLF)?"XL":"--");
			} else if (tt.llopts.tx_dl) {
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

			addr.can_family = AF_CAN;
			addr.can_addr.tp.tx_id = tt.addr.can_addr.tp.tx_id;
			addr.can_addr.tp.rx_id = tt.addr.can_addr.tp.rx_id;
			addr.can_ifindex = if_nametoindex(argv[optind]);
			if (!addr.can_ifindex) {
				perror("if_nametoindex");
				exit(1);
			}

			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
				perror("bind");
				close(s);
				exit(1);
			}

			cf.data[0] = t;
			cf.data[1] = d;
			cf.data[2] = (datalen[d] >> 16) & 0xFFU;
			cf.data[3] = (datalen[d] >> 8) & 0xFFU;
			cf.data[4] = datalen[d] & 0xFFU;

			printf(") TX_DL 0x%04X (%04d)", tx_dl, tx_dl);
			printf(" datalength 0x%04X (%04d) ... ", datalen[d], datalen[d]);

			/* send command to isotp-server */
			retval = write(r, &cf, sizeof(cf));
			if (retval < 0) {
				perror("write");
				return retval;
			}

			if (retval != sizeof(cf)) {
				fprintf(stderr, "wrote only %d from %lu byte\n", retval, sizeof(cf));
				exit(1);
			}

			retval = read(s, buf, BUFSIZE);
			if (retval < 0) {
				perror("read");
				return retval;
			}

			if (retval != datalen[d]) {
				fprintf(stderr, "read only %d from %d byte\n", retval, datalen[d]);
				exit(1);
			}

			if (memcmp(buf, refbuf, retval)) {
				fprintf(stderr, "content differs from reference buffer\n");
				exit(1);
			}

			printf("ok\n");
			fflush(stdout);

			close(s);

			if (lencase >= 0)
				d = MAXTESTLEN;
		}
		if (testcase >= 0)
			t = MAXTCD;
	}

	return 0;
}
