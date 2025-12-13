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

int main(int argc, char **argv)
{
	int s = 0;
	int r = 0;
	struct sockaddr_can addr;
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
		if (cf.len != 4) {
                        fprintf(stderr, "read: wrong CAN length\n");
                        return 1;
                }
		t = cf.data[0];
		if (t >= MAXTC) {
                        fprintf(stderr, "read: wrong test case %d\n", t);
                        return 1;
                }

		datalen = cf.data[1] << 16;
		datalen += cf.data[2] << 8;
		datalen += cf.data[3];

		if (datalen >= BUFSIZE) {
                        fprintf(stderr, "read: wrong datalen %d\n", datalen);
                        return 1;
                }

		printf("Testcase %02d (", t);

		s = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
		if (s < 0) {
			perror("isotp socket");
			exit(1);
		}

		if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_OPTS,
			       &tc[t].opts, sizeof(struct can_isotp_options)) < 0) {
			perror("sockopt");
			exit(1);
		}

		if (tc[t].llopts.mtu) {
			if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS,
				       &tc[t].llopts, sizeof(struct can_isotp_ll_options)) < 0) {
				perror("link layer sockopt");
				exit(1);
			}
			printf("%s", (tc[t].llopts.mtu == CANFD_MTU)?"FD":"CC");
			tx_dl = tc[t].llopts.tx_dl;
		}

		if (tc[t].xlopts.tx_flags & CANXL_XLF) {
			if (setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS,
				       &tc[t].xlopts, sizeof(struct can_isotp_xl_options)) < 0) {
				perror("XL link layer sockopt");
				exit(1);
			}
			printf("%s", (tc[t].xlopts.tx_flags & CANXL_XLF)?"XL":"--");
			tx_dl = tc[t].xlopts.tx_dl;
		}

		printf(") TX_DL 0x%04X (%04d)", tx_dl, tx_dl);
		printf(" datalength 0x%04X (%04d) ... ", datalen, datalen);

		/* re-use addr content from raw socket */
		addr.can_addr.tp.tx_id = tc[t].addr.can_addr.tp.tx_id;
		addr.can_addr.tp.rx_id = tc[t].addr.can_addr.tp.rx_id;
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

		printf("done \n");
		fflush(stdout);
	}

	close(r);

	return 0;
}
