/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * canxl-tx.c
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/can.h>
#include <linux/can/raw.h>

int main(int argc, char **argv)
{
	int s;
	struct sockaddr_can addr;

	union {
		struct can_frame cf;
		struct canfd_frame cfd;
		struct canxl_frame cfx;
	} c;

	int nbytes, ret, i;
	int sockopt = 0;

	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}
	addr.can_family = AF_CAN;
	addr.can_ifindex = if_nametoindex("vcan2");

	sockopt = (CAN_RAW_XL_ENABLE | CAN_RAW_XL_RX_DYN);
	ret = setsockopt(s, SOL_CAN_RAW, CAN_RAW_XL_FRAMES, &sockopt, sizeof(sockopt));
	if (ret < 0) {
		perror("sockopt CAN_RAW_XL_FRAMES");
		exit(1);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	while (1) {

		nbytes = read(s, &c.cfx, sizeof(struct canxl_frame));
		if (nbytes < 0) {
			perror("read");
			return 1;
		}
		printf("nbytes = %d\n", nbytes);
		
		if (nbytes < CANXL_HDR_SZ + CANXL_MIN_DLEN) {
			fprintf(stderr, "read: no CAN frame\n");
			return 1;
		}

		if (c.cfx.flags & CANXL_XLF) {
			if (nbytes != CANXL_HDR_SZ + c.cfx.len) {
				printf("nbytes = %d\n", nbytes);
				perror("read canxl_frame");
				continue;
			}
			printf("canxl frame prio %03X len %d flags %d\n",
			       c.cfx.prio, c.cfx.len, c.cfx.flags);
			continue;
		}

		if (nbytes != sizeof(struct can_frame) &&
		    nbytes != sizeof(struct canfd_frame)) {
			fprintf(stderr, "read: incomplete CAN(FD) frame\n");
			return 1;
		} else {
			if (c.cfd.can_id & CAN_EFF_FLAG)
				printf("%8X  ", c.cfd.can_id & CAN_EFF_MASK);
			else
				printf("%3X  ", c.cfd.can_id & CAN_SFF_MASK);

			printf("[%d] ", c.cfd.len);

			for (i = 0; i < c.cfd.len; i++) {
				printf("%02X ", c.cfd.data[i]);
			}
			if (c.cfd.can_id & CAN_RTR_FLAG)
				printf("remote request");
			printf("\n");
			fflush(stdout);
		}
	}

	close(s);

	return 0;
}
