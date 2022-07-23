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
		struct can_frame cc;
		struct canfd_frame fd;
		struct canxl_frame xl;
	} can;

	int nbytes, ret, i;
	int sockopt = 0;

	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}
	addr.can_family = AF_CAN;
	addr.can_ifindex = if_nametoindex("vcan2");

	sockopt = 1;
	ret = setsockopt(s, SOL_CAN_RAW, CAN_RAW_XL_FRAMES,
			 &sockopt, sizeof(sockopt));
	if (ret < 0) {
		perror("sockopt CAN_RAW_XL_FRAMES");
		exit(1);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	can.cc.can_id = 0x123;
	can.cc.len = 2;
	memset(can.cc.data, 0x11, CAN_MAX_DLEN);

	nbytes = write(s, &can.cc, sizeof(struct can_frame));
	if (nbytes != sizeof(struct can_frame)) {
		printf("nbytes = %d\n", nbytes);
		perror("write can_frame");
		exit(1);
	}

	can.fd.can_id = 0x234;
	can.fd.len = 20;
	memset(can.fd.data, 0x22, CANFD_MAX_DLEN);

	nbytes = write(s, &can.fd, sizeof(struct canfd_frame));
	if (nbytes != sizeof(struct canfd_frame)) {
		printf("nbytes = %d\n", nbytes);
		perror("write canfd_frame");
		exit(1);
	}

	can.xl.prio = 0x345;
	can.xl.len = 200;
	can.xl.flags = CANXL_XLF;
	memset(can.xl.data, 0x33, CANXL_MAX_DLEN);

	nbytes = write(s, &can.xl, CANXL_HDR_SIZE + can.xl.len);
	if (nbytes != CANXL_HDR_SIZE + can.xl.len) {
		printf("nbytes = %d\n", nbytes);
		perror("write canxl_frame");
		exit(1);
	}

	while (0) {

		nbytes = read(s, &can.cc, sizeof(struct can_frame));
		if (nbytes < 0) {
			perror("read");
			return 1;
		} else if (nbytes < sizeof(struct can_frame)) {
			fprintf(stderr, "read: incomplete CAN frame\n");
			return 1;
		} else {
			if (can.cc.can_id & CAN_EFF_FLAG)
				printf("%8X  ", can.cc.can_id & CAN_EFF_MASK);
			else
				printf("%3X  ", can.cc.can_id & CAN_SFF_MASK);

			printf("[%d] ", can.cc.len);

			for (i = 0; i < can.cc.len; i++) {
				printf("%02X ", can.cc.data[i]);
			}
			if (can.cc.can_id & CAN_RTR_FLAG)
				printf("remote request");
			printf("\n");
			fflush(stdout);
		}
	}

	close(s);

	return 0;
}
