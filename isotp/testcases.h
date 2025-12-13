/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * testcases.h
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */
#include <linux/can.h>
#include <linux/can/isotp.h>

struct isotp_testcase {
	struct sockaddr_can addr;
	struct can_isotp_options opts;
	struct can_isotp_ll_options llopts;
	struct can_isotp_xl_options xlopts;
};

const struct isotp_testcase tc[] = {
	{
		.addr.can_addr.tp.tx_id = 0x111,
		.addr.can_addr.tp.rx_id = 0x222,
		.llopts.mtu = CAN_MTU,
		.llopts.tx_dl = CAN_MAX_DLEN,
	},
	{
		.addr.can_addr.tp.tx_id = 0x333,
		.addr.can_addr.tp.rx_id = 0x444,
		.llopts.mtu = CANFD_MTU,
		.llopts.tx_dl = CANFD_MAX_DLEN,
		.llopts.tx_flags = CANFD_BRS,
	},
	{
		.addr.can_addr.tp.tx_id = 0x555,
		.addr.can_addr.tp.rx_id = 0x666,
		.xlopts.tx_dl = 128,
		.xlopts.tx_addr = 0x80555555,
		.xlopts.rx_addr = 0x80666666,
		.xlopts.tx_flags = CANXL_XLF,
		.xlopts.rx_flags = CANXL_XLF,
		.xlopts.tx_vcid = 0xAA,
		.xlopts.rx_vcid = 0xBB,
	},
	{
		.addr.can_addr.tp.tx_id = 0x555,
		.addr.can_addr.tp.rx_id = 0x666,
		.xlopts.tx_dl = 8,
		.xlopts.tx_addr = 0x80555555,
		.xlopts.rx_addr = 0x80666666,
		.xlopts.tx_flags = CANXL_XLF,
		.xlopts.rx_flags = CANXL_XLF,
		.xlopts.tx_vcid = 0xAA,
		.xlopts.rx_vcid = 0xBB,
	},
	{
		.addr.can_addr.tp.tx_id = 0x555,
		.addr.can_addr.tp.rx_id = 0x666,
		.xlopts.tx_dl = 2048,
		.xlopts.tx_addr = 0x80555555,
		.xlopts.rx_addr = 0x80666666,
		.xlopts.tx_flags = CANXL_XLF,
		.xlopts.rx_flags = CANXL_XLF,
		.xlopts.tx_vcid = 0xAA,
		.xlopts.rx_vcid = 0xBB,
	},
	{
		.addr.can_addr.tp.tx_id = 0x111,
		.addr.can_addr.tp.rx_id = 0x222,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.llopts.mtu = CAN_MTU,
		.llopts.tx_dl = CAN_MAX_DLEN,
	},
	{
		.addr.can_addr.tp.tx_id = 0x333,
		.addr.can_addr.tp.rx_id = 0x444,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.llopts.mtu = CANFD_MTU,
		.llopts.tx_dl = 32,
		.llopts.tx_flags = CANFD_BRS,
	},
	{
		.addr.can_addr.tp.tx_id = 0x555,
		.addr.can_addr.tp.rx_id = 0x666,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.xlopts.tx_dl = 1024,
		.xlopts.tx_addr = 0x80555555,
		.xlopts.rx_addr = 0x80666666,
		.xlopts.tx_flags = CANXL_XLF,
		.xlopts.rx_flags = CANXL_XLF,
		.xlopts.tx_vcid = 0xAA,
		.xlopts.rx_vcid = 0xBB,
	},
	{
		.addr.can_addr.tp.tx_id = 0x111,
		.addr.can_addr.tp.rx_id = 0x222,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR |
			       CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.opts.txpad_content = 0xAA,
		.opts.rxpad_content = 0x55,
		.llopts.mtu = CAN_MTU,
		.llopts.tx_dl = CAN_MAX_DLEN,
	},
	{
		.addr.can_addr.tp.tx_id = 0x333,
		.addr.can_addr.tp.rx_id = 0x444,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR |
			       CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.opts.txpad_content = 0xAA,
		.opts.rxpad_content = 0x55,
		.llopts.mtu = CANFD_MTU,
		.llopts.tx_dl = 16,
		.llopts.tx_flags = CANFD_BRS,
	},
	{
		.addr.can_addr.tp.tx_id = 0x555,
		.addr.can_addr.tp.rx_id = 0x666,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR |
			       CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.opts.txpad_content = 0xAA,
		.opts.rxpad_content = 0x55,
		.xlopts.tx_dl = 8,
		.xlopts.tx_addr = 0x80555555,
		.xlopts.rx_addr = 0x80666666,
		.xlopts.tx_flags = CANXL_XLF,
		.xlopts.rx_flags = CANXL_XLF,
		.xlopts.tx_vcid = 0xAA,
		.xlopts.rx_vcid = 0xBB,
	},
	{
		.addr.can_addr.tp.tx_id = 0x111,
		.addr.can_addr.tp.rx_id = 0x222,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR |
			       CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING |
			       CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.opts.txpad_content = 0xAA,
		.opts.rxpad_content = 0x55,
		.llopts.mtu = CAN_MTU,
		.llopts.tx_dl = CAN_MAX_DLEN,
	},
	{
		.addr.can_addr.tp.tx_id = 0x333,
		.addr.can_addr.tp.rx_id = 0x444,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR |
			       CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING |
			       CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.opts.txpad_content = 0xAA,
		.opts.rxpad_content = 0x55,
		.llopts.mtu = CANFD_MTU,
		.llopts.tx_dl = 8,
		.llopts.tx_flags = CANFD_BRS,
	},
	{
		.addr.can_addr.tp.tx_id = 0x555,
		.addr.can_addr.tp.rx_id = 0x666,
		.opts.flags = (CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR |
			       CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING |
			       CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA),
		.opts.ext_address = 0xEE,
		.opts.rx_ext_address = 0xDD,
		.opts.txpad_content = 0xAA,
		.opts.rxpad_content = 0x55,
		.xlopts.tx_dl = 8,
		.xlopts.tx_addr = 0x80555555,
		.xlopts.rx_addr = 0x80666666,
		.xlopts.tx_flags = CANXL_XLF,
		.xlopts.rx_flags = CANXL_XLF,
		.xlopts.tx_vcid = 0xAA,
		.xlopts.rx_vcid = 0xBB,
	},
};

#define MAXTC (sizeof(tc) / sizeof((tc)[0]))

#define MAXTESTLEN 14

#define CRTL_CAN_ID 0x777

