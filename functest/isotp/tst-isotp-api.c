// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * tst-isotp-api.c - CAN_ISOTP socket API, socket options and bind()
 *
 * Send feedback to <linux-can@vger.kernel.org>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can/raw.h>

#include "ft.h"

#define ISOTP_MIN_NAMELEN 16 /* CAN_REQUIRED_SIZE(struct sockaddr_can, can_addr.tp) */

static int isotp_socket(struct ft_ctx *ctx)
{
	int s = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);

	FT_CHECK(ctx, s >= 0, "socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP): %s",
		 ft_errname(errno));
	return s;
}

static int set_opt(int s, int opt, const void *val, socklen_t len)
{
	if (setsockopt(s, SOL_CAN_ISOTP, opt, val, len))
		return -errno;
	return 0;
}

static int get_opt(int s, int opt, void *val, socklen_t *len)
{
	if (getsockopt(s, SOL_CAN_ISOTP, opt, val, len))
		return -errno;
	return 0;
}

static int do_bind(int s, int ifindex, canid_t tx, canid_t rx, socklen_t len)
{
	struct sockaddr_can addr;

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifindex;
	addr.can_addr.tp.tx_id = tx;
	addr.can_addr.tp.rx_id = rx;

	if (bind(s, (struct sockaddr *)&addr, len))
		return -errno;
	return 0;
}

#define CHECK_RET(ctx, call, exp)					\
	({								\
		int __r = (call);					\
		FT_CHECK(ctx, __r == (exp), "%s returned %s, expected %s", \
			 #call, ft_errname(__r), ft_errname(exp));	\
	})

/* ------------------------------------------------------------------------
 * socket creation and generic socket operations
 * ------------------------------------------------------------------------
 */

static void api_sock_create(struct ft_ctx *ctx, const void *param)
{
	int s;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);
	close(s);

	s = socket(PF_CAN, SOCK_STREAM, CAN_ISOTP);
	FT_CHECK(ctx, s < 0 && errno == EPROTOTYPE,
		 "SOCK_STREAM: %d %s (expected EPROTOTYPE)", s,
		 ft_errname(errno));
	if (s >= 0)
		close(s);

	s = socket(PF_CAN, SOCK_RAW, CAN_ISOTP);
	FT_CHECK(ctx, s < 0 && errno == EPROTOTYPE,
		 "SOCK_RAW: %d %s (expected EPROTOTYPE)", s, ft_errname(errno));
	if (s >= 0)
		close(s);
}

static void api_sock_unsupported(struct ft_ctx *ctx, const void *param)
{
	struct sockaddr_can addr = { .can_family = AF_CAN };
	socklen_t alen = sizeof(addr);
	int sv[2];
	int s, r;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	addr.can_ifindex = ft_ifindex(FT_IF_CC);
	r = connect(s, (struct sockaddr *)&addr, sizeof(addr));
	FT_CHECK(ctx, r < 0 && errno == EOPNOTSUPP, "connect: %s",
		 ft_errname(errno));

	r = listen(s, 1);
	FT_CHECK(ctx, r < 0 && errno == EOPNOTSUPP, "listen: %s",
		 ft_errname(errno));

	r = accept(s, NULL, NULL);
	FT_CHECK(ctx, r < 0 && errno == EOPNOTSUPP, "accept: %s",
		 ft_errname(errno));

	r = shutdown(s, SHUT_RDWR);
	FT_CHECK(ctx, r < 0 && errno == EOPNOTSUPP, "shutdown: %s",
		 ft_errname(errno));

	r = getpeername(s, (struct sockaddr *)&addr, &alen);
	FT_CHECK(ctx, r < 0 && errno == EOPNOTSUPP, "getpeername: %s",
		 ft_errname(errno));

	r = socketpair(PF_CAN, SOCK_DGRAM, CAN_ISOTP, sv);
	FT_CHECK(ctx, r < 0 && errno == EOPNOTSUPP, "socketpair: %s",
		 ft_errname(errno));

	close(s);
}

static void api_sock_ioctl(struct ft_ctx *ctx, const void *param)
{
	struct ifreq ifr;
	int s, r, val = 0;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC))
		return;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	/* no protocol ioctls: handed down to the netdev layer */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ft_ifname(FT_IF_CC), IFNAMSIZ - 1);
	r = ioctl(s, SIOCGIFINDEX, &ifr);
	FT_CHECK(ctx, r == 0 && ifr.ifr_ifindex == ft_ifindex(FT_IF_CC),
		 "SIOCGIFINDEX: %d %s", r, ft_errname(errno));

	r = ioctl(s, FIONREAD, &val);
	FT_CHECK(ctx, r < 0 && errno == ENOTTY, "FIONREAD: %d %s", r,
		 ft_errname(errno));

	close(s);
}

static void api_sock_getname(struct ft_ctx *ctx, const void *param)
{
	struct sockaddr_can addr;
	socklen_t len = sizeof(addr);
	int s;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC))
		return;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	memset(&addr, 0xFF, sizeof(addr));
	FT_CHECK(ctx, !getsockname(s, (struct sockaddr *)&addr, &len),
		 "getsockname: %s", ft_errname(errno));
	FT_CHECK(ctx, len == ISOTP_MIN_NAMELEN, "len %u", len);
	FT_CHECK(ctx, addr.can_family == AF_CAN && addr.can_ifindex == 0 &&
		 addr.can_addr.tp.rx_id == 0 && addr.can_addr.tp.tx_id == 0,
		 "unbound: family %u ifindex %d rx %X tx %X",
		 addr.can_family, addr.can_ifindex, addr.can_addr.tp.rx_id,
		 addr.can_addr.tp.tx_id);

	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x80001234, 0x7FF,
			       sizeof(addr)), 0);

	len = sizeof(addr);
	memset(&addr, 0xFF, sizeof(addr));
	FT_CHECK(ctx, !getsockname(s, (struct sockaddr *)&addr, &len),
		 "getsockname: %s", ft_errname(errno));
	FT_CHECK(ctx, len == ISOTP_MIN_NAMELEN, "len %u", len);
	FT_CHECK(ctx, addr.can_family == AF_CAN &&
		 addr.can_ifindex == ft_ifindex(FT_IF_CC) &&
		 addr.can_addr.tp.rx_id == 0x7FF &&
		 addr.can_addr.tp.tx_id == 0x80001234,
		 "bound: family %u ifindex %d rx %X tx %X",
		 addr.can_family, addr.can_ifindex, addr.can_addr.tp.rx_id,
		 addr.can_addr.tp.tx_id);

	close(s);
}

/* ------------------------------------------------------------------------
 * socket options: defaults and generic checks
 * ------------------------------------------------------------------------
 */

static void api_opt_defaults(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_options opt;
	struct can_isotp_fc_options fc;
	struct can_isotp_ll_options ll;
	struct can_isotp_xl_options xl, xl0;
	uint32_t stmin;
	socklen_t len;
	int s;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	len = sizeof(opt);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &opt, &len), 0);
	FT_CHECK(ctx, len == sizeof(opt), "OPTS len %u", len);
	FT_CHECK(ctx, opt.flags == CAN_ISOTP_DEFAULT_FLAGS &&
		 opt.frame_txtime == CAN_ISOTP_DEFAULT_FRAME_TXTIME &&
		 opt.ext_address == CAN_ISOTP_DEFAULT_EXT_ADDRESS &&
		 opt.txpad_content == CAN_ISOTP_DEFAULT_PAD_CONTENT &&
		 opt.rxpad_content == CAN_ISOTP_DEFAULT_PAD_CONTENT &&
		 opt.rx_ext_address == CAN_ISOTP_DEFAULT_EXT_ADDRESS,
		 "OPTS defaults: flags %X txtime %u ext %02X txpad %02X rxpad %02X rxext %02X",
		 opt.flags, opt.frame_txtime, opt.ext_address,
		 opt.txpad_content, opt.rxpad_content, opt.rx_ext_address);

	len = sizeof(fc);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_RECV_FC, &fc, &len), 0);
	FT_CHECK(ctx, len == sizeof(fc) && fc.bs == 0 && fc.stmin == 0 &&
		 fc.wftmax == 0, "RECV_FC defaults: len %u bs %u stmin %u wftmax %u",
		 len, fc.bs, fc.stmin, fc.wftmax);

	len = sizeof(stmin);
	stmin = 0xDEAD;
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_TX_STMIN, &stmin, &len), 0);
	FT_CHECK(ctx, len == 4 && stmin == 0, "TX_STMIN default %u", stmin);

	len = sizeof(stmin);
	stmin = 0xDEAD;
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_RX_STMIN, &stmin, &len), 0);
	FT_CHECK(ctx, len == 4 && stmin == 0, "RX_STMIN default %u", stmin);

	len = sizeof(ll);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_LL_OPTS, &ll, &len), 0);
	FT_CHECK(ctx, len == sizeof(ll) && ll.mtu == CAN_MTU &&
		 ll.tx_dl == CAN_MAX_DLEN && ll.tx_flags == 0,
		 "LL defaults: mtu %u tx_dl %u tx_flags %X", ll.mtu, ll.tx_dl,
		 ll.tx_flags);

	len = sizeof(xl);
	memset(&xl, 0xFF, sizeof(xl));
	memset(&xl0, 0, sizeof(xl0));
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_XL_OPTS, &xl, &len), 0);
	FT_CHECK(ctx, len == sizeof(xl) && !memcmp(&xl, &xl0, sizeof(xl)),
		 "XL defaults not zero (tx_flags %X tx_dl %u sdt %u)",
		 xl.tx_flags, xl.tx_dl, xl.sdt_mode);

	close(s);
}

static void api_opt_get_errors(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_options opt;
	uint8_t buf[64];
	socklen_t len;
	int s, r;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	len = sizeof(opt);
	r = getsockopt(s, SOL_CAN_RAW, CAN_ISOTP_OPTS, &opt, &len);
	FT_CHECK(ctx, r < 0 && errno == EINVAL, "wrong level: %s",
		 ft_errname(errno));

	len = sizeof(buf);
	CHECK_RET(ctx, get_opt(s, 0, buf, &len), -ENOPROTOOPT);
	len = sizeof(buf);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_XL_OPTS + 1, buf, &len),
		  -ENOPROTOOPT);

	len = (socklen_t)-1;
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, buf, &len), -EINVAL);

	/* short buffers are filled up to the given length */
	len = 0;
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, buf, &len), 0);
	FT_CHECK(ctx, len == 0, "len 0 => %u", len);

	memset(buf, 0xAA, sizeof(buf));
	len = 2;
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, buf, &len), 0);
	FT_CHECK(ctx, len == 2 && buf[0] == 0 && buf[1] == 0 &&
		 buf[2] == 0xAA, "len 2 => %u (%02X %02X %02X)", len,
		 buf[0], buf[1], buf[2]);

	/* large buffers return the option size */
	len = sizeof(buf);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, buf, &len), 0);
	FT_CHECK(ctx, len == sizeof(opt), "len %zu => %u", sizeof(buf), len);

	len = sizeof(buf);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_TX_STMIN, buf, &len), 0);
	FT_CHECK(ctx, len == sizeof(uint32_t), "TX_STMIN len %u", len);

	len = sizeof(opt);
	r = getsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, NULL, &len);
	FT_CHECK(ctx, r < 0 && errno == EFAULT, "NULL optval: %s",
		 ft_errname(errno));

	close(s);
}

static void api_opt_set_errors(struct ft_ctx *ctx, const void *param)
{
	static const struct {
		int opt;
		socklen_t size;
	} opts[] = {
		{ CAN_ISOTP_OPTS, sizeof(struct can_isotp_options) },
		{ CAN_ISOTP_RECV_FC, sizeof(struct can_isotp_fc_options) },
		{ CAN_ISOTP_TX_STMIN, sizeof(uint32_t) },
		{ CAN_ISOTP_RX_STMIN, sizeof(uint32_t) },
		{ CAN_ISOTP_LL_OPTS, sizeof(struct can_isotp_ll_options) },
		{ CAN_ISOTP_XL_OPTS, sizeof(struct can_isotp_xl_options) },
	};
	uint8_t buf[64];
	unsigned int i;
	int s, r;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	memset(buf, 0, sizeof(buf));

	r = setsockopt(s, SOL_CAN_RAW, CAN_ISOTP_OPTS, buf,
		       sizeof(struct can_isotp_options));
	FT_CHECK(ctx, r < 0 && errno == EINVAL, "wrong level: %s",
		 ft_errname(errno));

	/* the level is checked before the option name */
	r = setsockopt(s, SOL_CAN_RAW, 100, buf, 4);
	FT_CHECK(ctx, r < 0 && errno == EINVAL, "wrong level/opt: %s",
		 ft_errname(errno));

	CHECK_RET(ctx, set_opt(s, 0, buf, 4), -ENOPROTOOPT);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS + 1, buf, 4),
		  -ENOPROTOOPT);
	CHECK_RET(ctx, set_opt(s, 100, buf, 4), -ENOPROTOOPT);

	for (i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
		ft_log(ctx, "option %d size %u", opts[i].opt, opts[i].size);
		CHECK_RET(ctx, set_opt(s, opts[i].opt, buf, 0), -EINVAL);
		CHECK_RET(ctx, set_opt(s, opts[i].opt, buf, opts[i].size - 1),
			  -EINVAL);
		CHECK_RET(ctx, set_opt(s, opts[i].opt, buf, opts[i].size + 1),
			  -EINVAL);
		CHECK_RET(ctx, set_opt(s, opts[i].opt, NULL, opts[i].size),
			  -EFAULT);
	}

	close(s);
}

/* ------------------------------------------------------------------------
 * CAN_ISOTP_OPTS
 * ------------------------------------------------------------------------
 */

static void api_opt_bcflags(struct ft_ctx *ctx, const void *param)
{
	static const uint32_t bad[] = {
		CAN_ISOTP_SF_BROADCAST | CAN_ISOTP_CF_BROADCAST,
		CAN_ISOTP_SF_BROADCAST | CAN_ISOTP_MF_BROADCAST,
		CAN_ISOTP_CF_BROADCAST | CAN_ISOTP_MF_BROADCAST,
		CAN_ISOTP_SF_BROADCAST | CAN_ISOTP_CF_BROADCAST |
		CAN_ISOTP_MF_BROADCAST,
	};
	static const uint32_t good[] = {
		CAN_ISOTP_SF_BROADCAST, CAN_ISOTP_CF_BROADCAST,
		CAN_ISOTP_MF_BROADCAST,
	};
	struct can_isotp_options opt, get;
	socklen_t len;
	unsigned int i;
	int s;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	/* set known values to check that rejected calls change nothing */
	memset(&opt, 0, sizeof(opt));
	opt.flags = CAN_ISOTP_TX_PADDING;
	opt.ext_address = 0x11;
	opt.txpad_content = 0x22;
	opt.rxpad_content = 0x33;
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		struct can_isotp_options b = opt;

		b.flags = bad[i] | CAN_ISOTP_RX_PADDING;
		b.ext_address = 0x44;
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &b, sizeof(b)),
			  -EINVAL);

		len = sizeof(get);
		CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &get, &len), 0);
		FT_CHECK(ctx, get.flags == CAN_ISOTP_TX_PADDING &&
			 get.ext_address == 0x11 && get.txpad_content == 0x22,
			 "options changed by rejected call (flags %X ext %02X)",
			 get.flags, get.ext_address);
	}

	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		struct can_isotp_options g = opt;

		g.flags = good[i];
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &g, sizeof(g)), 0);
		len = sizeof(get);
		CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &get, &len), 0);
		FT_CHECK(ctx, get.flags == good[i], "flags %X", get.flags);
	}

	close(s);
}

static void api_opt_padchk(struct ft_ctx *ctx, const void *param)
{
	static const struct {
		uint32_t flags;
		int ret;
	} tc[] = {
		{ CAN_ISOTP_CHK_PAD_DATA, 0 },
		{ CAN_ISOTP_CHK_PAD_DATA | CAN_ISOTP_CHK_PAD_LEN, 0 },
		{ CAN_ISOTP_CHK_PAD_DATA | CAN_ISOTP_TX_PADDING, 0 },
		{ CAN_ISOTP_CHK_PAD_LEN, 0 },
		{ CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_DATA, 0 },
		{ CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN |
		  CAN_ISOTP_CHK_PAD_DATA, 0 },
	};
	struct can_isotp_options opt, get;
	socklen_t len;
	unsigned int i;
	int s;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	for (i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
		memset(&opt, 0, sizeof(opt));
		opt.flags = CAN_ISOTP_WAIT_TX_DONE;
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);

		opt.flags = tc[i].flags;
		ft_log(ctx, "flags %03X", tc[i].flags);
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)),
			  tc[i].ret);

		len = sizeof(get);
		CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &get, &len), 0);
		FT_CHECK(ctx, get.flags == (tc[i].ret ? CAN_ISOTP_WAIT_TX_DONE :
					    tc[i].flags),
			 "flags %03X: stored flags %03X", tc[i].flags, get.flags);
	}

	close(s);
}

static void api_opt_txtime(struct ft_ctx *ctx, const void *param)
{
	static const struct {
		uint32_t val;
		int ret;
	} tc[] = {
		{ 1, 0 },
		{ FT_MAX_FRAME_TXTIME, 0 },
		{ FT_MAX_FRAME_TXTIME + 1, -EINVAL },
		{ 0xFFFFFFFE, -EINVAL },
		{ CAN_ISOTP_FRAME_TXTIME_ZERO, 0 },
		{ 0, 0 },
	};
	struct can_isotp_options opt, get;
	socklen_t len;
	unsigned int i;
	int s;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	for (i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
		memset(&opt, 0, sizeof(opt));
		opt.flags = CAN_ISOTP_WAIT_TX_DONE;
		opt.frame_txtime = 12345;
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);

		opt.flags = CAN_ISOTP_TX_PADDING;
		opt.frame_txtime = tc[i].val;
		ft_log(ctx, "frame_txtime %u", tc[i].val);
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)),
			  tc[i].ret);

		len = sizeof(get);
		CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &get, &len), 0);
		if (tc[i].ret) {
			FT_CHECK(ctx, get.frame_txtime == 12345 &&
				 get.flags == CAN_ISOTP_WAIT_TX_DONE,
				 "rejected value changed options (%u %X)",
				 get.frame_txtime, get.flags);
		} else {
			/* the given struct is stored as is (incl. 0 / ZERO) */
			FT_CHECK(ctx, get.frame_txtime == tc[i].val &&
				 get.flags == CAN_ISOTP_TX_PADDING,
				 "stored frame_txtime %u flags %X",
				 get.frame_txtime, get.flags);
		}
	}

	close(s);
}

static void api_opt_rxext(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_options opt, get;
	socklen_t len = sizeof(get);
	int s;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	memset(&opt, 0, sizeof(opt));
	opt.flags = CAN_ISOTP_EXTEND_ADDR;
	opt.ext_address = 0xA1;
	opt.rx_ext_address = 0xB2;
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &get, &len), 0);
	FT_CHECK(ctx, get.rx_ext_address == 0xA1,
		 "without RX_EXT_ADDR rx_ext_address %02X (expected A1)",
		 get.rx_ext_address);

	opt.flags = CAN_ISOTP_EXTEND_ADDR | CAN_ISOTP_RX_EXT_ADDR;
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);
	len = sizeof(get);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &get, &len), 0);
	FT_CHECK(ctx, get.rx_ext_address == 0xB2 && get.ext_address == 0xA1,
		 "with RX_EXT_ADDR ext %02X rx_ext %02X", get.ext_address,
		 get.rx_ext_address);

	/* RX_EXT_ADDR without EXTEND_ADDR is accepted */
	opt.flags = CAN_ISOTP_RX_EXT_ADDR;
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);

	close(s);
}

static void api_opt_recvfc(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_fc_options fc, get, last = { 0, 0, 0 };
	socklen_t len;
	unsigned int v;
	int s, r, exp, nerr = 0;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	/* bs and wftmax are not checked, STmin 0x80 - 0xF0, 0xFA - 0xFF
	 * are reserved and rejected (the stored values stay unchanged)
	 */
	for (v = 0; v < 256; v++) {
		fc.bs = 255 - v;
		fc.stmin = v;
		fc.wftmax = v;
		r = set_opt(s, CAN_ISOTP_RECV_FC, &fc, sizeof(fc));
		exp = (v > 0x7F && (v < 0xF1 || v > 0xF9)) ? -EINVAL : 0;
		if (r != exp) {
			ft_fail(ctx, "RECV_FC stmin %02X: %s (expected %s)", v,
				ft_errname(r), ft_errname(exp));
			if (++nerr > 5)
				break;
		}
		if (!r)
			last = fc;
		len = sizeof(get);
		CHECK_RET(ctx, get_opt(s, CAN_ISOTP_RECV_FC, &get, &len), 0);
		if (memcmp(&get, &last, sizeof(get))) {
			ft_fail(ctx, "RECV_FC stmin %02X: stored %u %02X %u", v,
				get.bs, get.stmin, get.wftmax);
			if (++nerr > 5)
				break;
		}
	}

	close(s);
}

static void api_opt_stmin(struct ft_ctx *ctx, const void *param)
{
	static const uint32_t tc[] = { 0, 1, 100000, 999999999, 0xFFFFFFFF };
	uint32_t get;
	socklen_t len;
	unsigned int i;
	int s;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	for (i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_TX_STMIN, &tc[i], 4), 0);
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_RX_STMIN, &tc[(i + 1) % 5],
				       4), 0);
		len = sizeof(get);
		CHECK_RET(ctx, get_opt(s, CAN_ISOTP_TX_STMIN, &get, &len), 0);
		FT_CHECK(ctx, get == tc[i], "TX_STMIN %u => %u", tc[i], get);
		len = sizeof(get);
		CHECK_RET(ctx, get_opt(s, CAN_ISOTP_RX_STMIN, &get, &len), 0);
		FT_CHECK(ctx, get == tc[(i + 1) % 5], "RX_STMIN %u => %u",
			 tc[(i + 1) % 5], get);
	}

	close(s);
}

/* ------------------------------------------------------------------------
 * CAN_ISOTP_LL_OPTS
 * ------------------------------------------------------------------------
 */

static bool fd_dl_valid(unsigned int dl)
{
	return dl == 8 || dl == 12 || dl == 16 || dl == 20 || dl == 24 ||
	       dl == 32 || dl == 48 || dl == 64;
}

static void api_opt_ll(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_ll_options ll, get, last;
	socklen_t len;
	unsigned int v;
	int s, r, nerr = 0;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	last.mtu = CAN_MTU;
	last.tx_dl = 8;
	last.tx_flags = 0;

	/* tx_dl for CAN FD: only valid DLC lengths 8 .. 64 */
	for (v = 0; v < 256; v++) {
		ll.mtu = CANFD_MTU;
		ll.tx_dl = v;
		ll.tx_flags = 0;
		r = set_opt(s, CAN_ISOTP_LL_OPTS, &ll, sizeof(ll));
		if (r != (fd_dl_valid(v) ? 0 : -EINVAL)) {
			ft_fail(ctx, "FD tx_dl %u: %s", v, ft_errname(r));
			nerr++;
		}
		if (!r) {
			last = ll;
			/* CANFD_FDF is always added for CAN FD */
			last.tx_flags |= CANFD_FDF;
		}
		len = sizeof(get);
		get_opt(s, CAN_ISOTP_LL_OPTS, &get, &len);
		if (memcmp(&get, &last, sizeof(get))) {
			ft_fail(ctx, "FD tx_dl %u: stored %u/%u/%X", v,
				get.mtu, get.tx_dl, get.tx_flags);
			nerr++;
		}
		if (nerr > 5)
			break;
	}

	/* tx_dl for CAN CC: only 8 */
	for (v = 0; v < 256; v++) {
		ll.mtu = CAN_MTU;
		ll.tx_dl = v;
		ll.tx_flags = 0;
		r = set_opt(s, CAN_ISOTP_LL_OPTS, &ll, sizeof(ll));
		if (r != ((v == 8) ? 0 : -EINVAL)) {
			ft_fail(ctx, "CC tx_dl %u: %s", v, ft_errname(r));
			if (++nerr > 5)
				break;
		}
	}

	/* mtu values */
	for (v = 0; v < 256; v++) {
		ll.mtu = v;
		ll.tx_dl = 8;
		ll.tx_flags = 0;
		r = set_opt(s, CAN_ISOTP_LL_OPTS, &ll, sizeof(ll));
		if (r != ((v == CAN_MTU || v == CANFD_MTU) ? 0 : -EINVAL)) {
			ft_fail(ctx, "mtu %u: %s", v, ft_errname(r));
			if (++nerr > 5)
				break;
		}
	}

	/* tx_flags: CC requires 0, FD only CANFD_BRS and CANFD_FDF */
	for (v = 0; v < 256; v++) {
		ll.mtu = CAN_MTU;
		ll.tx_dl = 8;
		ll.tx_flags = v;
		r = set_opt(s, CAN_ISOTP_LL_OPTS, &ll, sizeof(ll));
		if (r != (v ? -EINVAL : 0)) {
			ft_fail(ctx, "CC tx_flags %02X: %s", v, ft_errname(r));
			if (++nerr > 5)
				break;
		}

		ll.mtu = CANFD_MTU;
		ll.tx_dl = 64;
		r = set_opt(s, CAN_ISOTP_LL_OPTS, &ll, sizeof(ll));
		if (r != ((v & ~(CANFD_BRS | CANFD_FDF)) ? -EINVAL : 0)) {
			ft_fail(ctx, "FD tx_flags %02X: %s", v, ft_errname(r));
			if (++nerr > 5)
				break;
		}
		if (r)
			continue;
		len = sizeof(get);
		get_opt(s, CAN_ISOTP_LL_OPTS, &get, &len);
		/* CANFD_FDF is always added for CAN FD */
		if (get.tx_flags != (v | CANFD_FDF)) {
			ft_fail(ctx, "FD tx_flags %02X stored as %02X", v,
				get.tx_flags);
			if (++nerr > 5)
				break;
		}
	}

	close(s);
}

/* ------------------------------------------------------------------------
 * CAN_ISOTP_XL_OPTS
 * ------------------------------------------------------------------------
 */

/* true when a byte in buf is not zero */
static bool memchr_inv0(const uint8_t *buf, size_t len)
{
	while (len--)
		if (*buf++)
			return true;
	return false;
}

static void xl_valid(struct can_isotp_xl_options *xl)
{
	memset(xl, 0, sizeof(*xl));
	xl->tx_dl = 64;
	xl->tx_addr = 0x80012345;
	xl->rx_addr = 0x80054321;
	xl->tx_flags = CANXL_XLF;
	xl->rx_flags = CANXL_XLF;
	xl->tx_vcid = 0x12;
	xl->rx_vcid = 0x34;
	xl->sdt_mode = CAN_CIA_ISO15765_2_SDT;
}

static void api_opt_xl(struct ft_ctx *ctx, const void *param)
{
	static const struct {
		uint32_t val;
		int ret;
	} dl[] = {
		{ 0, -EINVAL }, { 7, -EINVAL }, { 8, 0 }, { 9, 0 },
		{ 100, 0 }, { 2048, 0 }, { 2049, -EINVAL },
		{ 0xFFFFFFFF, -EINVAL },
	};
	static const struct {
		canid_t id;
		int ret;
	} ids[] = {
		{ 0, 0 }, { 0x7FF, 0 }, { 0x800, -EINVAL },
		{ CAN_EFF_FLAG | 0x1FFFFFFF, 0 },
		{ CAN_EFF_FLAG | 0x20000000, -EINVAL },
		{ CAN_EFF_FLAG | CAN_RTR_FLAG | 0x123, -EINVAL },
		{ CAN_ERR_FLAG | 0x123, -EINVAL },
		{ CAN_RTR_FLAG | 0x123, -EINVAL },
	};
	struct can_isotp_xl_options xl, get, ref;
	socklen_t len;
	unsigned int v;
	int s, r, exp, nerr = 0;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	xl_valid(&xl);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)), 0);
	len = sizeof(get);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_XL_OPTS, &get, &len), 0);
	FT_CHECK(ctx, !memcmp(&get, &xl, sizeof(xl)), "XL options not stored");
	ref = xl;

	/* tx_flags: XLF mandatory to enable, only SEC/RRS allowed in addition */
	for (v = 0; v < 256; v++) {
		xl_valid(&xl);
		xl.tx_flags = v;
		r = set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl));
		if (!(v & CANXL_XLF))
			exp = 0; /* disables XL mode */
		else
			exp = (v & ~(CANXL_XLF | CANXL_SEC | CANXL_RRS)) ?
			      -EINVAL : 0;
		if (r != exp) {
			ft_fail(ctx, "tx_flags %02X: %s (expected %s)", v,
				ft_errname(r), ft_errname(exp));
			if (++nerr > 5)
				break;
		}
	}

	/* rx_flags: XLF mandatory, only SEC/RRS allowed in addition */
	for (v = 0; v < 256; v++) {
		xl_valid(&xl);
		xl.rx_flags = v;
		r = set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl));
		exp = (!(v & CANXL_XLF) ||
		       (v & ~(CANXL_XLF | CANXL_SEC | CANXL_RRS))) ? -EINVAL : 0;
		if (r != exp) {
			ft_fail(ctx, "rx_flags %02X: %s (expected %s)", v,
				ft_errname(r), ft_errname(exp));
			if (++nerr > 5)
				break;
		}
	}

	for (v = 0; v < sizeof(dl) / sizeof(dl[0]); v++) {
		xl_valid(&xl);
		xl.tx_dl = dl[v].val;
		r = set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl));
		FT_CHECK(ctx, r == dl[v].ret, "tx_dl %u: %s", dl[v].val,
			 ft_errname(r));
	}

	for (v = 0; v < sizeof(ids) / sizeof(ids[0]); v++) {
		xl_valid(&xl);
		xl.tx_addr = ids[v].id;
		r = set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl));
		FT_CHECK(ctx, r == ids[v].ret, "tx_addr %08X: %s", ids[v].id,
			 ft_errname(r));
		xl_valid(&xl);
		xl.rx_addr = ids[v].id;
		r = set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl));
		FT_CHECK(ctx, r == ids[v].ret, "rx_addr %08X: %s", ids[v].id,
			 ft_errname(r));
	}

	for (v = 0; v < 256; v++) {
		xl_valid(&xl);
		xl.sdt_mode = v;
		r = set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl));
		exp = (v == CAN_CIA_CC_TUNNEL_SDT || v == CAN_CIA_FD_TUNNEL_SDT ||
		       v == CAN_CIA_ISO15765_2_SDT) ? 0 : -EINVAL;
		if (r != exp) {
			ft_fail(ctx, "sdt_mode %02X: %s", v, ft_errname(r));
			if (++nerr > 5)
				break;
		}
	}

	for (v = 0; v < 256; v += 17) {
		xl_valid(&xl);
		xl.tx_vcid = v;
		xl.rx_vcid = 255 - v;
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)), 0);
	}

	/* reserved bytes must be zero (also when disabling the XL mode) */
	for (v = 0; v < sizeof(xl.__res); v++) {
		xl_valid(&xl);
		xl.__res[v] = 0x01 << v;
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)),
			  -EINVAL);
		xl.tx_flags = 0;
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)),
			  -EINVAL);
	}
	FT_CHECK(ctx, sizeof(xl) == 20, "sizeof(struct can_isotp_xl_options) %zu",
		 sizeof(xl));
	xl_valid(&xl);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)), 0);
	memset(&get, 0xFF, sizeof(get));
	len = sizeof(get);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_XL_OPTS, &get, &len), 0);
	FT_CHECK(ctx, !memchr_inv0(get.__res, sizeof(get.__res)),
		 "getsockopt() returns reserved bytes != 0");

	/* rejected call keeps the former values */
	xl_valid(&xl);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)), 0);
	xl.tx_dl = 3000;
	xl.tx_vcid = 0x99;
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)), -EINVAL);
	len = sizeof(get);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_XL_OPTS, &get, &len), 0);
	FT_CHECK(ctx, !memcmp(&get, &ref, sizeof(get)),
		 "rejected XL options changed the stored values");

	/* disable: no checks, only tx_flags is cleared */
	memset(&xl, 0, sizeof(xl));
	xl.tx_dl = 1;
	xl.sdt_mode = 0x55;
	xl.rx_flags = 0x7F;
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)), 0);
	len = sizeof(get);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_XL_OPTS, &get, &len), 0);
	ref.tx_flags = 0;
	FT_CHECK(ctx, !memcmp(&get, &ref, sizeof(get)),
		 "disabled XL options: tx_dl %u sdt %02X tx_flags %02X rx_flags %02X",
		 get.tx_dl, get.sdt_mode, get.tx_flags, get.rx_flags);

	close(s);
}

static void api_opt_bound(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_options opt;
	struct can_isotp_fc_options fc;
	struct can_isotp_ll_options ll;
	struct can_isotp_xl_options xl;
	uint32_t stmin = 0;
	socklen_t len;
	int s;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC))
		return;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123, 0x321,
			       sizeof(struct sockaddr_can)), 0);

	memset(&opt, 0, sizeof(opt));
	memset(&fc, 0, sizeof(fc));
	ll.mtu = CAN_MTU;
	ll.tx_dl = 8;
	ll.tx_flags = 0;
	xl_valid(&xl);

	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), -EISCONN);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_RECV_FC, &fc, sizeof(fc)), -EISCONN);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_TX_STMIN, &stmin, 4), -EISCONN);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_RX_STMIN, &stmin, 4), -EISCONN);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_LL_OPTS, &ll, sizeof(ll)), -EISCONN);
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_XL_OPTS, &xl, sizeof(xl)), -EISCONN);

	/* invalid values are not checked when bound */
	ll.mtu = 0;
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_LL_OPTS, &ll, sizeof(ll)), -EISCONN);

	/* the size check comes first */
	CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, 3), -EINVAL);

	/* getsockopt works on bound sockets */
	len = sizeof(opt);
	CHECK_RET(ctx, get_opt(s, CAN_ISOTP_OPTS, &opt, &len), 0);

	close(s);
}

/* ------------------------------------------------------------------------
 * bind()
 * ------------------------------------------------------------------------
 */

static void api_bind_addr(struct ft_ctx *ctx, const void *param)
{
	struct sockaddr_can addr;
	int s, r;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC))
		return;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123, 0x321,
			       ISOTP_MIN_NAMELEN - 1), -EINVAL);
	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123, 0x321, 0),
		  -EINVAL);

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_INET;
	addr.can_ifindex = ft_ifindex(FT_IF_CC);
	addr.can_addr.tp.tx_id = 0x123;
	addr.can_addr.tp.rx_id = 0x321;
	r = bind(s, (struct sockaddr *)&addr, sizeof(addr));
	FT_CHECK(ctx, r < 0 && errno == EINVAL, "AF_INET: %s",
		 ft_errname(errno));

	/* the minimum length is sufficient */
	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123, 0x321,
			       ISOTP_MIN_NAMELEN), 0);

	/* second bind() */
	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x124, 0x322,
			       sizeof(addr)), -EINVAL);

	close(s);
}

static const struct {
	canid_t id;
	bool valid;
} canids[] = {
	{ 0x000, true }, { 0x7FF, true }, { 0x800, false },
	{ 0xFFFF, false },
	{ CAN_EFF_FLAG | 0x0, true }, { CAN_EFF_FLAG | 0x1FFFFFFF, true },
	{ CAN_EFF_FLAG | 0x20000000, false },
	{ CAN_RTR_FLAG | 0x123, false },
	{ CAN_EFF_FLAG | CAN_RTR_FLAG | 0x123, false },
	{ CAN_ERR_FLAG | 0x123, false },
	{ CAN_ERR_FLAG | CAN_EFF_FLAG | 0x123, false },
};

static void api_bind_canid(struct ft_ctx *ctx, const void *param)
{
	unsigned int i;
	int s, r;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC))
		return;

	for (i = 0; i < sizeof(canids) / sizeof(canids[0]); i++) {
		/* tx_id */
		s = isotp_socket(ctx);
		FT_BAIL(ctx);
		r = do_bind(s, ft_ifindex(FT_IF_CC), canids[i].id, 0x555,
			    sizeof(struct sockaddr_can));
		FT_CHECK(ctx, r == (canids[i].valid ? 0 : -EINVAL),
			 "tx_id %08X: %s", canids[i].id, ft_errname(r));
		close(s);

		/* rx_id */
		s = isotp_socket(ctx);
		FT_BAIL(ctx);
		r = do_bind(s, ft_ifindex(FT_IF_CC), 0x555, canids[i].id,
			    sizeof(struct sockaddr_can));
		FT_CHECK(ctx, r == (canids[i].valid ? 0 : -EINVAL),
			 "rx_id %08X: %s", canids[i].id, ft_errname(r));
		close(s);
	}
}

static void api_bind_bc_rxid(struct ft_ctx *ctx, const void *param)
{
	static const uint32_t bc[] = { CAN_ISOTP_SF_BROADCAST,
				       CAN_ISOTP_CF_BROADCAST,
				       CAN_ISOTP_MF_BROADCAST };
	struct can_isotp_options opt;
	unsigned int i;
	int s;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC))
		return;

	for (i = 0; i < 3; i++) {
		memset(&opt, 0, sizeof(opt));
		opt.flags = bc[i];

		/* invalid rx_id is not checked */
		s = isotp_socket(ctx);
		FT_BAIL(ctx);
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);
		CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123,
				       0xFFFFFFFF, sizeof(struct sockaddr_can)),
			  0);
		close(s);

		/* rx_id == tx_id is allowed */
		s = isotp_socket(ctx);
		FT_BAIL(ctx);
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);
		CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123, 0x123,
				       sizeof(struct sockaddr_can)), 0);
		close(s);

		/* tx_id is still checked */
		s = isotp_socket(ctx);
		FT_BAIL(ctx);
		CHECK_RET(ctx, set_opt(s, CAN_ISOTP_OPTS, &opt, sizeof(opt)), 0);
		CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x800, 0x123,
				       sizeof(struct sockaddr_can)), -EINVAL);
		close(s);
	}
}

static void api_bind_sameid(struct ft_ctx *ctx, const void *param)
{
	int s;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC))
		return;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);
	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123, 0x123,
			       sizeof(struct sockaddr_can)), -EADDRNOTAVAIL);
	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), CAN_EFF_FLAG | 0x123,
			       CAN_EFF_FLAG | 0x123,
			       sizeof(struct sockaddr_can)), -EADDRNOTAVAIL);
	/* SFF and EFF with the same numeric value are different IDs */
	CHECK_RET(ctx, do_bind(s, ft_ifindex(FT_IF_CC), 0x123,
			       CAN_EFF_FLAG | 0x123,
			       sizeof(struct sockaddr_can)), 0);
	close(s);
}

static void api_bind_ifindex(struct ft_ctx *ctx, const void *param)
{
	int s, lo = if_nametoindex("lo");

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);
	CHECK_RET(ctx, do_bind(s, 0, 0x123, 0x321,
			       sizeof(struct sockaddr_can)), -ENODEV);
	CHECK_RET(ctx, do_bind(s, 0x7FFFFFF0, 0x123, 0x321,
			       sizeof(struct sockaddr_can)), -ENODEV);
	if (lo)
		CHECK_RET(ctx, do_bind(s, lo, 0x123, 0x321,
				       sizeof(struct sockaddr_can)), -ENODEV);
	close(s);
}

static void api_bind_mtu(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	int s;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_CC) || !ft_need_if(ctx, FT_IF_FD))
		return;

	/* CAN FD socket on CAN CC interface */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("FD64"));
	c.iface = FT_IF_CC;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "FD socket on CC interface: %s",
		 ft_errname(s));
	if (s >= 0)
		close(s);

	/* CAN FD socket with TX_DL 8 on CAN CC interface */
	ft_cfg_mode(&c, ft_mode_by_name("FD8"));
	c.iface = FT_IF_CC;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "FD8 socket on CC interface: %s",
		 ft_errname(s));
	if (s >= 0)
		close(s);

	/* CAN CC socket on CAN FD interface */
	ft_cfg_init(&c);
	c.iface = FT_IF_FD;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s >= 0, "CC socket on FD interface: %s", ft_errname(s));
	if (s >= 0)
		close(s);

	/* CAN FD socket on CAN XL interface */
	if (ft_ifindex(FT_IF_XL)) {
		ft_cfg_mode(&c, ft_mode_by_name("FD64"));
		c.iface = FT_IF_XL;
		s = ft_isotp_open_err(&c);
		FT_CHECK(ctx, s >= 0, "FD socket on XL interface: %s",
			 ft_errname(s));
		if (s >= 0)
			close(s);
	}
}

static void api_bind_lldl(struct ft_ctx *ctx, const void *param)
{
	static const struct {
		const char *mode;
		uint32_t flags;
		uint32_t xl_tx_dl;
		uint8_t mtu;
		int ret;
	} tc[] = {
		/* LL mtu 16: TX_PADDING only for CAN CC N_PDUs (TX_DL 8) */
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 8, CAN_MTU, 0 },
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 64, CAN_MTU, -EINVAL },
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 12, CAN_MTU, -EINVAL },
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 100, CAN_MTU, -EINVAL },
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 9, CAN_MTU, -EINVAL },
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 2048, CAN_MTU, -EINVAL },
		{ "XL9-64", 0, 100, CAN_MTU, 0 },
		/* CAN FD N_PDU (LL mtu 72) inside CAN XL SDT 9 */
		{ "XL9-64", 0, 64, CANFD_MTU, 0 },
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 64, CANFD_MTU, 0 },
		{ "XL9-64", CAN_ISOTP_TX_PADDING, 12, CANFD_MTU, 0 },
		{ "XL9-64", 0, 100, CANFD_MTU, -EINVAL },
		{ "XL9-64", 0, 13, CANFD_MTU, -EINVAL },
		{ "XL9-64", 0, 2048, CANFD_MTU, -EINVAL },
	};
	struct ft_isotp_cfg c;
	unsigned int i;
	int s;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_XL))
		return;

	for (i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
		ft_cfg_init(&c);
		ft_cfg_mode(&c, ft_mode_by_name(tc[i].mode));
		c.opts.flags = tc[i].flags;
		c.xl.tx_dl = tc[i].xl_tx_dl;
		c.ll.mtu = tc[i].mtu;
		c.ll.tx_dl = (tc[i].mtu == CANFD_MTU) ? 64 : 8;
		s = ft_isotp_open_err(&c);
		FT_CHECK(ctx, (s >= 0 ? 0 : s) == tc[i].ret,
			 "case %u: flags %X xl tx_dl %u mtu %u: %s (expected %s)",
			 i, tc[i].flags, tc[i].xl_tx_dl, tc[i].mtu,
			 ft_errname(s >= 0 ? 0 : s), ft_errname(tc[i].ret));
		if (s >= 0)
			close(s);
	}
}

static void api_bind_xl(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	int s;

	(void)param;

	if (!ft_need_if(ctx, FT_IF_XL))
		return;

	/* 29 bit CAN IDs are not allowed for the 11 bit XL priority */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL9-64"));
	c.tx_id = CAN_EFF_FLAG | 0x123;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "XL EFF tx_id: %s", ft_errname(s));
	if (s >= 0)
		close(s);

	ft_cfg_mode(&c, ft_mode_by_name("XL9-64"));
	c.tx_id = 0x123;
	c.rx_id = CAN_EFF_FLAG | 0x321;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "XL EFF rx_id: %s", ft_errname(s));
	if (s >= 0)
		close(s);

	/* SDT 7 (CAN FD tunnel) requires LL mtu CANFD_MTU */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL7-64"));
	c.ll.mtu = CAN_MTU;
	c.ll.tx_dl = 8;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "SDT7 with CC LL: %s", ft_errname(s));
	if (s >= 0)
		close(s);

	/* SDT 6 (CAN CC tunnel) requires LL mtu CAN_MTU ... */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL6-8"));
	c.ll.mtu = CANFD_MTU;
	c.ll.tx_dl = 8;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "SDT6 with FD LL: %s", ft_errname(s));
	if (s >= 0)
		close(s);

	/* ... and an XL tx_dl of 8 */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL6-8"));
	c.xl.tx_dl = 12;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "SDT6 with XL tx_dl 12: %s",
		 ft_errname(s));
	if (s >= 0)
		close(s);

	/* the valid configurations */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL6-8"));
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s >= 0, "SDT6: %s", ft_errname(s));
	if (s >= 0)
		close(s);

	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL7-64BRS"));
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s >= 0, "SDT7 BRS: %s", ft_errname(s));
	if (s >= 0)
		close(s);

	/* XL settings are checked before the interface */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL9-64"));
	c.tx_id = CAN_EFF_FLAG | 0x123;
	c.iface = FT_IF_CC;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "XL EFF on CC interface: %s",
		 ft_errname(s));
	if (s >= 0)
		close(s);
}

static void api_bind_down(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	uint8_t data[4] = { 1, 2, 3, 4 };
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	c.iface = FT_IF_DOWN;
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);

	ft_dut_expect_err(ctx, s, ENETDOWN, 100, NULL);

	n = ft_dut_send(ctx, s, data, sizeof(data), 0);
	FT_CHECK(ctx, n == -ENETDOWN, "send on down interface: %s",
		 ft_errname(n));

	/* the socket is usable afterwards (tx state back to idle) */
	n = ft_dut_send(ctx, s, data, sizeof(data), MSG_DONTWAIT);
	FT_CHECK(ctx, n == -ENETDOWN, "2nd send on down interface: %s",
		 ft_errname(n));

	close(s);
}

static void api_bind_xl_on_cc(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	uint8_t data[4] = { 1, 2, 3, 4 };
	ssize_t n;
	int s;

	(void)param;

	/* the XL mode needs a CAN XL capable interface */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name("XL9-64"));
	c.iface = FT_IF_CC;
	s = ft_isotp_open_err(&c);
	FT_CHECK(ctx, s == -EINVAL, "bind() of XL socket to CC interface: %s",
		 ft_errname(s >= 0 ? 0 : s));
	if (s < 0)
		return;

	n = ft_dut_send(ctx, s, data, sizeof(data), 0);
	ft_log(ctx, "send() = %s", ft_errname(n));
	close(s);
}

/* ------------------------------------------------------------------------
 * send() / recv() API
 * ------------------------------------------------------------------------
 */

static void api_io_unbound(struct ft_ctx *ctx, const void *param)
{
	uint8_t buf[16] = { 0 };
	int s, r;

	(void)param;

	s = isotp_socket(ctx);
	FT_BAIL(ctx);

	r = send(s, buf, 4, 0);
	FT_CHECK(ctx, r < 0 && errno == EADDRNOTAVAIL, "send: %s",
		 ft_errname(errno));
	r = recv(s, buf, sizeof(buf), MSG_DONTWAIT);
	FT_CHECK(ctx, r < 0 && errno == EADDRNOTAVAIL, "recv: %s",
		 ft_errname(errno));
	r = recv(s, buf, sizeof(buf), 0);
	FT_CHECK(ctx, r < 0 && errno == EADDRNOTAVAIL, "blocking recv: %s",
		 ft_errname(errno));

	close(s);
}

static void api_io_recvflags(struct ft_ctx *ctx, const void *param)
{
	static const int bad[] = { MSG_OOB, MSG_WAITALL, MSG_ERRQUEUE,
				   MSG_DONTROUTE };
	struct ft_isotp_cfg c;
	uint8_t buf[16];
	unsigned int i;
	int s, r;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		r = recv(s, buf, sizeof(buf), bad[i] | MSG_DONTWAIT);
		FT_CHECK(ctx, r < 0 && errno == EINVAL, "flags %X: %s",
			 bad[i], ft_errname(errno));
	}

	r = recv(s, buf, sizeof(buf), MSG_DONTWAIT);
	FT_CHECK(ctx, r < 0 && errno == EAGAIN, "empty queue: %s",
		 ft_errname(errno));
	r = recv(s, buf, sizeof(buf), MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC);
	FT_CHECK(ctx, r < 0 && errno == EAGAIN, "allowed flags: %s",
		 ft_errname(errno));

	close(s);
}

static void api_io_sendsize(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	unsigned int max = ft_max_pdu();
	uint8_t *buf = calloc(1, max + 2);
	struct ft_peer p;
	ssize_t n;
	int s;

	(void)param;

	if (!buf) {
		ft_fail(ctx, "out of memory");
		return;
	}

	ft_cfg_init(&c);
	c.opts.flags = CAN_ISOTP_CF_BROADCAST | CAN_ISOTP_WAIT_TX_DONE;
	s = ft_isotp_open(ctx, &c);
	if (ctx->failed || ctx->skipped)
		goto out;

	if (ft_peer_open(ctx, &p, c.iface))
		goto out_close;

	n = ft_dut_send(ctx, s, buf, 0, 0);
	FT_CHECK(ctx, n == -EINVAL, "size 0: %s", ft_errname(n));

	n = ft_dut_send(ctx, s, buf, max + 1, 0);
	FT_CHECK(ctx, n == -EINVAL, "size %u: %s", max + 1, ft_errname(n));

	ft_pattern(buf, max, 0x10);
	ft_tx_pdu(ctx, s, &c, &p, buf, max, 0, 0);

	ft_peer_close(&p);
out_close:
	close(s);
out:
	free(buf);
}

static void api_io_trunc(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc e;
	struct ft_frame hdr;
	struct ft_frame *frames;
	struct sockaddr_can addr;
	struct iovec iov;
	struct msghdr msg;
	uint8_t data[100], buf[100];
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_pattern(data, sizeof(data), 0x40);
	ft_enc_peer(&c, &e);
	ft_hdr_dut_rx(&c, &hdr);
	ft_rx_pdu(ctx, s, &c, &p, &e, data, 7);
	FT_BAIL(ctx);

	/* queue a 7 byte PDU via SF */
	ft_enc_pdu(&e, &hdr, data, 7, &frames);
	ft_peer_tx(ctx, &p, &frames[0]);
	free(frames);
	ft_sleep_ms(20);

	/* MSG_PEEK keeps the PDU, MSG_TRUNC returns the full length */
	memset(buf, 0, sizeof(buf));
	n = recv(s, buf, 3, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
	FT_CHECK(ctx, n == 7 && !memcmp(buf, data, 3) && buf[3] == 0,
		 "MSG_PEEK|MSG_TRUNC: %zd", n);

	/* msg_flags MSG_TRUNC for short buffers, return copied length */
	memset(&msg, 0, sizeof(msg));
	memset(&addr, 0xFF, sizeof(addr));
	iov.iov_base = buf;
	iov.iov_len = 5;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	n = recvmsg(s, &msg, MSG_DONTWAIT);
	FT_CHECK(ctx, n == 5 && (msg.msg_flags & MSG_TRUNC) &&
		 !memcmp(buf, data, 5), "short buffer: %zd flags %X", n,
		 msg.msg_flags);
	FT_CHECK(ctx, msg.msg_namelen == ISOTP_MIN_NAMELEN &&
		 addr.can_family == AF_CAN &&
		 addr.can_ifindex == ft_ifindex(c.iface) &&
		 addr.can_addr.tp.rx_id == 0 && addr.can_addr.tp.tx_id == 0,
		 "msg_name: len %u family %u ifindex %d rx %X tx %X",
		 msg.msg_namelen, addr.can_family, addr.can_ifindex,
		 addr.can_addr.tp.rx_id, addr.can_addr.tp.tx_id);

	/* the rest of a truncated PDU is discarded */
	n = recv(s, buf, sizeof(buf), MSG_DONTWAIT);
	FT_CHECK(ctx, n < 0 && errno == EAGAIN, "after truncation: %zd %s", n,
		 ft_errname(errno));

	ft_peer_close(&p);
	close(s);
}

static void api_io_queue(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc e;
	struct ft_frame hdr;
	struct ft_frame *frames;
	uint8_t data[8];
	int s, i;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_peer(&c, &e);
	ft_hdr_dut_rx(&c, &hdr);

	for (i = 1; i <= 7; i++) {
		ft_pattern(data, i, i);
		ft_enc_pdu(&e, &hdr, data, i, &frames);
		ft_peer_tx(ctx, &p, &frames[0]);
		free(frames);
	}

	for (i = 1; i <= 7; i++) {
		ft_pattern(data, i, i);
		ft_dut_expect_pdu(ctx, s, data, i, 500);
	}

	ft_peer_close(&p);
	close(s);
}

static void api_io_tstamp(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc e;
	struct ft_frame hdr, fc;
	struct ft_frame *frames;
	uint8_t data[20], buf[32];
	char ctrl[CMSG_SPACE(sizeof(struct timespec))];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = ctrl, .msg_controllen = sizeof(ctrl),
	};
	struct cmsghdr *cmsg;
	struct pollfd pfd;
	int64_t t1 = 0, t2 = 0, ts = 0;
	int s, n, i, on = 1;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}
	setsockopt(s, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on));

	ft_pattern(data, sizeof(data), 1);
	ft_enc_peer(&c, &e);
	ft_hdr_dut_rx(&c, &hdr);
	n = ft_enc_pdu(&e, &hdr, data, sizeof(data), &frames);

	ft_peer_tx(ctx, &p, &frames[0]);
	ft_peer_next(ctx, &p, &fc, 500);
	for (i = 1; i < n; i++) {
		if (i == n - 1) {
			/* the PDU timestamp is the one of the last CF */
			ft_sleep_ms(50);
			t1 = ft_now_ns();
		}
		ft_peer_tx(ctx, &p, &frames[i]);
	}
	t2 = ft_now_ns();
	free(frames);

	pfd.fd = s;
	pfd.events = POLLIN;
	poll(&pfd, 1, 500);
	n = recvmsg(s, &msg, MSG_DONTWAIT);
	FT_CHECK(ctx, n == (int)sizeof(data), "recvmsg: %d", n);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SO_TIMESTAMPNS) {
			struct timespec t;

			memcpy(&t, CMSG_DATA(cmsg), sizeof(t));
			ts = ft_ts_ns(&t);
		}
	}

	ft_log(ctx, "t1 %lld ts %lld t2 %lld", (long long)t1, (long long)ts,
	       (long long)t2);
	FT_CHECK(ctx, ts >= t1 && ts <= t2,
		 "PDU timestamp not within the sending time of the last CF");

	ft_peer_close(&p);
	close(s);
}

static void api_io_poll(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc pe;
	struct ft_frame hdr, f;
	struct pollfd pfd;
	uint8_t data[20];
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	pfd.fd = s;
	pfd.events = POLLIN | POLLOUT;
	FT_CHECK(ctx, poll(&pfd, 1, 0) == 1 && pfd.revents == POLLOUT,
		 "idle: revents %X", pfd.revents);

	/* FF sent, waiting for FC => not writable */
	ft_pattern(data, sizeof(data), 0);
	n = ft_dut_send(ctx, s, data, sizeof(data), 0);
	FT_CHECK(ctx, n == sizeof(data), "send %zd", n);
	ft_peer_next(ctx, &p, &f, 500);
	pfd.revents = 0;
	FT_CHECK(ctx, poll(&pfd, 1, 0) == 0 && pfd.revents == 0,
		 "waiting for FC: revents %X", pfd.revents);

	/* FC overflow => error, writable again */
	ft_enc_peer(&c, &pe);
	ft_hdr_dut_rx(&c, &hdr);
	ft_enc_fc(&pe, &hdr, FT_FS_OVFLW, 0, 0, &f);
	ft_peer_tx(ctx, &p, &f);
	ft_sleep_ms(20);
	pfd.revents = 0;
	FT_CHECK(ctx, poll(&pfd, 1, 0) == 1 &&
		 pfd.revents == (POLLOUT | POLLERR),
		 "after FC OVFLW: revents %X", pfd.revents);
	FT_CHECK(ctx, ft_sock_error(s) == EMSGSIZE, "SO_ERROR");

	/* received PDU => readable */
	ft_frame_bytes(&f, &hdr, 3, 0x02, 0xAA, 0xBB);
	ft_peer_tx(ctx, &p, &f);
	ft_sleep_ms(20);
	pfd.revents = 0;
	FT_CHECK(ctx, poll(&pfd, 1, 0) == 1 &&
		 pfd.revents == (POLLOUT | POLLIN),
		 "PDU received: revents %X", pfd.revents);

	ft_peer_close(&p);
	close(s);
}

static void api_io_busy(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc pe;
	struct ft_frame hdr, f;
	struct ft_async a;
	uint8_t data[20];
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_peer(&c, &pe);
	ft_hdr_dut_rx(&c, &hdr);
	ft_pattern(data, sizeof(data), 0);

	n = ft_dut_send(ctx, s, data, sizeof(data), 0);
	FT_CHECK(ctx, n == sizeof(data), "send %zd", n);
	ft_peer_next(ctx, &p, &f, 500); /* FF */

	/* a second PDU can not be sent while the first is active */
	n = ft_dut_send(ctx, s, data, 5, MSG_DONTWAIT);
	FT_CHECK(ctx, n == -EAGAIN, "MSG_DONTWAIT while busy: %s",
		 ft_errname(n));

	/* blocking send() waits until the first transfer is done */
	ft_async_send(&a, s, data, 5, 0);
	ft_sleep_ms(100);
	FT_CHECK(ctx, !ft_async_done(&a), "blocking send() did not block");

	ft_enc_fc(&pe, &hdr, FT_FS_CTS, 0, 0, &f);
	ft_peer_tx(ctx, &p, &f);

	/* 2 CFs of the 1st PDU, then the SF of the 2nd PDU */
	ft_peer_next(ctx, &p, &f, 500);
	FT_CHECK(ctx, f.data[0] == 0x21, "CF1 %02X", f.data[0]);
	ft_peer_next(ctx, &p, &f, 500);
	FT_CHECK(ctx, f.data[0] == 0x22, "CF2 %02X", f.data[0]);
	ft_peer_next(ctx, &p, &f, 500);
	FT_CHECK(ctx, f.data[0] == 0x05, "SF %02X", f.data[0]);

	if (ft_async_join(ctx, &a, 1000))
		FT_CHECK(ctx, a.ret == 5, "2nd send() %zd", a.ret);

	ft_peer_close(&p);
	close(s);
}

static void api_io_async_err(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc pe;
	struct ft_frame hdr, f;
	uint8_t data[20];
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_peer(&c, &pe);
	ft_hdr_dut_rx(&c, &hdr);
	ft_pattern(data, sizeof(data), 0);

	/* without WAIT_TX_DONE send() returns before the transfer is done */
	n = ft_dut_send(ctx, s, data, sizeof(data), 0);
	FT_CHECK(ctx, n == sizeof(data), "send %zd", n);
	ft_peer_next(ctx, &p, &f, 500);
	ft_enc_fc(&pe, &hdr, FT_FS_OVFLW, 0, 0, &f);
	ft_peer_tx(ctx, &p, &f);
	ft_sleep_ms(20);

	/* the pending error is returned by the next send() */
	n = ft_dut_send(ctx, s, data, 5, 0);
	FT_CHECK(ctx, n == -EMSGSIZE, "send after error: %s", ft_errname(n));
	FT_CHECK(ctx, ft_peer_expect_none(ctx, &p, 20),
		 "frame sent despite error");

	/* ... and is cleared afterwards */
	n = ft_dut_send(ctx, s, data, 5, 0);
	FT_CHECK(ctx, n == 5, "send after error report: %s", ft_errname(n));
	ft_peer_next(ctx, &p, &f, 500);
	ft_dut_expect_noerr(ctx, s);

	ft_peer_close(&p);
	close(s);
}

static void api_io_recv_err(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc e;
	struct ft_frame hdr, f;
	struct ft_frame *frames;
	uint8_t data[20], buf[32];
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_peer(&c, &e);
	ft_hdr_dut_rx(&c, &hdr);
	ft_pattern(data, sizeof(data), 0);
	ft_enc_pdu(&e, &hdr, data, sizeof(data), &frames);

	/* FF, FC, CF with wrong SN => EILSEQ */
	ft_peer_tx(ctx, &p, &frames[0]);
	ft_peer_next(ctx, &p, &f, 500);
	frames[1].data[0] = 0x22;
	ft_peer_tx(ctx, &p, &frames[1]);
	free(frames);
	ft_sleep_ms(20);

	/* the error is returned once by recv() */
	n = recv(s, buf, sizeof(buf), MSG_DONTWAIT);
	FT_CHECK(ctx, n < 0 && errno == EILSEQ, "1st recv: %zd %s", n,
		 ft_errname(errno));
	n = recv(s, buf, sizeof(buf), MSG_DONTWAIT);
	FT_CHECK(ctx, n < 0 && errno == EAGAIN, "2nd recv: %zd %s", n,
		 ft_errname(errno));

	ft_peer_close(&p);
	close(s);
}

static void api_io_close_busy(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_frame f;
	uint8_t data[20];
	int64_t t0, t1;
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_pattern(data, sizeof(data), 0);
	n = ft_dut_send(ctx, s, data, sizeof(data), 0);
	FT_CHECK(ctx, n == sizeof(data), "send %zd", n);
	ft_peer_next(ctx, &p, &f, 500);
	t0 = f.ts;

	/* close() waits for the end of the transfer (FC timeout) */
	close(s);
	t1 = ft_now_ns();
	ft_log(ctx, "close() returned %lld ms after FF",
	       (long long)(t1 - t0) / 1000000);
	FT_CHECK(ctx, t1 - t0 >= (FT_FC_TIMEOUT_MS - 5) * 1000000LL &&
		 t1 - t0 <= (FT_FC_TIMEOUT_MS + 200 + ft_cfg.tol_ms) * 1000000LL,
		 "close() returned after %lld ms", (long long)(t1 - t0) / 1000000);

	ft_peer_close(&p);
}

static void api_io_efault(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_frame f, hdr;
	uint8_t buf[8];
	ssize_t n;
	int s;

	(void)param;

	ft_cfg_init(&c);
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	/* invalid user space buffer for send() */
	n = send(s, NULL, 5, 0);
	FT_CHECK(ctx, n < 0 && errno == EFAULT, "send(NULL): %zd %s", n,
		 ft_errname(errno));
	ft_peer_expect_none(ctx, &p, 20);

	/* the socket is idle afterwards */
	n = ft_dut_send(ctx, s, "\x11\x22", 2, MSG_DONTWAIT);
	FT_CHECK(ctx, n == 2, "send() after EFAULT: %s", ft_errname(n));
	ft_peer_next(ctx, &p, &f, 200);

	/* invalid user space buffer for recv(): the PDU is consumed */
	ft_hdr_dut_rx(&c, &hdr);
	ft_frame_bytes(&f, &hdr, 3, 0x02, 0xAA, 0xBB);
	ft_peer_tx(ctx, &p, &f);
	ft_sleep_ms(20);
	n = recv(s, NULL, 10, MSG_DONTWAIT);
	FT_CHECK(ctx, n < 0 && errno == EFAULT, "recv(NULL): %zd %s", n,
		 ft_errname(errno));
	n = recv(s, buf, sizeof(buf), MSG_DONTWAIT);
	FT_CHECK(ctx, n < 0 && errno == EAGAIN, "PDU not consumed: %zd", n);

	ft_peer_close(&p);
	close(s);
}

/* ------------------------------------------------------------------------
 * test table
 * ------------------------------------------------------------------------
 */

#define T(i, t, fl, f, rq, rf, is)					\
	{ .id = i, .title = t, .req = rq, .ref = rf, .iso = is,		\
	  .flags = fl, .fn = f, .param = NULL }

static const struct ft_test tests[] = {
	T("API-SOCK-001", "socket creation", 0, api_sock_create,
	  "CAN_ISOTP sockets are created with socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP). Other socket types fail with EPROTOTYPE.",
	  "af_can.c:can_create(), isotp.c:isotp_can_proto", NULL),
	T("API-SOCK-002", "unsupported socket operations", 0,
	  api_sock_unsupported,
	  "connect(), listen(), accept(), shutdown(), getpeername() and socketpair() are not supported and return EOPNOTSUPP.",
	  "isotp.c:isotp_ops, isotp_getname()", NULL),
	T("API-SOCK-003", "ioctl() handling", 0, api_sock_ioctl,
	  "CAN_ISOTP has no protocol specific ioctls. Socket/netdev ioctls (e.g. SIOCGIFINDEX) are handled by the generic layers, others (e.g. FIONREAD) fail with ENOTTY.",
	  "isotp.c:isotp_sock_no_ioctlcmd()", NULL),
	T("API-SOCK-004", "getsockname()", 0, api_sock_getname,
	  "getsockname() returns 16 bytes (sockaddr_can up to can_addr.tp) with AF_CAN, the bound ifindex, rx_id and tx_id (all zero before bind()).",
	  "isotp.c:isotp_getname()", NULL),
	T("API-OPT-001", "default socket option values", 0, api_opt_defaults,
	  "A new socket has: flags 0, frame_txtime 50000 ns, ext_address 0, rx_ext_address 0, txpad/rxpad content 0xCC, RECV_FC bs 0 stmin 0 wftmax 0, TX_STMIN 0, RX_STMIN 0, LL mtu 16 tx_dl 8 tx_flags 0 and all XL options 0 (XL mode disabled).",
	  "isotp.c:isotp_init(), uapi isotp.h CAN_ISOTP_DEFAULT_*", NULL),
	T("API-OPT-002", "getsockopt() error handling", 0, api_opt_get_errors,
	  "getsockopt() requires level SOL_CAN_ISOTP (else EINVAL), known option names 1..6 (else ENOPROTOOPT) and optlen >= 0 (else EINVAL). Shorter buffers get the first optlen bytes, longer buffers get the option size in optlen. NULL optval leads to EFAULT.",
	  "isotp.c:isotp_getsockopt()", NULL),
	T("API-OPT-003", "setsockopt() error handling", 0, api_opt_set_errors,
	  "setsockopt() requires level SOL_CAN_ISOTP (EINVAL, checked first), a known option name (ENOPROTOOPT) and optlen equal to the option size (EINVAL). NULL optval leads to EFAULT.",
	  "isotp.c:isotp_setsockopt()", NULL),
	T("API-OPT-004", "CAN_ISOTP_OPTS: one broadcast flag", 0,
	  api_opt_bcflags,
	  "Only one of CAN_ISOTP_SF_BROADCAST, CAN_ISOTP_CF_BROADCAST and CAN_ISOTP_MF_BROADCAST may be set (else EINVAL). A rejected CAN_ISOTP_OPTS call leaves all options unchanged.",
	  "isotp.c:isotp_setsockopt_locked() hweight32(ISOTP_ALL_BC_FLAGS)", NULL),
	T("API-OPT-005", "CAN_ISOTP_OPTS: frame_txtime", 0, api_opt_txtime,
	  "frame_txtime (N_As/N_Ar) is limited to the N_As/N_Ar timeout of 1 s (else EINVAL, options unchanged). 0xFFFFFFFF (CAN_ISOTP_FRAME_TXTIME_ZERO) selects 0 ns, 0 keeps the current internal value. getsockopt() returns the struct as given by the last successful setsockopt() (incl. 0 / ZERO).",
	  "isotp.c:isotp_setsockopt_locked()", NULL),
	T("API-OPT-006", "CAN_ISOTP_OPTS: rx_ext_address", 0, api_opt_rxext,
	  "Without CAN_ISOTP_RX_EXT_ADDR the rx_ext_address is set to ext_address (visible with getsockopt). With the flag both addresses are kept independently.",
	  "isotp.c:isotp_setsockopt_locked()", NULL),
	T("API-OPT-013", "CAN_ISOTP_OPTS: padding check flags", 0,
	  api_opt_padchk,
	  "All combinations of the padding check flags are accepted and stored, also CAN_ISOTP_CHK_PAD_DATA without CAN_ISOTP_RX_PADDING (ignored on reception) and CAN_ISOTP_CHK_PAD_LEN without RX_PADDING (optimized frame length check).",
	  "isotp.c:isotp_setsockopt_locked() CAN_ISOTP_OPTS", NULL),
	T("API-OPT-008", "CAN_ISOTP_RECV_FC values", 0, api_opt_recvfc,
	  "CAN_ISOTP_RECV_FC stores bs and wftmax without checks. The reserved STmin values (0x80..0xF0, 0xFA..0xFF) are rejected with EINVAL and leave the stored values unchanged.",
	  "isotp.c:isotp_setsockopt_locked() CAN_ISOTP_RECV_FC", NULL),
	T("API-OPT-009", "CAN_ISOTP_TX_STMIN / RX_STMIN values", 0,
	  api_opt_stmin,
	  "CAN_ISOTP_TX_STMIN and CAN_ISOTP_RX_STMIN accept any u32 nanosecond value.",
	  "isotp.c:isotp_setsockopt_locked()", NULL),
	T("API-OPT-010", "CAN_ISOTP_LL_OPTS validation", 0, api_opt_ll,
	  "LL mtu must be 16 (CAN_MTU) or 72 (CANFD_MTU). tx_dl must be a CAN FD DLC length (8,12,16,20,24,32,48,64); with mtu 16 only tx_dl 8 and tx_flags 0 are valid, with mtu 72 only the tx_flags CANFD_BRS and CANFD_FDF (CANFD_ESI and undefined bits are rejected). For mtu 72 CANFD_FDF is always added to the stored tx_flags (visible with getsockopt). Rejected values leave the LL options unchanged (EINVAL).",
	  "isotp.c:isotp_setsockopt_locked() CAN_ISOTP_LL_OPTS", NULL),
	T("API-OPT-011", "CAN_ISOTP_XL_OPTS validation", 0, api_opt_xl,
	  "XL mode is enabled with CANXL_XLF in tx_flags. Then tx_flags and rx_flags may only contain XLF|SEC|RRS (rx_flags must contain XLF), tx_dl must be 8..2048, tx_addr/rx_addr must be valid 11/29 bit CAN IDs and sdt_mode must be 6, 7 or 9 (else EINVAL, options unchanged). VCIDs are not checked. The reserved bytes (__res[3], struct size 20) must be zero, also when disabling the XL mode (else EINVAL); getsockopt() returns them as zero. Without XLF the call disables XL mode without further checks and only clears the stored tx_flags.",
	  "isotp.c:isotp_setsockopt_locked() CAN_ISOTP_XL_OPTS", NULL),
	T("API-OPT-012", "socket options on bound sockets", 0, api_opt_bound,
	  "All socket options are rejected with EISCONN after bind() (the size check comes first). getsockopt() still works.",
	  "isotp.c:isotp_setsockopt_locked()", NULL),
	T("API-BIND-001", "bind(): address checks", 0, api_bind_addr,
	  "bind() requires an address length >= 16 and AF_CAN (else EINVAL). A second bind() fails with EINVAL.",
	  "isotp.c:isotp_bind()", NULL),
	T("API-BIND-002", "bind(): CAN ID validation", 0, api_bind_canid,
	  "tx_id and rx_id must be valid 11 bit or 29 bit (with CAN_EFF_FLAG) CAN IDs without RTR/ERR flags (else EINVAL).",
	  "isotp.c:isotp_invalid_canid()", NULL),
	T("API-BIND-003", "bind(): rx_id with broadcast flags", 0,
	  api_bind_bc_rxid,
	  "With SF/CF/MF broadcast flags the rx_id is not used: it is not validated and may be equal to tx_id.",
	  "isotp.c:isotp_bind(), protocolrx.c:isotp_register_rxid()", NULL),
	T("API-BIND-004", "bind(): rx_id equals tx_id", 0, api_bind_sameid,
	  "rx_id == tx_id is rejected with EADDRNOTAVAIL (11 bit and 29 bit IDs with the same numeric value are different).",
	  "isotp.c:isotp_bind()", NULL),
	T("API-BIND-005", "bind(): interface checks", 0, api_bind_ifindex,
	  "ifindex 0, a non existing interface or a non-CAN interface fail with ENODEV.",
	  "isotp.c:isotp_bind()", NULL),
	T("API-BIND-006", "bind(): interface MTU", 0, api_bind_mtu,
	  "The interface MTU must be >= the LL mtu: a CAN FD socket on a CAN CC interface fails with EINVAL, a CAN CC socket on a CAN FD interface and a CAN FD socket on a CAN XL interface are accepted.",
	  "isotp.c:isotp_bind() dev->mtu < so->ll.mtu", NULL),
	T("API-BIND-007", "bind(): padding and LL_DL", 0, api_bind_lldl,
	  "Padding is only defined for CAN CC/FD N_PDUs: with LL mtu 72 (CAN FD N_PDU) the effective TX_DL (also from CAN_ISOTP_XL_OPTS) must be a CAN FD DLC length; with LL mtu 16 CAN_ISOTP_TX_PADDING requires a TX_DL of 8 (CAN CC N_PDU), a CAN XL N_PDU (TX_DL > 8) is not padded (else EINVAL at bind()).",
	  "isotp.c:isotp_bind() fd_pdu()", NULL),
	T("API-BIND-008", "bind(): CAN XL settings", 0, api_bind_xl,
	  "In XL mode tx_id/rx_id must be 11 bit IDs (XL priority), SDT 7 requires LL mtu 72, SDT 6 requires LL mtu 16 and a TX_DL of 8 (else EINVAL). These checks come before the interface lookup.",
	  "isotp.c:isotp_bind(), isotp_bind_xl()", NULL),
	T("API-BIND-009", "bind() to an interface which is down", 0,
	  api_bind_down,
	  "bind() to a CAN interface which is down succeeds and reports ENETDOWN as socket error. send() fails synchronously with ENETDOWN and the socket stays usable.",
	  "isotp.c:isotp_bind() notify_enetdown, protocoltx.c:isotp_sendmsg() can_send()", NULL),
	T("API-BIND-010", "bind() of XL socket to CC interface", 0,
	  api_bind_xl_on_cc,
	  "bind() of a socket in XL mode to an interface without CAN XL support (MTU < CANXL_MIN_MTU) fails with EINVAL.",
	  "isotp.c:isotp_bind() isotp_req_mtu()", NULL),
	T("API-IO-001", "send()/recv() on unbound socket", 0, api_io_unbound,
	  "send() and recv() on an unbound socket fail with EADDRNOTAVAIL.",
	  "protocoltx.c:isotp_sendmsg(), isotp.c:isotp_recvmsg()", NULL),
	T("API-IO-002", "recv() flags", 0, api_io_recvflags,
	  "recv() only accepts MSG_DONTWAIT, MSG_TRUNC, MSG_PEEK and MSG_CMSG_COMPAT (else EINVAL). An empty queue with MSG_DONTWAIT returns EAGAIN.",
	  "isotp.c:isotp_recvmsg()", NULL),
	T("API-IO-003", "send() PDU size limits", 0, api_io_sendsize,
	  "send() with length 0 or more than max_pdu_size (module parameter, default 8300) fails with EINVAL. max_pdu_size bytes can be sent.",
	  "protocoltx.c:isotp_sendmsg()", NULL),
	T("API-IO-004", "recv() truncation, MSG_PEEK, address", 0,
	  api_io_trunc,
	  "A PDU is a datagram: with a short buffer the remaining bytes are discarded and MSG_TRUNC is set in msg_flags, with MSG_TRUNC recv() returns the full PDU length, MSG_PEEK keeps the PDU. msg_name gets 16 bytes with AF_CAN and the receiving ifindex (tp IDs zero).",
	  "isotp.c:isotp_recvmsg(), protocolrx.c:isotp_rcv_skb()", NULL),
	T("API-IO-005", "PDU receive queue order", 0, api_io_queue,
	  "Received PDUs are queued and delivered in order of reception.",
	  "protocolrx.c:isotp_rcv_skb()", NULL),
	T("API-IO-006", "PDU timestamp", 0, api_io_tstamp,
	  "The receive timestamp of a PDU (SO_TIMESTAMPNS) is the timestamp of the last received CAN frame of the PDU.",
	  "protocolrx.c:isotp_rcv_cf() nskb->tstamp = skb->tstamp", NULL),
	T("API-IO-007", "poll()", 0, api_io_poll,
	  "poll() reports POLLOUT only when no transfer is active, POLLIN when a PDU is queued and POLLERR when a socket error is pending.",
	  "isotp.c:isotp_poll()", NULL),
	T("API-IO-008", "send() while a transfer is active", 0, api_io_busy,
	  "Only one PDU can be sent at a time: send() with MSG_DONTWAIT fails with EAGAIN, a blocking send() waits until the active transfer is finished.",
	  "protocoltx.c:isotp_sendmsg()", NULL),
	T("API-IO-009", "asynchronous tx error reporting", 0, api_io_async_err,
	  "Without CAN_ISOTP_WAIT_TX_DONE send() returns the length immediately. A transfer error is reported via the socket error (SO_ERROR/POLLERR) and is returned by the next send() which then sends nothing. The error is cleared afterwards.",
	  "protocolrx.c:isotp_rcv_fc(), sock_alloc_send_skb() sock_error()", NULL),
	T("API-IO-010", "rx error reporting via recv()", 0, api_io_recv_err,
	  "A reception error (e.g. EILSEQ) is returned once by the next recv().",
	  "protocolrx.c:isotp_rcv_cf()", NULL),
	T("API-IO-012", "invalid user space buffers", 0, api_io_efault,
	  "send() with an invalid buffer fails with EFAULT without sending a frame and leaves the socket idle. recv() with an invalid buffer fails with EFAULT and the PDU is consumed.",
	  "protocoltx.c:isotp_sendmsg() memcpy_from_msg(), isotp.c:isotp_recvmsg() memcpy_to_msg()", NULL),
	T("API-IO-011", "close() during a transfer", FT_SLOW,
	  api_io_close_busy,
	  "close() waits for the end of an active transfer (here the N_Bs timeout of 1 s after a FF without FC).",
	  "isotp.c:isotp_release()", NULL),
};

int main(int argc, char **argv)
{
	return ft_main(argc, argv, "api", tests,
		       sizeof(tests) / sizeof(tests[0]));
}
