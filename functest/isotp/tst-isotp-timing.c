// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * tst-isotp-timing.c - CAN_ISOTP protocol timing
 *
 * Separation time of consecutive frames (STmin, frame_txtime,
 * CAN_ISOTP_TX_STMIN) and protocol timeouts (N_Bs, N_Cr).
 *
 * The lower bounds are checked strictly (hrtimers never fire early), the
 * upper bounds use the tolerance given with -T (default 20 ms).
 *
 * Send feedback to <linux-can@vger.kernel.org>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "ft.h"

#define US 1000LL
#define MS 1000000LL

#define TXT_ZERO CAN_ISOTP_FRAME_TXTIME_ZERO
#define TXT_DEF (FT_DEF_FRAME_TXTIME * 1LL)

/* slack for the lower bound: timestamp of the frame vs. timer start */
#define LOW_SLACK (30 * US)

struct stm_param {
	uint8_t stmin;		/* STmin in the FC */
	int64_t force;		/* CAN_ISOTP_TX_STMIN (>= 0 => FORCE_TXSTMIN) */
	uint32_t txtime;	/* frame_txtime option (0 => default 50 us) */
	uint32_t bcflag;	/* CF broadcast */
	int64_t gap;		/* expected gap (ns), < 0 => burst */
	int ncf;		/* number of CFs */
};

static int cmp64(const void *a, const void *b)
{
	int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;

	return (x > y) - (x < y);
}

static void tim_stmin(struct ft_ctx *ctx, const void *param)
{
	const struct stm_param *sp = param;
	static uint8_t data[2000];
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc e, pe;
	struct ft_frame hrx, fc, f;
	struct ft_async a;
	int64_t ts[64], gaps[64], gmin, gmed, gmax;
	unsigned int len;
	int s, i, ngap;

	ft_cfg_init(&c);
	c.opts.flags |= CAN_ISOTP_WAIT_TX_DONE | sp->bcflag;
	c.opts.frame_txtime = sp->txtime;
	if (sp->force >= 0) {
		c.opts.flags |= CAN_ISOTP_FORCE_TXSTMIN;
		c.set_tx_stmin = true;
		c.tx_stmin = sp->force;
	}

	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_dut(&c, &e);
	ft_enc_peer(&c, &pe);
	ft_hdr_dut_rx(&c, &hrx);

	len = 6 + sp->ncf * 7;
	ft_pattern(data, len, 1);
	ft_async_send(&a, s, data, len, 0);

	if (!ft_peer_next(ctx, &p, &f, 500)) {
		ft_fail(ctx, "no FF");
		goto out;
	}
	ts[0] = f.ts;

	if (!sp->bcflag) {
		ft_enc_fc(&pe, &hrx, FT_FS_CTS, 0, sp->stmin, &fc);
		ft_peer_tx(ctx, &p, &fc);
	}

	for (i = 1; i <= sp->ncf; i++) {
		if (!ft_peer_next(ctx, &p, &f, 2000)) {
			ft_fail(ctx, "CF %d missing", i);
			goto out;
		}
		FT_CHECK(ctx, f.data[0] == (0x20 | (i & 0x0F)), "CF %d N_PCI %02X",
			 i, f.data[0]);
		ts[i] = f.ts;
	}

	ft_async_join(ctx, &a, 3000);
	FT_CHECK(ctx, a.ret == (ssize_t)len, "send() %zd", a.ret);

	/* gaps between the CFs (the first CF follows the FC immediately) */
	ngap = 0;
	for (i = 2; i <= sp->ncf; i++)
		gaps[ngap++] = ts[i] - ts[i - 1];
	/* broadcast: the gap FF -> CF1 is timed as well */
	if (sp->bcflag)
		gaps[ngap++] = ts[1] - ts[0];

	qsort(gaps, ngap, sizeof(gaps[0]), cmp64);
	gmin = gaps[0];
	gmax = gaps[ngap - 1];
	gmed = gaps[ngap / 2];

	ft_log(ctx, "expected gap %lld us: min %lld us, median %lld us, max %lld us (%d gaps)",
	       (long long)sp->gap / 1000, (long long)gmin / 1000,
	       (long long)gmed / 1000, (long long)gmax / 1000, ngap);

	if (sp->gap < 0) {
		FT_CHECK(ctx, gmax < ft_cfg.tol_ms * MS,
			 "burst expected, max gap %lld us", (long long)gmax / 1000);
	} else {
		FT_CHECK(ctx, gmin >= sp->gap - LOW_SLACK,
			 "gap too short: min %lld us < %lld us",
			 (long long)gmin / 1000, (long long)sp->gap / 1000);
		FT_CHECK(ctx, gmed <= sp->gap + ft_cfg.tol_ms * MS,
			 "gap too long: median %lld us > %lld us + %d ms",
			 (long long)gmed / 1000, (long long)sp->gap / 1000,
			 ft_cfg.tol_ms);
	}
out:
	if (a.started)
		ft_async_join(ctx, &a, 4000);
	ft_peer_close(&p);
	close(s);
}

/* ------------------------------------------------------------------------
 * timeouts
 * ------------------------------------------------------------------------
 */

struct to_param {
	const char *what;
	uint32_t txtime;	/* frame_txtime option */
	int64_t expect;		/* expected timeout (ns) */
};

static bool check_timeout(struct ft_ctx *ctx, int64_t t_ref, int64_t t_err,
			  int64_t expect)
{
	int64_t d = t_err - t_ref;

	ft_log(ctx, "timeout after %lld us (expected %lld us)",
	       (long long)d / 1000, (long long)expect / 1000);

	return FT_CHECK(ctx, d >= expect - 2 * MS &&
			d <= expect + ft_cfg.tol_ms * MS,
			"timeout %lld us, expected %lld us (+%d ms)",
			(long long)d / 1000, (long long)expect / 1000,
			ft_cfg.tol_ms);
}

static void tim_nbs(struct ft_ctx *ctx, const void *param)
{
	const struct to_param *tp = param;
	static uint8_t data[100];
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc pe;
	struct ft_frame hrx, fc, f;
	int64_t t_ref = 0, t_err;
	ssize_t n;
	int s;

	ft_cfg_init(&c);
	c.opts.frame_txtime = tp->txtime;
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_peer(&c, &pe);
	ft_hdr_dut_rx(&c, &hrx);

	ft_pattern(data, sizeof(data), 0);
	n = ft_dut_send(ctx, s, data, 30, 0);
	FT_CHECK(ctx, n == 30, "send %zd", n);
	if (!ft_peer_next(ctx, &p, &f, 500)) {
		ft_fail(ctx, "no FF");
		goto out;
	}
	t_ref = f.ts;

	if (!strcmp(tp->what, "block")) {
		/* BS 1 => wait for FC after CF1 */
		ft_enc_fc(&pe, &hrx, FT_FS_CTS, 1, 0, &fc);
		ft_peer_tx(ctx, &p, &fc);
		if (!ft_peer_next(ctx, &p, &f, 500)) {
			ft_fail(ctx, "no CF");
			goto out;
		}
		t_ref = f.ts;
	} else if (!strcmp(tp->what, "wt")) {
		ft_enc_fc(&pe, &hrx, FT_FS_WT, 0, 0, &fc);
		ft_peer_tx(ctx, &p, &fc);
		t_ref = ft_now_ns();
	}

	if (ft_dut_expect_err(ctx, s, ECOMM, 3000, &t_err))
		check_timeout(ctx, t_ref, t_err, tp->expect);
out:
	ft_peer_close(&p);
	close(s);
}

static void tim_ncr(struct ft_ctx *ctx, const void *param)
{
	const struct to_param *tp = param;
	static uint8_t pdu[100];
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc pe;
	struct ft_frame hrx, f;
	struct ft_frame *fr = NULL;
	int64_t t_ref = 0, t_err;
	int s, n;

	ft_cfg_init(&c);
	c.opts.frame_txtime = tp->txtime;
	if (!strcmp(tp->what, "listen"))
		c.opts.flags |= CAN_ISOTP_LISTEN_MODE;
	if (!strcmp(tp->what, "block"))
		c.fc.bs = 2;
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_peer(&c, &pe);
	ft_hdr_dut_rx(&c, &hrx);

	ft_pattern(pdu, sizeof(pdu), 0);
	n = ft_enc_pdu(&pe, &hrx, pdu, 60, &fr);
	if (n < 4)
		goto out;

	ft_peer_tx(ctx, &p, &fr[0]);
	t_ref = ft_now_ns();

	if (strcmp(tp->what, "listen")) {
		/* FC of the DUT */
		if (!ft_peer_next(ctx, &p, &f, 500)) {
			ft_fail(ctx, "no FC");
			goto out;
		}
		t_ref = f.ts;
	}

	if (!strcmp(tp->what, "cf")) {
		/* CF1 (no block end) */
		ft_peer_tx(ctx, &p, &fr[1]);
		t_ref = ft_now_ns();
	} else if (!strcmp(tp->what, "block")) {
		/* CF1 + CF2 => FC after the block */
		ft_peer_tx(ctx, &p, &fr[1]);
		ft_peer_tx(ctx, &p, &fr[2]);
		if (!ft_peer_next(ctx, &p, &f, 500)) {
			ft_fail(ctx, "no FC after block");
			goto out;
		}
		t_ref = f.ts;
	}

	if (ft_dut_expect_err(ctx, s, ETIMEDOUT, 3000, &t_err))
		check_timeout(ctx, t_ref, t_err, tp->expect);
out:
	free(fr);
	ft_peer_close(&p);
	close(s);
}

/* ------------------------------------------------------------------------
 * local echo timeout (real CAN interface without bus partner)
 *
 * Without a second node on the bus the CAN frame is never acknowledged
 * and the controller retries it. The local echo (IFF_ECHO) only comes
 * after a successful transmission and therefore never arrives.
 * ------------------------------------------------------------------------
 */

struct echo_param {
	const char *what;
	enum ft_if iface;
};

static void tim_echo(struct ft_ctx *ctx, const void *param)
{
	const struct echo_param *ep = param;
	const char *what = ep->what;
	struct ft_isotp_cfg c;
	struct pollfd pfd;
	static uint8_t data[100];
	int64_t t0, t_err = 0, expect = 2000 * MS + TXT_DEF;
	unsigned int len = 5;
	ssize_t n;
	int s;

	if (ep->iface == FT_IF_HW ? !ft_need_hw(ctx) :
	    !ft_need_echo_if(ctx, ep->iface))
		return;

	ft_cfg_init(&c);
	c.iface = ep->iface;
	if (!strcmp(what, "wtd"))
		c.opts.flags |= CAN_ISOTP_WAIT_TX_DONE;
	if (!strcmp(what, "cfbc")) {
		c.opts.flags |= CAN_ISOTP_CF_BROADCAST;
		len = 20;
	}
	if (!strcmp(what, "ff")) {
		/* FF echo is not monitored: N_Bs (FC timeout) applies */
		len = 20;
		expect = 1000 * MS + TXT_DEF;
	}

	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);

	ft_pattern(data, len, 0x5A);
	t0 = ft_now_ns();
	n = ft_dut_send(ctx, s, data, len, 0);

	if (!strcmp(what, "wtd")) {
		/* send() returns the result after the echo timeout */
		t_err = ft_now_ns();
		FT_CHECK(ctx, n == -ECOMM,
			 "send() returned %zd %s (echo received: another node on the bus / no frame loss?)", n,
			 n < 0 ? ft_errname(n) : "");
		ft_dut_expect_noerr(ctx, s);
	} else {
		if (!FT_CHECK(ctx, n == (ssize_t)len, "send() %zd %s", n,
			      n < 0 ? ft_errname(n) : ""))
			goto out;

		/* the transfer is active: not writable */
		ft_sleep_ms(100);
		pfd.fd = s;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		FT_CHECK(ctx, poll(&pfd, 1, 0) == 0,
			 "POLLOUT while waiting for the echo (revents %X, another node on the bus?)",
			 pfd.revents);

		/* a second PDU can not be sent */
		n = ft_dut_send(ctx, s, data, 3, MSG_DONTWAIT);
		FT_CHECK(ctx, n == -EAGAIN, "2nd send(): %s", ft_errname(n));

		ft_dut_expect_err(ctx, s, ECOMM, 4000, &t_err);
	}

	if (t_err)
		check_timeout(ctx, t0, t_err, expect);

	/* the socket is idle again */
	pfd.fd = s;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	FT_CHECK(ctx, poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLOUT),
		 "socket not writable after the timeout (revents %X)",
		 pfd.revents);
out:
	close(s);
}

/* late echo (vcan echo=1 + netem delay 3000ms): the echo of the timed out
 * SF arrives during the next transfer and must not complete it
 */
static void tim_echo_late(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	static uint8_t data[8];
	int64_t t0, t1;
	ssize_t n;
	int s;

	if (!ft_need_echo_if(ctx, FT_IF_EDELAY))
		return;

	ft_cfg_init(&c);
	c.iface = FT_IF_EDELAY;
	c.opts.flags |= CAN_ISOTP_WAIT_TX_DONE;
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);

	/* 1st SF: echo after 3 s => ECOMM after 2 s */
	ft_pattern(data, 5, 1);
	t0 = ft_now_ns();
	n = ft_dut_send(ctx, s, data, 5, 0);
	t1 = ft_now_ns();
	FT_CHECK(ctx, n == -ECOMM, "1st send() %zd %s", n,
		 n < 0 ? ft_errname(n) : "");
	check_timeout(ctx, t0, t1, 2000 * MS + TXT_DEF);

	/* 2nd SF: the late echo of the 1st SF arrives after 1 s, the own
	 * echo after 3 s => ECOMM after 2 s (not completed by the 1st echo)
	 */
	n = ft_dut_send(ctx, s, data, 4, 0);
	FT_CHECK(ctx, n == -ECOMM,
		 "2nd send() %zd %s (completed by the late echo of the 1st SF?)",
		 n, n < 0 ? ft_errname(n) : "");
	check_timeout(ctx, t1, ft_now_ns(), 2000 * MS + TXT_DEF);

	/* the late echo of the 2nd SF (after 1 s) changes nothing */
	ft_sleep_ms(1200);
	ft_dut_expect_noerr(ctx, s);

	close(s);
}

/* slow echo (vcan echo=1 + netem delay 100ms): the local echo is the
 * transmission confirmation which paces the transfer
 */
struct slow_param {
	enum ft_if iface;	/* FT_IF_ESLOW (netem) or FT_IF_ERATE (tbf) */
	uint8_t stmin;
	uint32_t bcflag;
	int64_t gap;		/* expected gap between the frames */
};

static void tim_echo_slow(struct ft_ctx *ctx, const void *param)
{
	const struct slow_param *sp = param;
	struct ft_isotp_cfg c;
	struct ft_peer p;
	struct ft_enc pe;
	struct ft_frame hrx, fc, f;
	struct ft_async a;
	static uint8_t data[100];
	int64_t ts[8], t0, slack;
	unsigned int len = 6 + 3 * 7; /* FF + 3 CFs */
	int s, i;

	if (!ft_need_echo_if(ctx, sp->iface))
		return;

	ft_cfg_init(&c);
	c.iface = sp->iface;
	c.opts.flags |= CAN_ISOTP_WAIT_TX_DONE | sp->bcflag;
	s = ft_isotp_open(ctx, &c);
	FT_BAIL(ctx);
	if (ft_peer_open(ctx, &p, c.iface)) {
		close(s);
		return;
	}

	ft_enc_peer(&c, &pe);
	ft_hdr_dut_rx(&c, &hrx);

	/* SF: send() returns after the delayed echo */
	ft_pattern(data, sizeof(data), 3);
	t0 = ft_now_ns();
	FT_CHECK(ctx, ft_dut_send(ctx, s, data, 5, 0) == 5, "SF send()");
	ft_log(ctx, "SF send() returned after %lld us",
	       (long long)(ft_now_ns() - t0) / 1000);
	if (sp->iface == FT_IF_ESLOW)
		FT_CHECK(ctx, ft_now_ns() - t0 >= 100 * MS - LOW_SLACK,
			 "SF send() returned before the (delayed) echo");
	ft_peer_next(ctx, &p, &f, 500);

	/* segmented PDU: the peer sees the frames after the qdisc delay */
	ft_async_send(&a, s, data, len, 0);
	if (!ft_peer_next(ctx, &p, &f, 1000)) {
		ft_fail(ctx, "no FF");
		goto out;
	}
	ts[0] = f.ts;
	if (!sp->bcflag) {
		/* the FC is delayed by the qdisc as well */
		ft_enc_fc(&pe, &hrx, FT_FS_CTS, 0, sp->stmin, &fc);
		ft_peer_tx(ctx, &p, &fc);
	}
	for (i = 1; i <= 3; i++) {
		if (!ft_peer_next(ctx, &p, &f, 1000)) {
			ft_async_join(ctx, &a, 3000);
			if (sp->iface == FT_IF_ESLOW && i > 1 && a.ret == -ECOMM) {
				ft_note_finding(ctx, "CF %d not sent, transfer aborted with ECOMM: the echo of CF %d was not recognized. netem (delay) calls skb_orphan_partial() (net/core/sock.c) which keeps skb->sk only for skbs with sock_wfree destructor; the CF skbs from alloc_skb() + can_skb_set_owner() are already partially orphaned (sock_efree + sk reference) but lose skb->sk, so isotp_rcv_echo() drops the echo (skb->sk != sk). SF/FF skbs from sock_alloc_send_skb() keep skb->sk. Cause in net/core: skb_orphan_partial() should keep sock_efree skbs.",
						i, i - 1);
			} else {
				ft_fail(ctx, "CF %d missing (send() %zd %s)", i,
					a.ret, a.ret < 0 ? ft_errname(a.ret) : "");
			}
			goto out;
		}
		FT_CHECK(ctx, f.data[0] == (0x20 | i), "CF %d N_PCI %02X", i,
			 f.data[0]);
		ts[i] = f.ts;
	}
	if (ft_async_join(ctx, &a, 3000))
		FT_CHECK(ctx, a.ret == (ssize_t)len, "send() %zd %s", a.ret,
			 a.ret < 0 ? ft_errname(a.ret) : "");

	/* the gap between the CFs starts with the echo of the previous CF */
	/* tbf paces the frames by its token bucket (not by an isotp hrtimer)
	 * with some imprecision => 1 ms slack for the lower bound
	 */
	slack = (sp->iface == FT_IF_ERATE) ? 1 * MS : LOW_SLACK;

	/* tbf: the token bucket is not empty after an idle phase, so the
	 * gap FF -> CF1 can be shorter than the frame time
	 */
	for (i = (sp->bcflag && sp->iface != FT_IF_ERATE) ? 1 : 2; i <= 3; i++) {
		int64_t d = ts[i] - ts[i - 1];

		ft_log(ctx, "gap %d: %lld us (expected %lld us)", i,
		       (long long)d / 1000, (long long)sp->gap / 1000);
		FT_CHECK(ctx, d >= sp->gap - slack &&
			 d <= sp->gap + ft_cfg.tol_ms * MS,
			 "gap %d: %lld us, expected %lld us", i,
			 (long long)d / 1000, (long long)sp->gap / 1000);
	}
out:
	if (a.started)
		ft_async_join(ctx, &a, 4000);
	ft_peer_close(&p);
	close(s);
}

/* ------------------------------------------------------------------------
 * test table
 * ------------------------------------------------------------------------
 */

#define T(i, t, fl, f, p, rq, rf, is)					\
	{ .id = i, .title = t, .req = rq, .ref = rf, .iso = is,		\
	  .flags = fl, .fn = f, .param = p }

static const char stm_req[] =
	"The gap between consecutive frames is frame_txtime (N_As, default 50 us) + STmin from the first FC: 0x00..0x7F => 0..127 ms, 0xF1..0xF9 => 100..900 us, reserved values (0x80..0xF0, 0xFA..0xFF) => 127 ms. With CAN_ISOTP_FORCE_TXSTMIN the CAN_ISOTP_TX_STMIN value (ns) replaces the FC STmin. Without any gap the CFs are sent in burst mode (no timer).";
static const char stm_ref[] =
	"protocolrx.c:isotp_rcv_fc() tx_gap, protocoltx.c:isotp_rcv_echo(), hrtimer.c:isotp_txfr_timer_handler()";

#define STM(i, t, st, fo, tt, g, n)					\
	T("TIM-STM-" i, t, FT_TIMING, tim_stmin,			\
	  &((const struct stm_param){ st, fo, tt, 0, g, n }), stm_req,	\
	  stm_ref, NULL)

static const char bc_req[] =
	"In CF/MF broadcast mode (no FC) the gap between all frames is frame_txtime, or CAN_ISOTP_TX_STMIN with FORCE_TXSTMIN (without frame_txtime).";

static const struct ft_test tests[] = {
	STM("001", "burst (STmin 0, frame_txtime 0)", 0, -1, TXT_ZERO, -1, 20),
	STM("002", "STmin 0, default frame_txtime", 0, -1, 0, TXT_DEF, 20),
	STM("003", "STmin 1 ms", 0x01, -1, 0, 1 * MS + TXT_DEF, 10),
	STM("004", "STmin 10 ms", 0x0A, -1, 0, 10 * MS + TXT_DEF, 6),
	STM("005", "STmin 127 ms", 0x7F, -1, 0, 127 * MS + TXT_DEF, 3),
	STM("006", "STmin 100 us", 0xF1, -1, 0, 100 * US + TXT_DEF, 20),
	STM("007", "STmin 500 us", 0xF5, -1, 0, 500 * US + TXT_DEF, 20),
	STM("008", "STmin 900 us", 0xF9, -1, 0, 900 * US + TXT_DEF, 20),
	STM("009", "reserved STmin 0x80", 0x80, -1, 0, 127 * MS + TXT_DEF, 3),
	STM("010", "reserved STmin 0xF0", 0xF0, -1, 0, 127 * MS + TXT_DEF, 3),
	STM("011", "reserved STmin 0xFA", 0xFA, -1, 0, 127 * MS + TXT_DEF, 3),
	STM("012", "reserved STmin 0xFF", 0xFF, -1, 0, 127 * MS + TXT_DEF, 3),
	STM("013", "FORCE_TXSTMIN 20 ms (FC STmin 0)", 0, 20 * MS, 0,
	    20 * MS + TXT_DEF, 5),
	STM("014", "FORCE_TXSTMIN 0 (FC STmin 127 ms)", 0x7F, 0, TXT_ZERO, -1,
	    10),
	STM("015", "FORCE_TXSTMIN 250 us", 0x7F, 250 * US, 0,
	    250 * US + TXT_DEF, 20),
	STM("016", "frame_txtime 5 ms", 0, -1, 5 * MS, 5 * MS, 6),
	STM("017", "frame_txtime 5 ms + STmin 10 ms", 0x0A, -1, 5 * MS,
	    15 * MS, 5),
	STM("018", "frame_txtime 100 ms", 0, -1, 100 * MS, 100 * MS, 3),
	STM("019", "frame_txtime 1 ns", 0, -1, 1, 0, 20),

	T("TIM-BC-001", "CF broadcast gap (frame_txtime 5 ms)", FT_TIMING,
	  tim_stmin,
	  &((const struct stm_param){ 0, -1, 5 * MS, CAN_ISOTP_CF_BROADCAST,
				      5 * MS, 6 }),
	  bc_req, "protocoltx.c:isotp_sendmsg() tx_gap", NULL),
	T("TIM-BC-002", "CF broadcast gap (FORCE_TXSTMIN 10 ms)", FT_TIMING,
	  tim_stmin,
	  &((const struct stm_param){ 0, 10 * MS, 50 * MS,
				      CAN_ISOTP_CF_BROADCAST, 10 * MS, 6 }),
	  bc_req, "protocoltx.c:isotp_sendmsg() tx_gap", NULL),
	T("TIM-BC-003", "MF broadcast gap (default frame_txtime)", FT_TIMING,
	  tim_stmin,
	  &((const struct stm_param){ 0, -1, 0, CAN_ISOTP_MF_BROADCAST,
				      TXT_DEF, 20 }),
	  bc_req, "protocoltx.c:isotp_sendmsg() tx_gap", NULL),

	T("TIM-NBS-001", "N_Bs after FF", FT_SLOW | FT_TIMING, tim_nbs,
	  &((const struct to_param){ "ff", 0, 1000 * MS + TXT_DEF }),
	  "The FC timeout after the FF is 1 s + frame_txtime (ECOMM).",
	  "protocoltx.c:isotp_sendmsg() hrtimer_start(txtimer)", NULL),
	T("TIM-NBS-002", "N_Bs after FF (frame_txtime 100 ms)",
	  FT_SLOW | FT_TIMING, tim_nbs,
	  &((const struct to_param){ "ff", 100 * MS, 1100 * MS }),
	  "The FC timeout after the FF is 1 s + frame_txtime (ECOMM).",
	  "protocoltx.c:isotp_sendmsg() hrtimer_start(txtimer)", NULL),
	T("TIM-NBS-003", "N_Bs after a block (frame_txtime 100 ms)",
	  FT_SLOW | FT_TIMING, tim_nbs,
	  &((const struct to_param){ "block", 100 * MS, 1000 * MS }),
	  "The FC timeout after a block of CFs is 1 s without frame_txtime (ECOMM).",
	  "protocoltx.c:isotp_rcv_echo() hrtimer_start(txtimer)",
	  "REVIEW: frame_txtime (N_As/N_Ar) is only added to the first N_Bs timeout."),
	T("TIM-NBS-004", "N_Bs after FC.WT (frame_txtime 100 ms)",
	  FT_SLOW | FT_TIMING, tim_nbs,
	  &((const struct to_param){ "wt", 100 * MS, 1000 * MS }),
	  "The FC timeout after a FC.WT is 1 s without frame_txtime (ECOMM).",
	  "protocolrx.c:isotp_rcv_fc() ISOTP_FC_WT", NULL),
	T("TIM-NCR-001", "N_Cr after FC", FT_SLOW | FT_TIMING, tim_ncr,
	  &((const struct to_param){ "ff", 0, 1000 * MS + TXT_DEF }),
	  "The CF timeout after a sent FC is 1 s + frame_txtime (ETIMEDOUT).",
	  "protocoltx.c:isotp_send_fc()", NULL),
	T("TIM-NCR-002", "N_Cr after FC (frame_txtime 100 ms)",
	  FT_SLOW | FT_TIMING, tim_ncr,
	  &((const struct to_param){ "ff", 100 * MS, 1100 * MS }),
	  "The CF timeout after a sent FC is 1 s + frame_txtime (ETIMEDOUT).",
	  "protocoltx.c:isotp_send_fc()", NULL),
	T("TIM-NCR-003", "N_Cr after CF (frame_txtime 100 ms)",
	  FT_SLOW | FT_TIMING, tim_ncr,
	  &((const struct to_param){ "cf", 100 * MS, 1000 * MS }),
	  "The CF timeout after a received CF (no block end) is 1 s without frame_txtime (ETIMEDOUT).",
	  "protocolrx.c:isotp_rcv_cf() hrtimer_start(rxtimer)", NULL),
	T("TIM-NCR-004", "N_Cr after block FC (frame_txtime 100 ms)",
	  FT_SLOW | FT_TIMING, tim_ncr,
	  &((const struct to_param){ "block", 100 * MS, 1100 * MS }),
	  "The CF timeout after the FC at a block end is 1 s + frame_txtime (ETIMEDOUT).",
	  "protocoltx.c:isotp_send_fc()", NULL),
	T("TIM-NCR-005", "N_Cr in listen mode (frame_txtime 100 ms)",
	  FT_SLOW | FT_TIMING, tim_ncr,
	  &((const struct to_param){ "listen", 100 * MS, 1000 * MS }),
	  "In listen mode the CF timeout after the FF is 1 s without frame_txtime (ETIMEDOUT).",
	  "protocolrx.c:isotp_rcv_ff() hrtimer_start(rxtimer)", NULL),

#define ECHO(i, t, w, fi, rq, rf, is)					\
	T("TIM-ECHO-" i, t, FT_SLOW | FT_TIMING, tim_echo,		\
	  &((const struct echo_param){ w, FT_IF_ELOSS }),		\
	  "vcan with echo=1 and netem loss 100% (setup_vcan.sh -e): " rq, rf, is), \
	T("TIM-ECHO-HW-" i, t " (real CAN)", FT_SLOW | FT_TIMING, tim_echo, \
	  &((const struct echo_param){ w, FT_IF_HW }),			\
	  "Real CAN interface (FT_IF_HW) without bus partner: " rq, rf, is)

	ECHO("001", "echo timeout SF (WAIT_TX_DONE)", "wtd", 0,
	     "when the local echo of a SF does not arrive, the transfer is aborted after 2 s + frame_txtime and send() with CAN_ISOTP_WAIT_TX_DONE returns ECOMM; the socket error is cleared and the socket is idle again.",
	     "protocoltx.c:isotp_sendmsg() echotimer, hrtimer.c:isotp_echo_timer_handler(), isotp_tx_timeout()", NULL),
	ECHO("002", "echo timeout SF (asynchronous)", "async", 0,
	     "without CAN_ISOTP_WAIT_TX_DONE send() returns immediately; while waiting for the echo the socket is not writable and further send() calls fail with EAGAIN (MSG_DONTWAIT). After 2 s + frame_txtime the socket error ECOMM is reported and the socket is idle again.",
	     "protocoltx.c:isotp_sendmsg() echotimer, hrtimer.c:isotp_echo_timer_handler()", NULL),
	ECHO("003", "echo timeout CF broadcast FF", "cfbc", 0,
	     "in CF broadcast mode the echo of the FF is monitored; without echo the transfer is aborted after 2 s + frame_txtime with ECOMM.",
	     "protocoltx.c:isotp_sendmsg() CF broadcast cfecho, hrtimer.c:isotp_echo_timer_handler()", NULL),
	ECHO("004", "FF without echo (N_Bs)", "ff", 0,
	     "the echo of a FF (with FC) is not monitored, the transfer is aborted by the N_Bs timeout after 1 s + frame_txtime with ECOMM.",
	     "protocoltx.c:isotp_sendmsg() txtimer for ISOTP_WAIT_FIRST_FC",
	     "REVIEW: N_As (missing transmission confirmation) is monitored with 2 s for SF/CF and covered by N_Bs (1 s) for the FF."),
	T("TIM-ECHO-005", "late echo after echo timeout", FT_SLOW | FT_TIMING,
	  tim_echo_late, NULL,
	  "vcan with echo=1 and netem delay 3000ms (setup_vcan.sh -e): a SF whose echo arrives after 3 s is aborted after 2 s + frame_txtime with ECOMM. The late echo arriving during the next SF transfer does not complete that transfer (echo identified by the skb uid), which is aborted with ECOMM as well.",
	  "protocoltx.c:isotp_rcv_echo() cfecho / can_skb_uid check", NULL),
	T("TIM-ECHO-006", "netem delayed echo (STmin 10 ms)", FT_TIMING,
	  tim_echo_slow,
	  &((const struct slow_param){ FT_IF_ESLOW, 0x0A, 0, 100 * MS + 10 * MS + TXT_DEF }),
	  "vcan with echo=1 and netem delay 100ms (setup_vcan.sh -e): a SF send() with WAIT_TX_DONE returns after the delayed echo. Expected: the separation time between CFs (STmin + frame_txtime) starts at the echo of the previous CF (gap = echo delay + STmin + frame_txtime). Observed behaviour is reported.",
	  "protocoltx.c:isotp_send_cframe() alloc_skb()/can_skb_set_owner(), isotp_rcv_echo() skb->sk check, sch_netem.c:netem_enqueue(), sock.c:skb_orphan_partial()",
	  "FINDING (if observed): netem with delay orphans the CF skbs (sock_efree destructor), the CF echo is not recognized and the transfer is aborted with ECOMM. Cause in net/core: skb_orphan_partial() does not keep already partially orphaned (sock_efree) skbs."),
	T("TIM-ECHO-007", "netem delayed echo (CF broadcast)", FT_TIMING,
	  tim_echo_slow,
	  &((const struct slow_param){ FT_IF_ESLOW, 0, CAN_ISOTP_CF_BROADCAST, 100 * MS + TXT_DEF }),
	  "vcan with echo=1 and netem delay 100ms (setup_vcan.sh -e): expected: in CF broadcast mode each frame (incl. the FF) is sent after the echo of the previous frame + frame_txtime. Observed behaviour is reported.",
	  "protocoltx.c:isotp_send_cframe() alloc_skb()/can_skb_set_owner(), isotp_rcv_echo() skb->sk check, sch_netem.c:netem_enqueue(), sock.c:skb_orphan_partial()",
	  "FINDING (if observed): netem with delay orphans the CF skbs (sock_efree destructor), the CF echo is not recognized and the transfer is aborted with ECOMM. Cause in net/core: skb_orphan_partial() does not keep already partially orphaned (sock_efree) skbs."),
	T("TIM-ECHO-008", "slow bus paces CFs (tbf, STmin 0)", FT_TIMING,
	  tim_echo_slow,
	  &((const struct slow_param){ FT_IF_ERATE, 0x00, 0, 64 * MS }),
	  "vcan with echo=1 and tbf rate 2kbit (setup_vcan.sh -e, 64 ms per CAN CC frame): the transfer completes and the CFs are paced by the transmission confirmation (echo): gap = max(frame time, STmin + frame_txtime) = 64 ms.",
	  "protocoltx.c:isotp_rcv_echo()", NULL),
	T("TIM-ECHO-009", "slow bus paces CFs (tbf, STmin 100 ms)", FT_TIMING,
	  tim_echo_slow,
	  &((const struct slow_param){ FT_IF_ERATE, 0x64, 0, 100 * MS + TXT_DEF }),
	  "vcan with echo=1 and tbf rate 2kbit (setup_vcan.sh -e, 64 ms per CAN CC frame): with STmin 100 ms > frame time the gap between CFs is STmin + frame_txtime, measured from the echo of the previous CF.",
	  "protocoltx.c:isotp_rcv_echo() txfrtimer start", NULL),
	T("TIM-ECHO-010", "slow bus paces CF broadcast (tbf)", FT_TIMING,
	  tim_echo_slow,
	  &((const struct slow_param){ FT_IF_ERATE, 0, CAN_ISOTP_CF_BROADCAST, 64 * MS }),
	  "vcan with echo=1 and tbf rate 2kbit (setup_vcan.sh -e, 64 ms per CAN CC frame): in CF broadcast mode the CFs are paced by the transmission confirmation (gap between the CFs = frame time).",
	  "protocoltx.c:isotp_rcv_echo()", NULL),
};

int main(int argc, char **argv)
{
	return ft_main(argc, argv, "timing", tests,
		       sizeof(tests) / sizeof(tests[0]));
}
