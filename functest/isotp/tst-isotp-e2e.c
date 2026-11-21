// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * tst-isotp-e2e.c - CAN_ISOTP end-to-end tests
 *
 * Two (or more) CAN_ISOTP sockets communicate with each other on the same
 * CAN interface: both directions, full duplex, asymmetric link layer
 * settings, 1-to-n broadcast/multicast and listen mode sniffers.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "ft.h"

#define MAXS 5

static uint8_t txbuf[2][FT_MAX_PDU];

/* send len bytes from sx (async) and check the reception on all sy[] */
static bool e2e_xfer(struct ft_ctx *ctx, int sx, int *sy, int ny,
		     const bool *rx_ok, unsigned int len, unsigned int seed)
{
	struct ft_async a;
	int i;
	bool ok = true;

	ft_pattern(txbuf[0], len, seed);
	ft_log(ctx, "transfer %u byte", len);
	ft_async_send(&a, sx, txbuf[0], len, 0);

	for (i = 0; i < ny; i++) {
		if (!rx_ok || rx_ok[i])
			ok &= ft_dut_expect_pdu(ctx, sy[i], txbuf[0], len, 3000);
		else
			ok &= ft_dut_expect_nopdu(ctx, sy[i], 50);
	}

	if (!ft_async_join(ctx, &a, 3000))
		return false;

	ok &= FT_CHECK(ctx, a.ret == (ssize_t)len, "send() %zd %s", a.ret,
		       a.ret < 0 ? ft_errname(a.ret) : "");

	for (i = 0; i < ny; i++)
		ok &= ft_dut_expect_noerr(ctx, sy[i]);
	ok &= ft_dut_expect_noerr(ctx, sx);

	return ok;
}

static bool e2e_duplex(struct ft_ctx *ctx, int sa, int sb, unsigned int la,
		       unsigned int lb)
{
	struct ft_async a, b;
	bool ok = true;

	ft_log(ctx, "full duplex transfer %u / %u byte", la, lb);
	ft_pattern(txbuf[0], la, 0xA0);
	ft_pattern(txbuf[1], lb, 0xB0);
	ft_async_send(&a, sa, txbuf[0], la, 0);
	ft_async_send(&b, sb, txbuf[1], lb, 0);

	ok &= ft_dut_expect_pdu(ctx, sb, txbuf[0], la, 5000);
	ok &= ft_dut_expect_pdu(ctx, sa, txbuf[1], lb, 5000);

	if (ft_async_join(ctx, &a, 3000))
		ok &= FT_CHECK(ctx, a.ret == (ssize_t)la, "send() A %zd", a.ret);
	if (ft_async_join(ctx, &b, 3000))
		ok &= FT_CHECK(ctx, b.ret == (ssize_t)lb, "send() B %zd", b.ret);

	return ok;
}

/* ------------------------------------------------------------------------
 * point-to-point
 * ------------------------------------------------------------------------
 */

struct p2p_param {
	const char *mode_a;
	const char *mode_b;	/* NULL => same as A */
	int var;
	bool fcparm;		/* BS 3 / STmin 0xF1 for both directions */
	bool hd;		/* half duplex */
};

static void e2e_p2p(struct ft_ctx *ctx, const void *param)
{
	const struct p2p_param *pp = param;
	struct ft_isotp_cfg ca, cb;
	struct ft_enc ea, eb;
	unsigned int lens[32];
	int sa, sb, i, n;

	ft_cfg_init(&ca);
	ft_cfg_mode(&ca, ft_mode_by_name(pp->mode_a));
	ft_cfg_variant(&ca, pp->var);
	ca.opts.flags |= CAN_ISOTP_WAIT_TX_DONE;
	if (pp->hd)
		ca.opts.flags |= CAN_ISOTP_HALF_DUPLEX;
	if (pp->fcparm) {
		ca.fc.bs = 3;
		ca.fc.stmin = 0xF1;
	}

	cb = ca;
	if (pp->mode_b)
		ft_cfg_mode(&cb, ft_mode_by_name(pp->mode_b));
	ft_cfg_swap(&cb);

	sa = ft_isotp_open(ctx, &ca);
	FT_BAIL(ctx);
	sb = ft_isotp_open(ctx, &cb);
	if (sb < 0) {
		close(sa);
		return;
	}

	ft_enc_dut(&ca, &ea);
	ft_enc_dut(&cb, &eb);

	n = ft_seg_lengths(&ea, FT_MAX_PDU, lens, 32);
	for (i = 0; i < n; i++)
		if (!e2e_xfer(ctx, sa, &sb, 1, NULL, lens[i], i))
			goto out;

	n = ft_seg_lengths(&eb, FT_MAX_PDU, lens, 32);
	for (i = 0; i < n; i++)
		if (!e2e_xfer(ctx, sb, &sa, 1, NULL, lens[i], i + 0x40))
			goto out;

	/* full duplex: both sockets send at the same time */
	if (!pp->hd) {
		e2e_duplex(ctx, sa, sb, FT_MAX_PDU, 4000);
		e2e_duplex(ctx, sa, sb, 3, 5);
		e2e_duplex(ctx, sa, sb, 100, 1);
	}
out:
	close(sa);
	close(sb);
}

/* ------------------------------------------------------------------------
 * 1-to-n communication
 * ------------------------------------------------------------------------
 */

struct mc_param {
	const char *mode;
	uint32_t flag;
};

static void e2e_mc(struct ft_ctx *ctx, const void *param)
{
	const struct mc_param *mp = param;
	struct ft_isotp_cfg ca, cl, cn;
	unsigned int lens[] = { 1, 7, 8, 63, 100, 4095, 4096, FT_MAX_PDU };
	int s[MAXS], sa;
	bool rx_ok[MAXS];
	unsigned int i;
	int k;

	for (k = 0; k < MAXS; k++)
		s[k] = -1;

	ft_cfg_init(&ca);
	ft_cfg_mode(&ca, ft_mode_by_name(mp->mode));
	ca.opts.flags |= CAN_ISOTP_WAIT_TX_DONE | mp->flag;

	/* receivers: 2 in listen mode, 1 normal (+ BS 2) */
	cl = ca;
	ft_cfg_swap(&cl);
	cl.opts.flags &= ~(CAN_ISOTP_SF_BROADCAST | CAN_ISOTP_CF_BROADCAST |
			   CAN_ISOTP_MF_BROADCAST);
	cn = cl;
	cn.fc.bs = 2;
	cl.opts.flags |= CAN_ISOTP_LISTEN_MODE;

	sa = ft_isotp_open(ctx, &ca);
	FT_BAIL(ctx);
	s[0] = ft_isotp_open(ctx, &cl);
	s[1] = ft_isotp_open(ctx, &cl);
	s[2] = ft_isotp_open(ctx, &cn);
	if (ctx->failed)
		goto out;

	rx_ok[0] = true;
	rx_ok[1] = true;
	rx_ok[2] = true;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		struct ft_enc e;

		ft_enc_dut(&ca, &e);
		if (mp->flag == CAN_ISOTP_SF_BROADCAST &&
		    lens[i] > ft_enc_sf_max(&e))
			continue;
		/* the normal receiver ignores MF frames */
		rx_ok[2] = !(mp->flag == CAN_ISOTP_MF_BROADCAST &&
			     lens[i] > ft_enc_sf_max(&e));
		if (!e2e_xfer(ctx, sa, s, 3, rx_ok, lens[i], i))
			break;
	}
out:
	close(sa);
	for (k = 0; k < MAXS; k++)
		if (s[k] >= 0)
			close(s[k]);
}

static void e2e_sniff(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg ca, cb, cla, clb;
	unsigned int lens[] = { 1, 7, 8, 30, 100, 4096 };
	int sa, sb, sla, slb;
	bool rx_ok[2] = { true, true };
	int sy[2];
	unsigned int i;

	ft_cfg_init(&ca);
	ft_cfg_mode(&ca, ft_mode_by_name(param));
	ca.opts.flags |= CAN_ISOTP_WAIT_TX_DONE;
	ca.fc.bs = 2;
	cb = ca;
	ft_cfg_swap(&cb);

	/* sniffers in listen mode for both directions */
	clb = cb;
	clb.opts.flags |= CAN_ISOTP_LISTEN_MODE;
	cla = ca;
	cla.opts.flags |= CAN_ISOTP_LISTEN_MODE;

	sa = ft_isotp_open(ctx, &ca);
	FT_BAIL(ctx);
	sb = ft_isotp_open(ctx, &cb);
	sla = ft_isotp_open(ctx, &cla);
	slb = ft_isotp_open(ctx, &clb);
	if (ctx->failed)
		goto out;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		/* A -> B, sniffed by the listener with the B settings */
		sy[0] = sb;
		sy[1] = slb;
		if (!e2e_xfer(ctx, sa, sy, 2, rx_ok, lens[i], i))
			break;
		ft_dut_expect_nopdu(ctx, sla, 10);

		/* B -> A, sniffed by the listener with the A settings */
		sy[0] = sa;
		sy[1] = sla;
		if (!e2e_xfer(ctx, sb, sy, 2, rx_ok, lens[i], i + 7))
			break;
		ft_dut_expect_nopdu(ctx, slb, 10);
	}
out:
	if (sa >= 0)
		close(sa);
	if (sb >= 0)
		close(sb);
	if (sla >= 0)
		close(sla);
	if (slb >= 0)
		close(slb);
}

/* ------------------------------------------------------------------------
 * test table
 * ------------------------------------------------------------------------
 */

#define T(i, t, fl, f, p, rq, rf, is)					\
	{ .id = i, .title = t, .req = rq, .ref = rf, .iso = is,		\
	  .flags = fl, .fn = f, .param = p }

static const char p2p_req[] =
	"Two CAN_ISOTP sockets with swapped CAN IDs (and swapped address extensions/padding content) exchange PDUs of all relevant lengths in both directions and in full duplex (simultaneous transfers) without errors.";

static const char p2p_ref[] =
	"protocoltx.c, protocolrx.c, hrtimer.c";

#define P2P(m, v)							\
	T("E2E-" m "-" #v, "end-to-end " m " " #v, 0, e2e_p2p,		\
	  &((const struct p2p_param){ m, NULL, FT_V_##v, false, false }), \
	  p2p_req, p2p_ref, NULL)

#define P2PFC(m)							\
	T("E2E-" m "-FCPARM", "end-to-end " m " BS 3 STmin 100us", 0,	\
	  e2e_p2p,							\
	  &((const struct p2p_param){ m, NULL, FT_V_PLAIN, true, false }), \
	  "Like the end-to-end test with BS 3 and STmin 0xF1 (100 us) in the FC frames of both sockets.", \
	  p2p_ref, NULL)

#define P2PMIX(a, b)							\
	T("E2E-MIX-" a "-" b, "end-to-end " a " <-> " b, 0, e2e_p2p,	\
	  &((const struct p2p_param){ a, b, FT_V_PLAIN, false, false }), \
	  "Two sockets with different TX_DL settings communicate: the receiver accepts the sender LL_DL (taken from the FF).", \
	  p2p_ref, NULL)

static const struct ft_test tests[] = {
	P2P("CC8", PLAIN), P2P("CC8", AE), P2P("CC8", PAD), P2P("CC8", AEPAD),
	P2PFC("CC8"),
	P2P("FD8", PLAIN), P2P("FD8", PAD),
	P2P("FD24", PLAIN), P2P("FD24", AEPAD),
	P2P("FD64", PLAIN), P2P("FD64", AE), P2P("FD64", PAD), P2P("FD64", AEPAD),
	P2PFC("FD64"),
	P2P("FD64BRS", PLAIN),
	P2P("XL9-8", PLAIN),
	P2P("XL9-12", PLAIN),
	P2P("XL9-64", PLAIN), P2P("XL9-64", AE),
	P2P("XL9FD-12", PAD), P2P("XL9FD-64", AEPAD),
	P2P("XL9-65", AE),
	P2P("XL9-255", PLAIN),
	P2P("XL9-2048", PLAIN), P2P("XL9-2048", AE),
	P2PFC("XL9-2048"),
	P2P("XL9-2048-SEC-VCID", PLAIN),
	P2P("XL9-100-RRS", AE),
	P2P("XL9-512-IF512", PLAIN),
	P2P("XL9-256-IF256", PLAIN),
	P2P("XL6-8", PLAIN), P2P("XL6-8", PAD),
	P2P("XL7-64", PLAIN), P2P("XL7-64BRS", AEPAD),
	P2PMIX("FD64", "FD8"),
	P2PMIX("FD12", "FD48"),
	P2PMIX("XL9-2048", "XL9-64"),
	P2PMIX("XL9-9", "XL9-1000"),
	P2PMIX("XL7-64", "XL7-8"),

	T("E2E-HD-001", "end-to-end half duplex", 0, e2e_p2p,
	  &((const struct p2p_param){ "CC8", NULL, FT_V_PLAIN, true, true }),
	  "Two sockets with CAN_ISOTP_HALF_DUPLEX exchange PDUs in both directions (sequentially).",
	  "protocolrx.c:isotp_rcv() CAN_ISOTP_HALF_DUPLEX", NULL),

	T("E2E-MC-CF-CC8", "CF broadcast to n receivers CC8", 0, e2e_mc,
	  &((const struct mc_param){ "CC8", CAN_ISOTP_CF_BROADCAST }),
	  "A CF broadcast sender transmits to two listen mode receivers and one normal receiver (whose FCs are ignored by the sender); all receive the PDUs.",
	  "protocoltx.c:isotp_sendmsg() CF broadcast", NULL),
	T("E2E-MC-CF-FD64", "CF broadcast to n receivers FD64", 0, e2e_mc,
	  &((const struct mc_param){ "FD64", CAN_ISOTP_CF_BROADCAST }),
	  "A CF broadcast sender transmits to two listen mode receivers and one normal receiver (whose FCs are ignored by the sender); all receive the PDUs.",
	  "protocoltx.c:isotp_sendmsg() CF broadcast", NULL),
	T("E2E-MC-CF-XL9-2048", "CF broadcast to n receivers XL", 0, e2e_mc,
	  &((const struct mc_param){ "XL9-2048", CAN_ISOTP_CF_BROADCAST }),
	  "A CF broadcast sender transmits to two listen mode receivers and one normal receiver (whose FCs are ignored by the sender); all receive the PDUs.",
	  "protocoltx.c:isotp_sendmsg() CF broadcast", NULL),
	T("E2E-MC-MF-CC8", "MF multicast to n receivers CC8", 0, e2e_mc,
	  &((const struct mc_param){ "CC8", CAN_ISOTP_MF_BROADCAST }),
	  "A MF multicast sender transmits to two listen mode receivers which receive the segmented PDUs; a normal receiver only receives SF PDUs and ignores MF started transfers.",
	  "protocoltx.c:isotp_ff_pci() N_PCI_MF, protocolrx.c:isotp_rcv()", NULL),
	T("E2E-MC-MF-FD64", "MF multicast to n receivers FD64", 0, e2e_mc,
	  &((const struct mc_param){ "FD64", CAN_ISOTP_MF_BROADCAST }),
	  "A MF multicast sender transmits to two listen mode receivers which receive the segmented PDUs; a normal receiver only receives SF PDUs and ignores MF started transfers.",
	  "protocoltx.c:isotp_ff_pci() N_PCI_MF, protocolrx.c:isotp_rcv()", NULL),
	T("E2E-MC-MF-XL9-2048", "MF multicast to n receivers XL", 0, e2e_mc,
	  &((const struct mc_param){ "XL9-2048", CAN_ISOTP_MF_BROADCAST }),
	  "A MF multicast sender transmits to two listen mode receivers which receive the segmented PDUs; a normal receiver only receives SF PDUs and ignores MF started transfers.",
	  "protocoltx.c:isotp_ff_pci() N_PCI_MF, protocolrx.c:isotp_rcv()", NULL),
	T("E2E-MC-SF-CC8", "SF broadcast to n receivers CC8", 0, e2e_mc,
	  &((const struct mc_param){ "CC8", CAN_ISOTP_SF_BROADCAST }),
	  "A SF broadcast sender (functional addressing) transmits SF PDUs to normal and listen mode receivers.",
	  "protocoltx.c:isotp_sendmsg() SF broadcast", NULL),
	T("E2E-MC-SF-FD64", "SF broadcast to n receivers FD64", 0, e2e_mc,
	  &((const struct mc_param){ "FD64", CAN_ISOTP_SF_BROADCAST }),
	  "A SF broadcast sender (functional addressing) transmits SF PDUs to normal and listen mode receivers.",
	  "protocoltx.c:isotp_sendmsg() SF broadcast", NULL),
	T("E2E-SNIFF-CC8", "listen mode sniffer CC8", 0, e2e_sniff, "CC8",
	  "Listen mode sockets with the receiver settings receive the PDUs of an ongoing point-to-point communication (BS 2) without disturbing it.",
	  "protocolrx.c CAN_ISOTP_LISTEN_MODE", NULL),
	T("E2E-SNIFF-FD64", "listen mode sniffer FD64", 0, e2e_sniff, "FD64",
	  "Listen mode sockets with the receiver settings receive the PDUs of an ongoing point-to-point communication (BS 2) without disturbing it.",
	  "protocolrx.c CAN_ISOTP_LISTEN_MODE", NULL),
	T("E2E-SNIFF-XL9-2048", "listen mode sniffer XL", 0, e2e_sniff,
	  "XL9-2048",
	  "Listen mode sockets with the receiver settings receive the PDUs of an ongoing point-to-point communication (BS 2) without disturbing it.",
	  "protocolrx.c CAN_ISOTP_LISTEN_MODE", NULL),
};

int main(int argc, char **argv)
{
	return ft_main(argc, argv, "e2e", tests,
		       sizeof(tests) / sizeof(tests[0]));
}
