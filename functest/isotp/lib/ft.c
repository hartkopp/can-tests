// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * ft.c - functional test framework for the CAN_ISOTP protocol
 *
 * Send feedback to <linux-can@vger.kernel.org>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fnmatch.h>
#include <stddef.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <linux/can.h>
#include <linux/can/bcm.h>
#include <linux/can/isotp.h>
#include <linux/can/raw.h>

#include "ft.h"

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

#define FT_FRAME_LOG_LIMIT 400	/* max. logged frames per test case */

struct ft_config ft_cfg = {
	.ifname = {
		[FT_IF_CC] = "vcaniso0",
		[FT_IF_FD] = "vcaniso1",
		[FT_IF_XL] = "vcaniso2",
		[FT_IF_XL512] = "vcaniso3",
		[FT_IF_XL256] = "vcaniso4",
		[FT_IF_DOWN] = "vcaniso5",
	},
	.verbose = 0,
	.quick = 0,
	.tol_ms = 20,
	.watchdog_s = 120,
};

static const char *ft_if_env[FT_IF_MAX] = {
	[FT_IF_CC] = "FT_IF_CC",
	[FT_IF_FD] = "FT_IF_FD",
	[FT_IF_XL] = "FT_IF_XL",
	[FT_IF_XL512] = "FT_IF_XL512",
	[FT_IF_XL256] = "FT_IF_XL256",
	[FT_IF_DOWN] = "FT_IF_DOWN",
};

static int ft_frame_logs; /* logged frames in current test case */

/* ------------------------------------------------------------------------
 * logging and results
 * ------------------------------------------------------------------------
 */

static void ft_vlog(struct ft_ctx *ctx, const char *pfx, const char *fmt,
		    va_list ap)
{
	if (!ctx || !ctx->log)
		return;

	fprintf(ctx->log, "# %s", pfx);
	vfprintf(ctx->log, fmt, ap);
	fputc('\n', ctx->log);
	fflush(ctx->log);
}

void ft_log(struct ft_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ft_vlog(ctx, "  ", fmt, ap);
	va_end(ap);
}

void ft_fail_at(struct ft_ctx *ctx, const char *file, int line,
		const char *fmt, ...)
{
	va_list ap;
	char pfx[128];
	const char *f = strrchr(file, '/');

	snprintf(pfx, sizeof(pfx), "FAIL (%s:%d): ", f ? f + 1 : file, line);
	va_start(ap, fmt);
	ft_vlog(ctx, pfx, fmt, ap);
	va_end(ap);
	ctx->failed++;
}

void ft_skip(struct ft_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ft_vlog(ctx, "SKIP: ", fmt, ap);
	va_end(ap);
	ctx->skipped++;
}

void ft_note_dev(struct ft_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ft_vlog(ctx, "DEVIATION: ", fmt, ap);
	va_end(ap);
	ctx->ndev++;
}

static void ft_log_frame(struct ft_ctx *ctx, const char *pfx,
			 const struct ft_frame *f, bool force)
{
	char buf[CANXL_MAX_DLEN * 3 + 128];

	if (!force && ft_cfg.verbose < 2 &&
	    ++ft_frame_logs > FT_FRAME_LOG_LIMIT) {
		if (ft_frame_logs == FT_FRAME_LOG_LIMIT + 1)
			ft_log(ctx, "(frame trace limit reached)");
		return;
	}

	ft_frame_str(f, buf, sizeof(buf));
	ft_log(ctx, "%s %s", pfx, buf);
}

const char *ft_errname(int err)
{
	static char buf[32];

	if (err < 0)
		err = -err;

	switch (err) {
	case 0: return "OK";
	case EINVAL: return "EINVAL";
	case ENOPROTOOPT: return "ENOPROTOOPT";
	case EISCONN: return "EISCONN";
	case EAGAIN: return "EAGAIN";
	case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
	case ENODEV: return "ENODEV";
	case ENXIO: return "ENXIO";
	case ECOMM: return "ECOMM";
	case EMSGSIZE: return "EMSGSIZE";
	case EBADMSG: return "EBADMSG";
	case ETIMEDOUT: return "ETIMEDOUT";
	case EILSEQ: return "EILSEQ";
	case ENETDOWN: return "ENETDOWN";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case EFAULT: return "EFAULT";
	case EPROTOTYPE: return "EPROTOTYPE";
	case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
	case ENOTTY: return "ENOTTY";
	case ENOENT: return "ENOENT";
	case ETIME: return "ETIME(no event)";
	case EINTR: return "EINTR";
	case ENOBUFS: return "ENOBUFS";
	case EPERM: return "EPERM";
	case EDESTADDRREQ: return "EDESTADDRREQ";
	case ENOTCONN: return "ENOTCONN";
	case EAFNOSUPPORT: return "EAFNOSUPPORT";
	case EINPROGRESS: return "EINPROGRESS";
	case EIO: return "EIO";
	}
	snprintf(buf, sizeof(buf), "errno %d", err);
	return buf;
}

/* ------------------------------------------------------------------------
 * misc helpers
 * ------------------------------------------------------------------------
 */

const char *ft_ifname(enum ft_if i)
{
	return ft_cfg.ifname[i];
}

int ft_ifindex(enum ft_if i)
{
	return if_nametoindex(ft_cfg.ifname[i]);
}

bool ft_need_if(struct ft_ctx *ctx, enum ft_if i)
{
	if (ft_ifindex(i))
		return true;

	ft_skip(ctx, "interface %s not available (run setup_vcan.sh)",
		ft_ifname(i));
	return false;
}

int64_t ft_ts_ns(const struct timespec *ts)
{
	return (int64_t)ts->tv_sec * 1000000000LL + ts->tv_nsec;
}

int64_t ft_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ft_ts_ns(&ts);
}

void ft_sleep_us(int us)
{
	struct timespec ts = {
		.tv_sec = us / 1000000,
		.tv_nsec = (us % 1000000) * 1000L,
	};

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

void ft_sleep_ms(int ms)
{
	ft_sleep_us(ms * 1000);
}

unsigned int ft_max_pdu(void)
{
	FILE *f = fopen("/sys/module/can_isotp/parameters/max_pdu_size", "r");
	unsigned int val = FT_MAX_PDU;

	if (f) {
		if (fscanf(f, "%u", &val) != 1 || val < FT_MAX_PDU)
			val = FT_MAX_PDU;
		fclose(f);
	}

	return val;
}

void ft_pattern(uint8_t *buf, size_t len, unsigned int seed)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)(seed + i + 3 * (i >> 8));
}

/* ------------------------------------------------------------------------
 * frames
 * ------------------------------------------------------------------------
 */

void ft_frame_str(const struct ft_frame *f, char *buf, size_t size)
{
	size_t n = 0;
	unsigned int i;
	unsigned int max = f->len;

	if (max > CANXL_MAX_DLEN)
		max = CANXL_MAX_DLEN;

	switch (f->type) {
	case FT_CC:
		n = snprintf(buf, size, "CC %03X [%u] ", f->id, f->len);
		if (f->id & CAN_EFF_FLAG)
			n = snprintf(buf, size, "CC %08X [%u] ",
				     f->id & CAN_EFF_MASK, f->len);
		if (f->id & CAN_RTR_FLAG)
			n += snprintf(buf + n, size - n, "RTR ");
		/* show bytes beyond len up to 8 for CAN_DL < 8 tests */
		if (max > CAN_MAX_DLEN)
			max = CAN_MAX_DLEN;
		break;
	case FT_FD:
		n = snprintf(buf, size, "FD %03X [%02u] fl %02X ",
			     f->id & CAN_EFF_MASK, f->len, f->flags);
		if (f->id & CAN_EFF_FLAG)
			n = snprintf(buf, size, "FD %08X [%02u] fl %02X ",
				     f->id & CAN_EFF_MASK, f->len, f->flags);
		if (max > CANFD_MAX_DLEN)
			max = CANFD_MAX_DLEN;
		break;
	case FT_XL:
		n = snprintf(buf, size,
			     "XL %03X vcid %02X fl %02X sdt %02X af %08X [%u] ",
			     f->id & CANXL_PRIO_MASK,
			     (f->id >> CANXL_VCID_OFFSET) & 0xFF,
			     f->flags, f->sdt, f->af, f->len);
		break;
	}

	for (i = 0; i < max && n + 4 < size; i++) {
		if (i >= 64 && i < max - 8) {
			n += snprintf(buf + n, size - n, ".. ");
			i = max - 9;
			continue;
		}
		n += snprintf(buf + n, size - n, "%02X ", f->data[i]);
	}
}

bool ft_frame_eq(const struct ft_frame *a, const struct ft_frame *b)
{
	if (a->type != b->type || a->id != b->id || a->len != b->len)
		return false;

	if (a->type != FT_CC && a->flags != b->flags)
		return false;

	if (a->type == FT_XL && (a->sdt != b->sdt || a->af != b->af))
		return false;

	return !memcmp(a->data, b->data, a->len);
}

void ft_frame_set(struct ft_frame *f, const struct ft_frame *hdr,
		  const uint8_t *data, unsigned int len)
{
	f->type = hdr->type;
	f->id = hdr->id;
	f->flags = hdr->flags;
	f->sdt = hdr->sdt;
	f->af = hdr->af;
	f->ts = 0;
	f->len = len;
	/* data may point into f->data */
	if (data && len)
		memmove(f->data, data, len);
	else
		len = 0;
	memset(f->data + len, 0, sizeof(f->data) - len);
}

void ft_frame_bytes(struct ft_frame *f, const struct ft_frame *hdr,
		    unsigned int len, ...)
{
	va_list ap;
	unsigned int i;

	ft_frame_set(f, hdr, NULL, len);
	va_start(ap, len);
	for (i = 0; i < len; i++)
		f->data[i] = (uint8_t)va_arg(ap, int);
	va_end(ap);
}

/* ------------------------------------------------------------------------
 * CAN_RAW peer
 * ------------------------------------------------------------------------
 */

static void ft_peer_store(struct ft_peer *p, const struct ft_frame *f)
{
	pthread_mutex_lock(&p->lock);
	if (p->nframes == p->size) {
		unsigned int nsize = p->size ? p->size * 2 : 1024;
		struct ft_frame *n = realloc(p->frames, nsize * sizeof(*n));

		if (!n) {
			pthread_mutex_unlock(&p->lock);
			return;
		}
		p->frames = n;
		p->size = nsize;
	}
	p->frames[p->nframes++] = *f;
	pthread_cond_broadcast(&p->cond);
	pthread_mutex_unlock(&p->lock);
}

static void *ft_peer_thread(void *arg)
{
	struct ft_peer *p = arg;
	static __thread uint8_t buf[CANXL_MTU];
	char ctrl[CMSG_SPACE(sizeof(struct timespec)) +
		  CMSG_SPACE(sizeof(uint32_t)) + 64];
	struct ft_frame *f = malloc(sizeof(*f));

	if (!f)
		return NULL;

	while (!p->stop) {
		struct pollfd pfd = { .fd = p->s, .events = POLLIN };
		struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
		struct msghdr msg = {
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = ctrl,
			.msg_controllen = sizeof(ctrl),
		};
		struct cmsghdr *cmsg;
		ssize_t n;

		if (poll(&pfd, 1, 20) <= 0)
			continue;

		n = recvmsg(p->s, &msg, MSG_DONTWAIT);
		if (n <= 0)
			continue;

		memset(f, 0, offsetof(struct ft_frame, data));
		f->ts = ft_now_ns();

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET)
				continue;
			if (cmsg->cmsg_type == SO_TIMESTAMPNS) {
				struct timespec ts;

				memcpy(&ts, CMSG_DATA(cmsg), sizeof(ts));
				f->ts = ft_ts_ns(&ts);
			} else if (cmsg->cmsg_type == SO_RXQ_OVFL) {
				memcpy(&p->drops, CMSG_DATA(cmsg),
				       sizeof(p->drops));
			}
		}

		if (n == CAN_MTU) {
			struct can_frame *cf = (struct can_frame *)buf;

			f->type = FT_CC;
			f->id = cf->can_id;
			f->len = cf->len;
			memcpy(f->data, cf->data, CAN_MAX_DLEN);
		} else if (n == CANFD_MTU) {
			struct canfd_frame *cfd = (struct canfd_frame *)buf;

			f->type = FT_FD;
			f->id = cfd->can_id;
			f->flags = cfd->flags;
			f->len = cfd->len;
			memcpy(f->data, cfd->data, CANFD_MAX_DLEN);
		} else if (n >= (ssize_t)CANXL_HDR_SIZE + CANXL_MIN_DLEN) {
			struct canxl_frame *cxl = (struct canxl_frame *)buf;

			f->type = FT_XL;
			f->id = cxl->prio;
			f->flags = cxl->flags;
			f->sdt = cxl->sdt;
			f->af = cxl->af;
			f->len = cxl->len;
			if (f->len > CANXL_MAX_DLEN)
				f->len = CANXL_MAX_DLEN;
			memcpy(f->data, cxl->data, f->len);
		} else {
			continue;
		}

		ft_peer_store(p, f);
	}

	free(f);
	return NULL;
}

int ft_peer_open(struct ft_ctx *ctx, struct ft_peer *p, enum ft_if i)
{
	struct sockaddr_can addr = { .can_family = AF_CAN };
	struct can_raw_vcid_options vcid = {
		.flags = CAN_RAW_XL_VCID_TX_PASS | CAN_RAW_XL_VCID_RX_FILTER,
		.rx_vcid = 0,
		.rx_vcid_mask = 0, /* accept all VCIDs */
	};
	int on = 1;
	int rcvbuf = 8 * 1024 * 1024;

	memset(p, 0, sizeof(*p));
	p->s = -1;
	p->ctx = ctx;

	if (!ft_need_if(ctx, i))
		return -1;

	p->ifname = ft_ifname(i);
	p->ifindex = ft_ifindex(i);

	p->s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (p->s < 0) {
		ft_fail(ctx, "CAN_RAW socket: %s", ft_errname(errno));
		return -1;
	}

	if (setsockopt(p->s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &on, sizeof(on)))
		ft_log(ctx, "peer: CAN_RAW_FD_FRAMES: %s", ft_errname(errno));
	if (setsockopt(p->s, SOL_CAN_RAW, CAN_RAW_XL_FRAMES, &on, sizeof(on)))
		ft_log(ctx, "peer: CAN_RAW_XL_FRAMES: %s", ft_errname(errno));
	if (setsockopt(p->s, SOL_CAN_RAW, CAN_RAW_XL_VCID_OPTS, &vcid,
		       sizeof(vcid)))
		ft_log(ctx, "peer: CAN_RAW_XL_VCID_OPTS: %s", ft_errname(errno));
	setsockopt(p->s, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on));
	setsockopt(p->s, SOL_SOCKET, SO_RXQ_OVFL, &on, sizeof(on));
	if (setsockopt(p->s, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf,
		       sizeof(rcvbuf)))
		setsockopt(p->s, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
			   sizeof(rcvbuf));

	addr.can_ifindex = p->ifindex;
	if (bind(p->s, (struct sockaddr *)&addr, sizeof(addr))) {
		ft_fail(ctx, "CAN_RAW bind %s: %s", p->ifname,
			ft_errname(errno));
		close(p->s);
		p->s = -1;
		return -1;
	}

	pthread_mutex_init(&p->lock, NULL);
	pthread_cond_init(&p->cond, NULL);
	if (pthread_create(&p->thread, NULL, ft_peer_thread, p)) {
		ft_fail(ctx, "pthread_create failed");
		close(p->s);
		p->s = -1;
		return -1;
	}

	return 0;
}

void ft_peer_close(struct ft_peer *p)
{
	if (p->s < 0)
		return;

	p->stop = 1;
	pthread_join(p->thread, NULL);
	close(p->s);
	p->s = -1;
	free(p->frames);
	p->frames = NULL;
	pthread_mutex_destroy(&p->lock);
	pthread_cond_destroy(&p->cond);
}

int ft_peer_send(struct ft_ctx *ctx, struct ft_peer *p, const struct ft_frame *f)
{
	static uint8_t buf[CANXL_MTU];
	size_t size;
	ssize_t n;

	memset(buf, 0, sizeof(buf));

	switch (f->type) {
	case FT_CC: {
		struct can_frame *cf = (struct can_frame *)buf;

		cf->can_id = f->id;
		cf->len = f->len;
		/* copy all 8 bytes: tests may use data beyond CAN_DL */
		memcpy(cf->data, f->data, CAN_MAX_DLEN);
		size = CAN_MTU;
		break;
	}
	case FT_FD: {
		struct canfd_frame *cfd = (struct canfd_frame *)buf;

		cfd->can_id = f->id;
		cfd->flags = f->flags;
		cfd->len = f->len;
		memcpy(cfd->data, f->data, CANFD_MAX_DLEN);
		size = CANFD_MTU;
		break;
	}
	default: {
		struct canxl_frame *cxl = (struct canxl_frame *)buf;

		cxl->prio = f->id;
		cxl->flags = f->flags;
		cxl->sdt = f->sdt;
		cxl->len = f->len;
		cxl->af = f->af;
		memcpy(cxl->data, f->data, f->len);
		size = CANXL_HDR_SIZE + f->len;
		break;
	}
	}

	ft_log_frame(ctx, "peer TX", f, false);

	n = write(p->s, buf, size);
	if (n < 0)
		return -errno;
	if ((size_t)n != size)
		return -EIO;

	return 0;
}

bool ft_peer_tx(struct ft_ctx *ctx, struct ft_peer *p, const struct ft_frame *f)
{
	int ret = ft_peer_send(ctx, p, f);

	return FT_CHECK(ctx, !ret, "peer write failed: %s", ft_errname(ret));
}

bool ft_peer_next(struct ft_ctx *ctx, struct ft_peer *p, struct ft_frame *f,
		  int timeout_ms)
{
	struct timespec abs;
	bool ret = false;

	clock_gettime(CLOCK_REALTIME, &abs);
	abs.tv_sec += timeout_ms / 1000;
	abs.tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (abs.tv_nsec >= 1000000000L) {
		abs.tv_sec++;
		abs.tv_nsec -= 1000000000L;
	}

	pthread_mutex_lock(&p->lock);
	while (p->rd >= p->nframes) {
		if (pthread_cond_timedwait(&p->cond, &p->lock, &abs) ==
		    ETIMEDOUT)
			break;
	}
	if (p->rd < p->nframes) {
		*f = p->frames[p->rd++];
		ret = true;
	}
	pthread_mutex_unlock(&p->lock);

	if (ret)
		ft_log_frame(ctx, "peer RX", f, false);

	return ret;
}

void ft_peer_flush(struct ft_peer *p)
{
	pthread_mutex_lock(&p->lock);
	p->rd = p->nframes;
	pthread_mutex_unlock(&p->lock);
}

bool ft_peer_expect(struct ft_ctx *ctx, struct ft_peer *p,
		    const struct ft_frame *exp, int timeout_ms)
{
	struct ft_frame *f = malloc(sizeof(*f));
	bool ret;

	if (!f) {
		ft_fail(ctx, "out of memory");
		return false;
	}

	if (!ft_peer_next(ctx, p, f, timeout_ms)) {
		ft_log_frame(ctx, "expected", exp, true);
		ft_fail(ctx, "no frame received within %d ms", timeout_ms);
		free(f);
		return false;
	}

	ret = ft_frame_eq(exp, f);
	if (!ret) {
		ft_log_frame(ctx, "expected", exp, true);
		ft_log_frame(ctx, "received", f, true);
		ft_fail(ctx, "frame mismatch");
	}

	free(f);
	return ret;
}

bool ft_peer_expect_none(struct ft_ctx *ctx, struct ft_peer *p, int ms)
{
	struct ft_frame *f = malloc(sizeof(*f));
	bool ret = true;

	if (!f) {
		ft_fail(ctx, "out of memory");
		return false;
	}

	if (ft_peer_next(ctx, p, f, ms)) {
		ft_log_frame(ctx, "unexpected", f, true);
		ft_fail(ctx, "unexpected frame received");
		ret = false;
	}

	free(f);
	return ret;
}

bool ft_peer_check_drops(struct ft_ctx *ctx, struct ft_peer *p)
{
	return FT_CHECK(ctx, p->drops == 0,
			"peer receive queue overflow (%u drops) - system too slow?",
			p->drops);
}

/* ------------------------------------------------------------------------
 * CAN_BCM sequence sender
 * ------------------------------------------------------------------------
 */

bool ft_bcm_send_seq(struct ft_ctx *ctx, enum ft_if i,
		     const struct ft_frame *frames, int n, int gap_us)
{
	struct sockaddr_can addr = { .can_family = AF_CAN };
	struct {
		struct bcm_msg_head h;
		struct canfd_frame f[256];
	} msg;
	struct can_frame *cf = (struct can_frame *)msg.f;
	bool fd = (frames[0].type == FT_FD);
	size_t fsize = fd ? sizeof(struct canfd_frame) : sizeof(struct can_frame);
	struct pollfd pfd;
	int s, k;
	bool ret = true;

	if (n < 1 || n > 256 || frames[0].type == FT_XL) {
		ft_fail(ctx, "ft_bcm_send_seq: unsupported parameters");
		return false;
	}

	s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM);
	if (s < 0) {
		ft_fail(ctx, "CAN_BCM socket: %s", ft_errname(errno));
		return false;
	}

	addr.can_ifindex = ft_ifindex(i);
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr))) {
		ft_fail(ctx, "CAN_BCM connect: %s", ft_errname(errno));
		close(s);
		return false;
	}

	memset(&msg, 0, sizeof(msg));
	msg.h.opcode = TX_SETUP;
	msg.h.flags = SETTIMER | STARTTIMER | TX_ANNOUNCE | TX_COUNTEVT;
	if (fd)
		msg.h.flags |= CAN_FD_FRAME;
	msg.h.count = n;
	msg.h.ival1.tv_sec = gap_us / 1000000;
	msg.h.ival1.tv_usec = gap_us % 1000000;
	msg.h.can_id = frames[0].id;
	msg.h.nframes = n;

	for (k = 0; k < n; k++) {
		if (fd) {
			msg.f[k].can_id = frames[k].id;
			msg.f[k].flags = frames[k].flags;
			msg.f[k].len = frames[k].len;
			memcpy(msg.f[k].data, frames[k].data, CANFD_MAX_DLEN);
		} else {
			cf[k].can_id = frames[k].id;
			cf[k].len = frames[k].len;
			memcpy(cf[k].data, frames[k].data, CAN_MAX_DLEN);
		}
		ft_log_frame(ctx, "bcm TX", &frames[k], false);
	}

	if (write(s, &msg, sizeof(msg.h) + n * fsize) < 0) {
		ft_fail(ctx, "CAN_BCM TX_SETUP: %s", ft_errname(errno));
		close(s);
		return false;
	}

	/* the last frame is sent by the timer which also creates the
	 * TX_EXPIRED notification (not for n == 1 with TX_ANNOUNCE)
	 */
	if (n > 1) {
		pfd.fd = s;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, (n * gap_us) / 1000 + 2000) == 1) {
			struct bcm_msg_head rh;

			if (read(s, &rh, sizeof(rh)) < 0 ||
			    rh.opcode != TX_EXPIRED)
				ret = FT_CHECK(ctx, false,
					       "CAN_BCM: no TX_EXPIRED");
		} else {
			ret = FT_CHECK(ctx, false, "CAN_BCM: sequence timeout");
		}
	}

	close(s);
	return ret;
}

/* ------------------------------------------------------------------------
 * link layer modes
 * ------------------------------------------------------------------------
 */

#define CC_MODE(n, i)						\
	{ .name = n, .iface = i, .mtu = CAN_MTU, .ll_tx_dl = 8 }
#define FD_MODE(n, dl, fl)					\
	{ .name = n, .iface = FT_IF_FD, .mtu = CANFD_MTU,	\
	  .ll_tx_dl = dl, .ll_tx_flags = fl }
#define XL_MODE(n, i, s, dl, fl, tv, rv)			\
	{ .name = n, .iface = i,				\
	  .mtu = ((s) == CAN_CIA_FD_TUNNEL_SDT) ? CANFD_MTU : CAN_MTU, \
	  .ll_tx_dl = ((s) == CAN_CIA_FD_TUNNEL_SDT) ? (dl) : 8, \
	  .xl = true, .sdt = s, .xl_tx_dl = dl,			\
	  .xl_flags = CANXL_XLF | (fl), .tx_vcid = tv, .rx_vcid = rv }
#define XL7_BRS_MODE(n, dl)					\
	{ .name = n, .iface = FT_IF_XL, .mtu = CANFD_MTU,	\
	  .ll_tx_dl = dl, .ll_tx_flags = CANFD_BRS,		\
	  .xl = true, .sdt = CAN_CIA_FD_TUNNEL_SDT, .xl_tx_dl = dl, \
	  .xl_flags = CANXL_XLF }

const struct ft_mode ft_modes[] = {
	CC_MODE("CC8", FT_IF_CC),
	FD_MODE("FD8", 8, 0),
	FD_MODE("FD12", 12, 0),
	FD_MODE("FD16", 16, 0),
	FD_MODE("FD20", 20, 0),
	FD_MODE("FD24", 24, 0),
	FD_MODE("FD32", 32, 0),
	FD_MODE("FD48", 48, 0),
	FD_MODE("FD64", 64, 0),
	FD_MODE("FD64BRS", 64, CANFD_BRS),
	XL_MODE("XL9-8", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 8, 0, 0, 0),
	XL_MODE("XL9-9", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 9, 0, 0, 0),
	XL_MODE("XL9-12", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 12, 0, 0, 0),
	XL_MODE("XL9-64", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 64, 0, 0, 0),
	XL_MODE("XL9-65", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 65, 0, 0, 0),
	XL_MODE("XL9-255", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 255, 0, 0, 0),
	XL_MODE("XL9-256", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 256, 0, 0, 0),
	XL_MODE("XL9-1000", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 1000, 0, 0, 0),
	XL_MODE("XL9-2048", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 2048, 0, 0, 0),
	XL_MODE("XL9-2048-SEC-VCID", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 2048,
		CANXL_SEC, 0x12, 0x34),
	XL_MODE("XL9-100-RRS", FT_IF_XL, CAN_CIA_ISO15765_2_SDT, 100,
		CANXL_RRS, 0, 0xAB),
	XL_MODE("XL9-512-IF512", FT_IF_XL512, CAN_CIA_ISO15765_2_SDT, 512,
		0, 0, 0),
	XL_MODE("XL9-256-IF256", FT_IF_XL256, CAN_CIA_ISO15765_2_SDT, 256,
		0, 0, 0),
	XL_MODE("XL6-8", FT_IF_XL, CAN_CIA_CC_TUNNEL_SDT, 8, 0, 0, 0),
	XL_MODE("XL7-8", FT_IF_XL, CAN_CIA_FD_TUNNEL_SDT, 8, 0, 0, 0),
	XL_MODE("XL7-12", FT_IF_XL, CAN_CIA_FD_TUNNEL_SDT, 12, 0, 0, 0),
	XL_MODE("XL7-64", FT_IF_XL, CAN_CIA_FD_TUNNEL_SDT, 64, 0, 0, 0),
	XL7_BRS_MODE("XL7-64BRS", 64),
};

const int ft_nmodes = sizeof(ft_modes) / sizeof(ft_modes[0]);

const struct ft_mode *ft_mode_by_name(const char *name)
{
	int i;

	for (i = 0; i < ft_nmodes; i++)
		if (!strcmp(ft_modes[i].name, name))
			return &ft_modes[i];

	fprintf(stderr, "unknown mode %s\n", name);
	abort();
}

/* ------------------------------------------------------------------------
 * CAN_ISOTP configuration
 * ------------------------------------------------------------------------
 */

void ft_cfg_init(struct ft_isotp_cfg *c)
{
	memset(c, 0, sizeof(*c));

	c->iface = FT_IF_CC;
	c->tx_id = FT_DUT_TX_ID;
	c->rx_id = FT_DUT_RX_ID;

	/* default values (frame_txtime 0 => keep the default 50 us) */
	c->opts.flags = CAN_ISOTP_DEFAULT_FLAGS;
	c->opts.frame_txtime = 0;
	c->opts.ext_address = CAN_ISOTP_DEFAULT_EXT_ADDRESS;
	c->opts.txpad_content = CAN_ISOTP_DEFAULT_PAD_CONTENT;
	c->opts.rxpad_content = CAN_ISOTP_DEFAULT_PAD_CONTENT;
	c->opts.rx_ext_address = CAN_ISOTP_DEFAULT_EXT_ADDRESS;
	c->set_opts = true;

	c->fc.bs = CAN_ISOTP_DEFAULT_RECV_BS;
	c->fc.stmin = CAN_ISOTP_DEFAULT_RECV_STMIN;
	c->fc.wftmax = CAN_ISOTP_DEFAULT_RECV_WFTMAX;
	c->set_fc = true;

	c->ll.mtu = CAN_MTU;
	c->ll.tx_dl = CAN_MAX_DLEN;
	c->ll.tx_flags = 0;
	c->set_ll = true;
}

void ft_cfg_mode(struct ft_isotp_cfg *c, const struct ft_mode *m)
{
	c->iface = m->iface;

	c->ll.mtu = m->mtu;
	c->ll.tx_dl = m->ll_tx_dl;
	c->ll.tx_flags = m->ll_tx_flags;
	c->set_ll = true;

	memset(&c->xl, 0, sizeof(c->xl));
	c->set_xl = m->xl;
	if (m->xl) {
		c->xl.tx_dl = m->xl_tx_dl;
		c->xl.tx_addr = FT_XL_TX_AF;
		c->xl.rx_addr = FT_XL_RX_AF;
		c->xl.tx_flags = m->xl_flags;
		c->xl.rx_flags = m->xl_flags;
		c->xl.tx_vcid = m->tx_vcid;
		c->xl.rx_vcid = m->rx_vcid;
		c->xl.sdt_mode = m->sdt;
	}
}

const char *ft_variant_name[FT_V_MAX] = {
	[FT_V_PLAIN] = "plain",
	[FT_V_AE] = "ae",
	[FT_V_PAD] = "pad",
	[FT_V_AEPAD] = "aepad",
};

void ft_cfg_variant(struct ft_isotp_cfg *c, int var)
{
	if (var == FT_V_AE || var == FT_V_AEPAD) {
		c->opts.flags |= CAN_ISOTP_EXTEND_ADDR;
		c->opts.ext_address = 0xA5;
		c->opts.rx_ext_address = 0xA5;
	}

	if (var == FT_V_AEPAD) {
		c->opts.flags |= CAN_ISOTP_RX_EXT_ADDR;
		c->opts.rx_ext_address = 0x5A;
	}

	if (var == FT_V_PAD || var == FT_V_AEPAD) {
		c->opts.flags |= CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING |
				 CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA;
		c->opts.txpad_content = 0x55;
		c->opts.rxpad_content = 0xAA;
	}
}

bool ft_variant_valid(const struct ft_mode *m, int var)
{
	unsigned int dl = m->xl ? m->xl_tx_dl : m->ll_tx_dl;

	if (var == FT_V_PAD || var == FT_V_AEPAD)
		return dl <= 64 && ft_padlen(dl) == dl;

	return true;
}

static void ft_add_len(unsigned int *out, int *n, int size, unsigned int len,
		       unsigned int max)
{
	int i, j;

	if (len < 1 || len > max || *n >= size)
		return;

	for (i = 0; i < *n; i++) {
		if (out[i] == len)
			return;
		if (out[i] > len)
			break;
	}

	for (j = *n; j > i; j--)
		out[j] = out[j - 1];
	out[i] = len;
	(*n)++;
}

int ft_seg_lengths(const struct ft_enc *e, unsigned int max,
		   unsigned int *out, int size)
{
	unsigned int sf = ft_enc_sf_max(e);
	unsigned int ae = e->ae ? 1 : 0;
	unsigned int ff = e->ll_dl - 2 - ae;	/* FF payload (12 bit FF_DL) */
	unsigned int cf = e->ll_dl - 1 - ae;	/* CF payload */
	int n = 0;

	ft_add_len(out, &n, size, 1, max);
	ft_add_len(out, &n, size, 2, max);
	/* 4 bit SF_DL boundary for TX_DL > 8 */
	ft_add_len(out, &n, size, CAN_MAX_DLEN - 1 - ae, max);
	ft_add_len(out, &n, size, CAN_MAX_DLEN - ae, max);
	ft_add_len(out, &n, size, sf - 1, max);
	ft_add_len(out, &n, size, sf, max);
	ft_add_len(out, &n, size, sf + 1, max);
	ft_add_len(out, &n, size, sf + 2, max);
	/* FF + one full CF, FF + one CF with one byte */
	ft_add_len(out, &n, size, ff + cf, max);
	ft_add_len(out, &n, size, ff + cf + 1, max);
	/* sequence number wrap around (> 16 CFs) */
	ft_add_len(out, &n, size, ff + 17 * cf + 3, max);
	ft_add_len(out, &n, size, FT_MAX_12BIT_PDU, max);
	ft_add_len(out, &n, size, FT_MAX_12BIT_PDU + 1, max);
	ft_add_len(out, &n, size, FT_MAX_PDU, max);

	return n;
}

bool ft_cfg_is_xl(const struct ft_isotp_cfg *c)
{
	return c->set_xl && (c->xl.tx_flags & CANXL_XLF);
}

bool ft_cfg_is_fdpdu(const struct ft_isotp_cfg *c)
{
	return c->set_ll && c->ll.mtu == CANFD_MTU;
}

unsigned int ft_cfg_tx_dl(const struct ft_isotp_cfg *c)
{
	/* ft_isotp_open() applies CAN_ISOTP_XL_OPTS after LL_OPTS */
	if (ft_cfg_is_xl(c))
		return c->xl.tx_dl;

	if (c->set_ll)
		return c->ll.tx_dl;

	return CAN_MAX_DLEN;
}

void ft_cfg_swap(struct ft_isotp_cfg *c)
{
	canid_t id = c->tx_id;
	uint8_t v;

	c->tx_id = c->rx_id;
	c->rx_id = id;

	id = c->xl.tx_addr;
	c->xl.tx_addr = c->xl.rx_addr;
	c->xl.rx_addr = id;

	v = c->xl.tx_vcid;
	c->xl.tx_vcid = c->xl.rx_vcid;
	c->xl.rx_vcid = v;

	if (c->opts.flags & CAN_ISOTP_RX_EXT_ADDR) {
		v = c->opts.ext_address;
		c->opts.ext_address = c->opts.rx_ext_address;
		c->opts.rx_ext_address = v;
	}

	v = c->opts.txpad_content;
	c->opts.txpad_content = c->opts.rxpad_content;
	c->opts.rxpad_content = v;
}

int ft_isotp_open_err(const struct ft_isotp_cfg *c)
{
	struct sockaddr_can addr = { .can_family = AF_CAN };
	int s, err;

	s = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
	if (s < 0)
		return -errno;

	if (c->set_opts &&
	    setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &c->opts,
		       sizeof(c->opts)))
		goto err;

	if (c->set_fc &&
	    setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_RECV_FC, &c->fc,
		       sizeof(c->fc)))
		goto err;

	if (c->set_tx_stmin &&
	    setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_TX_STMIN, &c->tx_stmin,
		       sizeof(c->tx_stmin)))
		goto err;

	if (c->set_rx_stmin &&
	    setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_RX_STMIN, &c->rx_stmin,
		       sizeof(c->rx_stmin)))
		goto err;

	if (c->set_ll &&
	    setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS, &c->ll,
		       sizeof(c->ll)))
		goto err;

	if (c->set_xl &&
	    setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS, &c->xl,
		       sizeof(c->xl)))
		goto err;

	addr.can_ifindex = ft_ifindex(c->iface);
	addr.can_addr.tp.tx_id = c->tx_id;
	addr.can_addr.tp.rx_id = c->rx_id;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)))
		goto err;

	return s;

err:
	err = -errno;
	close(s);
	return err;
}

int ft_isotp_open(struct ft_ctx *ctx, const struct ft_isotp_cfg *c)
{
	int s;

	if (!ft_need_if(ctx, c->iface))
		return -1;

	s = ft_isotp_open_err(c);
	if (s < 0) {
		ft_fail(ctx, "CAN_ISOTP socket setup on %s (tx %X rx %X) failed: %s",
			ft_ifname(c->iface), c->tx_id, c->rx_id, ft_errname(s));
		return -1;
	}

	return s;
}

static uint32_t ft_af_conv(canid_t addr)
{
	/* move the EFF flag to the CiA 611-1 AF position */
	if (addr & CAN_EFF_FLAG)
		addr ^= (CAN_EFF_FLAG | FT_AF_SDT_EFF);

	return addr;
}

void ft_hdr_dut_tx(const struct ft_isotp_cfg *c, struct ft_frame *h)
{
	memset(h, 0, offsetof(struct ft_frame, data));

	if (ft_cfg_is_xl(c)) {
		h->type = FT_XL;
		h->id = c->tx_id | ((canid_t)c->xl.tx_vcid << CANXL_VCID_OFFSET);
		h->flags = c->xl.tx_flags;
		h->sdt = c->xl.sdt_mode;
		h->af = ft_af_conv(c->xl.tx_addr);
		if (c->xl.sdt_mode == CAN_CIA_FD_TUNNEL_SDT &&
		    (c->ll.tx_flags & CANFD_BRS))
			h->af |= FT_AF_SDT7_BRS;
	} else if (ft_cfg_is_fdpdu(c)) {
		h->type = FT_FD;
		h->id = c->tx_id;
		h->flags = c->ll.tx_flags | CANFD_FDF;
	} else {
		h->type = FT_CC;
		h->id = c->tx_id;
	}
}

void ft_hdr_dut_rx(const struct ft_isotp_cfg *c, struct ft_frame *h)
{
	memset(h, 0, offsetof(struct ft_frame, data));

	if (ft_cfg_is_xl(c)) {
		h->type = FT_XL;
		h->id = c->rx_id | ((canid_t)c->xl.rx_vcid << CANXL_VCID_OFFSET);
		h->flags = c->xl.rx_flags;
		h->sdt = c->xl.sdt_mode;
		h->af = ft_af_conv(c->xl.rx_addr);
	} else if (ft_cfg_is_fdpdu(c)) {
		h->type = FT_FD;
		h->id = c->rx_id;
		h->flags = CANFD_FDF;
	} else {
		h->type = FT_CC;
		h->id = c->rx_id;
	}
}

/* ------------------------------------------------------------------------
 * reference encoder
 * ------------------------------------------------------------------------
 */

unsigned int ft_padlen(unsigned int len)
{
	static const uint8_t plen[] = {
		8, 8, 8, 8, 8, 8, 8, 8, 8,	/* 0 - 8 */
		12, 12, 12, 12,			/* 9 - 12 */
		16, 16, 16, 16,			/* 13 - 16 */
		20, 20, 20, 20,			/* 17 - 20 */
		24, 24, 24, 24,			/* 21 - 24 */
		32, 32, 32, 32, 32, 32, 32, 32,	/* 25 - 32 */
		48, 48, 48, 48, 48, 48, 48, 48,	/* 33 - 40 */
		48, 48, 48, 48, 48, 48, 48, 48	/* 41 - 48 */
	};

	if (len > 64)
		return len; /* no CAN FD DLC length */

	if (len > 48)
		return 64;

	return plen[len];
}

void ft_enc_dut(const struct ft_isotp_cfg *c, struct ft_enc *e)
{
	memset(e, 0, sizeof(*e));
	e->ll_dl = ft_cfg_tx_dl(c);
	e->ae = c->opts.flags & CAN_ISOTP_EXTEND_ADDR;
	e->ae_val = c->opts.ext_address;
	e->pad = c->opts.flags & CAN_ISOTP_TX_PADDING;
	e->pad_val = c->opts.txpad_content;
	e->fd = ft_cfg_is_fdpdu(c);
	e->xlsf = ft_cfg_is_xl(c) && !e->fd;
	e->mf = c->opts.flags & CAN_ISOTP_MF_BROADCAST;
}

void ft_enc_peer(const struct ft_isotp_cfg *c, struct ft_enc *e)
{
	memset(e, 0, sizeof(*e));
	e->ll_dl = ft_cfg_tx_dl(c);
	e->ae = c->opts.flags & CAN_ISOTP_EXTEND_ADDR;
	if (c->opts.flags & CAN_ISOTP_RX_EXT_ADDR)
		e->ae_val = c->opts.rx_ext_address;
	else
		e->ae_val = c->opts.ext_address;
	e->pad = c->opts.flags & CAN_ISOTP_RX_PADDING;
	e->pad_val = c->opts.rxpad_content;
	e->fd = ft_cfg_is_fdpdu(c);
	e->xlsf = ft_cfg_is_xl(c) && !e->fd;
	e->mf = false;
}

unsigned int ft_enc_sf_max(const struct ft_enc *e)
{
	if (e->ll_dl == CAN_MAX_DLEN)
		return CAN_MAX_DLEN - 1 - e->ae;

	return e->ll_dl - 2 - e->ae;
}

/* pad frame data from datalen to the padded length if required */
static unsigned int ft_enc_pad(const struct ft_enc *e, uint8_t *buf,
			       unsigned int datalen)
{
	unsigned int plen;

	if (!(e->pad || (e->fd && datalen > CAN_MAX_DLEN)))
		return datalen;

	plen = ft_padlen(datalen);
	memset(buf + datalen, e->pad ? e->pad_val : CAN_ISOTP_DEFAULT_PAD_CONTENT,
	       plen - datalen);

	return plen;
}

int ft_enc_pdu(const struct ft_enc *e, const struct ft_frame *hdr,
	       const uint8_t *data, unsigned int len, struct ft_frame **frames)
{
	unsigned int ae = e->ae ? 1 : 0;
	unsigned int cfspace = e->ll_dl - 1 - ae;
	unsigned int max = 2 + len / cfspace + 1;
	static uint8_t buf[CANXL_MAX_DLEN];
	struct ft_frame *f;
	unsigned int idx, n = 0, pci, datalen, req;
	uint8_t sn = 1;

	f = calloc(max, sizeof(*f));
	*frames = f;
	if (!f)
		return -1;

	memset(buf, 0, sizeof(buf));
	if (ae)
		buf[0] = e->ae_val;

	if (len <= ft_enc_sf_max(e)) {
		/* single frame */
		if (len <= CAN_MAX_DLEN - 1 - ae) {
			buf[ae] = FT_PCI_SF | len;
			pci = 1;
		} else {
			buf[ae] = FT_PCI_SF | (len >> 8) | (e->xlsf ? 8 : 0);
			buf[ae + 1] = len & 0xFF;
			pci = 2;
		}
		memcpy(buf + ae + pci, data, len);
		datalen = ae + pci + len;
		if (datalen < e->ll_dl)
			datalen = ft_enc_pad(e, buf, datalen);
		ft_frame_set(&f[n++], hdr, buf, datalen);
		return n;
	}

	/* first frame */
	if (len > FT_MAX_12BIT_PDU) {
		buf[ae] = e->mf ? FT_PCI_MF : FT_PCI_FF;
		buf[ae + 1] = 0;
		buf[ae + 2] = len >> 24;
		buf[ae + 3] = len >> 16;
		buf[ae + 4] = len >> 8;
		buf[ae + 5] = len;
		pci = 6;
	} else {
		buf[ae] = (e->mf ? FT_PCI_MF : FT_PCI_FF) | (len >> 8);
		buf[ae + 1] = len & 0xFF;
		pci = 2;
	}
	idx = e->ll_dl - ae - pci;
	memcpy(buf + ae + pci, data, idx);
	ft_frame_set(&f[n++], hdr, buf, e->ll_dl);

	/* consecutive frames */
	while (idx < len) {
		memset(buf, 0, sizeof(buf));
		if (ae)
			buf[0] = e->ae_val;
		buf[ae] = FT_PCI_CF | sn;
		sn = (sn + 1) & 0x0F;
		req = len - idx;
		if (req > cfspace)
			req = cfspace;
		memcpy(buf + ae + 1, data + idx, req);
		idx += req;
		datalen = ae + 1 + req;
		if (req < cfspace)
			datalen = ft_enc_pad(e, buf, datalen);
		ft_frame_set(&f[n++], hdr, buf, datalen);
	}

	return n;
}

void ft_enc_fc(const struct ft_enc *e, const struct ft_frame *hdr,
	       uint8_t fs, uint8_t bs, uint8_t stmin, struct ft_frame *f)
{
	uint8_t buf[CAN_MAX_DLEN];
	unsigned int ae = e->ae ? 1 : 0;
	unsigned int datalen = ae + 3;

	memset(buf, 0, sizeof(buf));
	if (ae)
		buf[0] = e->ae_val;
	buf[ae] = FT_PCI_FC | fs;
	buf[ae + 1] = bs;
	buf[ae + 2] = stmin;

	/* FC frames are only padded with CAN_ISOTP_TX_PADDING (to 8 byte) */
	if (e->pad) {
		memset(buf + datalen, e->pad_val, CAN_MAX_DLEN - datalen);
		datalen = CAN_MAX_DLEN;
	}

	ft_frame_set(f, hdr, buf, datalen);
}

int ft_enc_block_end(int cf_idx, int bs)
{
	return bs && (cf_idx % bs) == 0;
}

/* ------------------------------------------------------------------------
 * DUT socket operations
 * ------------------------------------------------------------------------
 */

ssize_t ft_dut_send(struct ft_ctx *ctx, int s, const void *buf, size_t len,
		    int flags)
{
	ssize_t n = send(s, buf, len, flags);

	if (n < 0)
		n = -errno;

	ft_log(ctx, "DUT send(%zu%s) = %zd %s", len,
	       (flags & MSG_DONTWAIT) ? ", MSG_DONTWAIT" : "", n,
	       n < 0 ? ft_errname(n) : "");
	return n;
}

ssize_t ft_dut_recv(struct ft_ctx *ctx, int s, void *buf, size_t size,
		    int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	ssize_t n;
	int ret;

	ret = poll(&pfd, 1, timeout_ms);
	if (ret == 0)
		return -ETIME;
	if (ret < 0)
		return -errno;

	n = recv(s, buf, size, MSG_DONTWAIT);
	if (n < 0)
		n = -errno;

	ft_log(ctx, "DUT recv() = %zd %s", n, n < 0 ? ft_errname(n) : "");
	return n;
}

bool ft_dut_expect_pdu(struct ft_ctx *ctx, int s, const uint8_t *data,
		       size_t len, int timeout_ms)
{
	static uint8_t buf[FT_MAX_PDU + 100];
	ssize_t n = ft_dut_recv(ctx, s, buf, sizeof(buf), timeout_ms);
	size_t i;

	if (!FT_CHECK(ctx, n >= 0, "no PDU received: %s", ft_errname(n)))
		return false;

	if (!FT_CHECK(ctx, (size_t)n == len,
		      "received PDU length %zd, expected %zu", n, len))
		return false;

	for (i = 0; i < len; i++)
		if (buf[i] != data[i])
			break;

	return FT_CHECK(ctx, i == len,
			"PDU content mismatch at index %zu: %02X != %02X",
			i, buf[i], data[i]);
}

bool ft_dut_expect_nopdu(struct ft_ctx *ctx, int s, int ms)
{
	static uint8_t buf[FT_MAX_PDU + 100];
	ssize_t n = ft_dut_recv(ctx, s, buf, sizeof(buf), ms);

	if (n >= 0)
		return FT_CHECK(ctx, false, "unexpected PDU (len %zd)", n);

	return FT_CHECK(ctx, n == -ETIME, "unexpected error on recv(): %s",
			ft_errname(n));
}

int ft_sock_error(int s)
{
	int err = 0;
	socklen_t len = sizeof(err);

	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len))
		return -errno;

	return err;
}

bool ft_dut_expect_err(struct ft_ctx *ctx, int s, int err, int timeout_ms,
		       int64_t *t_ns)
{
	struct pollfd pfd = { .fd = s, .events = 0 };
	int ret, e;

	if (err < 0)
		err = -err;

	ret = poll(&pfd, 1, timeout_ms);
	if (t_ns)
		*t_ns = ft_now_ns();

	if (!FT_CHECK(ctx, ret == 1 && (pfd.revents & POLLERR),
		      "no socket error within %d ms (expected %s)", timeout_ms,
		      ft_errname(err)))
		return false;

	e = ft_sock_error(s);
	ft_log(ctx, "DUT SO_ERROR = %s", ft_errname(e));

	return FT_CHECK(ctx, e == err, "socket error %s, expected %s",
			ft_errname(e), ft_errname(err));
}

bool ft_dut_expect_noerr(struct ft_ctx *ctx, int s)
{
	int e = ft_sock_error(s);

	return FT_CHECK(ctx, e == 0, "unexpected socket error %s",
			ft_errname(e));
}

static void *ft_async_thread(void *arg)
{
	struct ft_async *a = arg;
	ssize_t n;

	a->t_start = ft_now_ns();
	n = send(a->s, a->buf, a->len, a->flags);
	a->ret = (n < 0) ? -errno : n;
	a->t_done = ft_now_ns();
	__atomic_store_n(&a->done, 1, __ATOMIC_RELEASE);

	return NULL;
}

void ft_async_send(struct ft_async *a, int s, const void *buf, size_t len,
		   int flags)
{
	memset(a, 0, sizeof(*a));
	a->s = s;
	a->buf = buf;
	a->len = len;
	a->flags = flags;
	a->ret = -EINPROGRESS;
	if (!pthread_create(&a->thread, NULL, ft_async_thread, a))
		a->started = 1;
}

bool ft_async_done(struct ft_async *a)
{
	return __atomic_load_n(&a->done, __ATOMIC_ACQUIRE);
}

bool ft_async_join(struct ft_ctx *ctx, struct ft_async *a, int timeout_ms)
{
	int64_t end = ft_now_ns() + (int64_t)timeout_ms * 1000000;

	if (!FT_CHECK(ctx, a->started, "async send thread not started"))
		return false;

	while (!ft_async_done(a)) {
		if (ft_now_ns() > end) {
			ft_fail(ctx, "send() did not return within %d ms",
				timeout_ms);
			return false;
		}
		ft_sleep_ms(1);
	}

	pthread_join(a->thread, NULL);
	a->started = 0;
	ft_log(ctx, "DUT send(%zu) returned %zd %s after %lld us", a->len,
	       a->ret, a->ret < 0 ? ft_errname(a->ret) : "",
	       (long long)(a->t_done - a->t_start) / 1000);
	return true;
}

/* ------------------------------------------------------------------------
 * high level protocol helpers
 * ------------------------------------------------------------------------
 */

bool ft_tx_pdu(struct ft_ctx *ctx, int s, const struct ft_isotp_cfg *c,
	       struct ft_peer *p, const uint8_t *data, unsigned int len,
	       uint8_t bs, uint8_t stmin)
{
	struct ft_enc e, pe;
	struct ft_frame hdr_tx, hdr_rx, fc;
	struct ft_frame *frames;
	struct ft_async a;
	int n, i, cfs = 0;
	bool bc = c->opts.flags & (CAN_ISOTP_CF_BROADCAST |
				   CAN_ISOTP_MF_BROADCAST);
	bool ok = true;
	int to = FT_FC_TIMEOUT_MS + 200;

	ft_enc_dut(c, &e);
	ft_enc_peer(c, &pe);
	ft_hdr_dut_tx(c, &hdr_tx);
	ft_hdr_dut_rx(c, &hdr_rx);

	n = ft_enc_pdu(&e, &hdr_tx, data, len, &frames);
	if (n < 0) {
		ft_fail(ctx, "out of memory");
		return false;
	}

	ft_log(ctx, "TX PDU len %u => %d frame(s), FC bs %u stmin 0x%02X",
	       len, n, bs, stmin);

	ft_async_send(&a, s, data, len, 0);

	if (!ft_peer_expect(ctx, p, &frames[0], to)) {
		ok = false;
		goto out;
	}

	if (n > 1 && !bc) {
		ft_enc_fc(&pe, &hdr_rx, FT_FS_CTS, bs, stmin, &fc);
		if (!ft_peer_tx(ctx, p, &fc)) {
			ok = false;
			goto out;
		}
	}

	for (i = 1; i < n; i++) {
		if (!ft_peer_expect(ctx, p, &frames[i], to)) {
			ft_log(ctx, "mismatch at frame %d of %d", i, n);
			ok = false;
			goto out;
		}
		cfs++;
		if (!bc && i < n - 1 && ft_enc_block_end(cfs, bs)) {
			if (!ft_peer_tx(ctx, p, &fc)) {
				ok = false;
				goto out;
			}
		}
	}

	if (!ft_async_join(ctx, &a, 3000)) {
		ok = false;
		goto out;
	}

	ok = FT_CHECK(ctx, a.ret == (ssize_t)len, "send() returned %zd (%s)",
		      a.ret, a.ret < 0 ? ft_errname(a.ret) : "");
	ok &= ft_peer_expect_none(ctx, p, 5);
	ok &= ft_peer_check_drops(ctx, p);

out:
	if (a.started) {
		/* make sure the thread is gone before freeing the data */
		ft_async_join(ctx, &a, 4000);
	}
	free(frames);
	return ok && !ctx->failed;
}

bool ft_rx_pdu(struct ft_ctx *ctx, int s, const struct ft_isotp_cfg *c,
	       struct ft_peer *p, const struct ft_enc *enc,
	       const uint8_t *data, unsigned int len)
{
	struct ft_enc de;
	struct ft_frame hdr_tx, hdr_rx, fc;
	struct ft_frame *frames;
	bool listen = c->opts.flags & CAN_ISOTP_LISTEN_MODE;
	int n, i, cfs = 0;
	bool ok = true;

	ft_enc_dut(c, &de);
	ft_hdr_dut_tx(c, &hdr_tx);
	ft_hdr_dut_rx(c, &hdr_rx);

	n = ft_enc_pdu(enc, &hdr_rx, data, len, &frames);
	if (n < 0) {
		ft_fail(ctx, "out of memory");
		return false;
	}

	ft_log(ctx, "RX PDU len %u => %d frame(s) LL_DL %u, DUT FC bs %u",
	       len, n, enc->ll_dl, c->fc.bs);

	/* DUT flow control frame */
	ft_enc_fc(&de, &hdr_tx, FT_FS_CTS, c->fc.bs, c->fc.stmin, &fc);

	if (!ft_peer_tx(ctx, p, &frames[0])) {
		ok = false;
		goto out;
	}

	if (n > 1 && !listen) {
		if (!ft_peer_expect(ctx, p, &fc, 500)) {
			ok = false;
			goto out;
		}
	}

	for (i = 1; i < n; i++) {
		if (!ft_peer_tx(ctx, p, &frames[i])) {
			ok = false;
			goto out;
		}
		cfs++;
		if (!listen && i < n - 1 && ft_enc_block_end(cfs, c->fc.bs)) {
			if (!ft_peer_expect(ctx, p, &fc, 500)) {
				ft_log(ctx, "no FC after block of %u CFs",
				       c->fc.bs);
				ok = false;
				goto out;
			}
		}
	}

	ok = ft_dut_expect_pdu(ctx, s, data, len, 1000);
	ok &= ft_peer_expect_none(ctx, p, 5);
	ok &= ft_dut_expect_noerr(ctx, s);

out:
	free(frames);
	return ok && !ctx->failed;
}

/* ------------------------------------------------------------------------
 * test runner
 * ------------------------------------------------------------------------
 */

static void ft_usage(const char *prg, const char *suite)
{
	fprintf(stderr,
		"%s - CAN_ISOTP functional tests (%s)\n\n"
		"Usage: %s [options]\n"
		"  -t <patterns>  run only tests matching the comma separated\n"
		"                 shell patterns (e.g. 'TX-FC-*,TX-SEG-CC8-*')\n"
		"  -x <patterns>  exclude tests matching the patterns\n"
		"  -q             quick mode: skip tests running into timeouts\n"
		"  -v             verbose (print trace of all tests, -vv: all frames)\n"
		"  -T <ms>        timing tolerance (default %d ms)\n"
		"  -W <s>         watchdog per test case (default %d s)\n"
		"  -l             list test cases\n"
		"  -m             print test case catalog in markdown\n"
		"\n"
		"Interfaces (environment variables, default):\n"
		"  FT_IF_CC (%s) FT_IF_FD (%s) FT_IF_XL (%s)\n"
		"  FT_IF_XL512 (%s) FT_IF_XL256 (%s) FT_IF_DOWN (%s)\n",
		prg, suite, prg, ft_cfg.tol_ms, ft_cfg.watchdog_s,
		ft_cfg.ifname[FT_IF_CC], ft_cfg.ifname[FT_IF_FD],
		ft_cfg.ifname[FT_IF_XL], ft_cfg.ifname[FT_IF_XL512],
		ft_cfg.ifname[FT_IF_XL256], ft_cfg.ifname[FT_IF_DOWN]);
}

static bool ft_match(const char *list, const char *id)
{
	char *dup, *tok, *save = NULL;
	bool ret = false;

	if (!list)
		return false;

	dup = strdup(list);
	for (tok = strtok_r(dup, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		if (!fnmatch(tok, id, 0)) {
			ret = true;
			break;
		}
	}
	free(dup);
	return ret;
}

static void ft_md_text(const char *s)
{
	for (; s && *s; s++) {
		if (*s == '|')
			fputs("\\|", stdout);
		else
			fputc(*s, stdout);
	}
}

static void ft_print_md(const char *suite, const struct ft_test *tests,
			int ntests)
{
	int i, j;

	printf("## %s\n\n", suite);

	for (i = 0; i < ntests; i = j) {
		/* group parameterized tests with identical description */
		for (j = i + 1; j < ntests; j++)
			if (tests[j].req != tests[i].req ||
			    tests[j].fn != tests[i].fn)
				break;

		printf("### %s", tests[i].id);
		if (j - i > 1)
			printf(" .. %s (%d variants)", tests[j - 1].id, j - i);
		printf("\n\n");
		printf("**%s**\n\n", tests[i].title);
		if (j - i > 1) {
			int k;

			printf("- **Variants:** ");
			for (k = i; k < j; k++)
				printf("`%s`%s", tests[k].id,
				       k < j - 1 ? ", " : "\n");
		}
		printf("- **Behaviour:** ");
		ft_md_text(tests[i].req);
		printf("\n- **Code:** ");
		ft_md_text(tests[i].ref);
		printf("\n");
		if (tests[i].iso) {
			printf("- **ISO 15765-2:** ");
			ft_md_text(tests[i].iso);
			printf("\n");
		}
		if (tests[i].flags) {
			printf("- **Flags:**%s%s\n",
			       (tests[i].flags & FT_SLOW) ? " slow" : "",
			       (tests[i].flags & FT_TIMING) ? " timing" : "");
		}
		printf("\n");
	}
}

static int ft_run_one(const struct ft_test *t)
{
	struct ft_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.t = t;
	ctx.log = open_memstream(&ctx.logbuf, &ctx.loglen);
	ft_frame_logs = 0;

	t->fn(&ctx, t->param);

	fclose(ctx.log);

	if (ctx.failed)
		ret = 1;
	else if (ctx.skipped)
		ret = 2;
	else if (ctx.ndev)
		ret = 3;
	else
		ret = 0;

	if (ft_cfg.verbose || ret)
		fwrite(ctx.logbuf, 1, ctx.loglen, stdout);
	fflush(stdout);
	free(ctx.logbuf);

	return ret;
}

int ft_main(int argc, char **argv, const char *suite,
	    const struct ft_test *tests, int ntests)
{
	const char *incl = NULL, *excl = NULL;
	int opt, i, num = 0;
	int npass = 0, nfail = 0, nskip = 0, ndev = 0, nrev = 0;
	int list = 0, md = 0;
	int64_t t0 = ft_now_ns();

	for (i = 0; i < FT_IF_MAX; i++) {
		const char *e = getenv(ft_if_env[i]);

		if (e && *e)
			ft_cfg.ifname[i] = e;
	}

	while ((opt = getopt(argc, argv, "t:x:qvT:W:lmh")) != -1) {
		switch (opt) {
		case 't':
			incl = optarg;
			break;
		case 'x':
			excl = optarg;
			break;
		case 'q':
			ft_cfg.quick = 1;
			break;
		case 'v':
			ft_cfg.verbose++;
			break;
		case 'T':
			ft_cfg.tol_ms = atoi(optarg);
			break;
		case 'W':
			ft_cfg.watchdog_s = atoi(optarg);
			break;
		case 'l':
			list = 1;
			break;
		case 'm':
			md = 1;
			break;
		default:
			ft_usage(argv[0], suite);
			return 2;
		}
	}

	if (md) {
		ft_print_md(suite, tests, ntests);
		return 0;
	}

	if (list) {
		for (i = 0; i < ntests; i++)
			printf("%-28s %s%s%s\n", tests[i].id, tests[i].title,
			       (tests[i].flags & FT_SLOW) ? " [slow]" : "",
			       (tests[i].flags & FT_TIMING) ? " [timing]" : "");
		return 0;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGPIPE, SIG_IGN);

	i = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
	if (i < 0) {
		printf("Bail out! CAN_ISOTP sockets not available: %s\n",
		       ft_errname(errno));
		return 2;
	}
	close(i);

	printf("# CAN_ISOTP functional test suite: %s\n", suite);
	printf("# interfaces: CC %s FD %s XL %s XL512 %s XL256 %s DOWN %s\n",
	       ft_cfg.ifname[FT_IF_CC], ft_cfg.ifname[FT_IF_FD],
	       ft_cfg.ifname[FT_IF_XL], ft_cfg.ifname[FT_IF_XL512],
	       ft_cfg.ifname[FT_IF_XL256], ft_cfg.ifname[FT_IF_DOWN]);
	printf("# timing tolerance %d ms%s\n", ft_cfg.tol_ms,
	       ft_cfg.quick ? ", quick mode" : "");

	/* count selected tests for the TAP plan */
	for (i = 0; i < ntests; i++) {
		if (incl && !ft_match(incl, tests[i].id))
			continue;
		if (excl && ft_match(excl, tests[i].id))
			continue;
		num++;
	}
	printf("1..%d\n", num);

	num = 0;
	for (i = 0; i < ntests; i++) {
		const struct ft_test *t = &tests[i];
		const char *note = "";
		int64_t ts = ft_now_ns();
		pid_t pid;
		int status = 0, ret;

		if (incl && !ft_match(incl, t->id))
			continue;
		if (excl && ft_match(excl, t->id))
			continue;

		num++;

		if (ft_cfg.quick && (t->flags & FT_SLOW)) {
			printf("ok %d - %s %s # SKIP quick mode\n", num, t->id,
			       t->title);
			nskip++;
			continue;
		}

		if (ft_cfg.verbose)
			printf("# ---- %s: %s\n", t->id, t->title);

		fflush(stdout);
		pid = fork();
		if (pid < 0) {
			perror("fork");
			return 2;
		}
		if (pid == 0) {
			alarm(ft_cfg.watchdog_s);
			_exit(ft_run_one(t));
		}

		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;

		if (WIFEXITED(status))
			ret = WEXITSTATUS(status);
		else
			ret = -1;

		/* "DEVIATION (if observed)": only reported dynamically */
		if (t->iso && !strncmp(t->iso, "DEVIATION (if observed)", 23))
			note = "";
		else if (t->iso && !strncmp(t->iso, "DEVIATION", 9))
			note = " # DEVIATION";
		else if (t->iso && !strncmp(t->iso, "REVIEW", 6))
			note = " # REVIEW";

		switch (ret) {
		case 0:
		case 3:
			if (ret == 3)
				note = " # DEVIATION";
			printf("ok %d - %s %s%s\n", num, t->id, t->title, note);
			npass++;
			if (*note == ' ' && note[3] == 'D')
				ndev++;
			else if (*note)
				nrev++;
			break;
		case 2:
			printf("ok %d - %s %s # SKIP\n", num, t->id, t->title);
			nskip++;
			break;
		case 1:
			printf("not ok %d - %s %s\n", num, t->id, t->title);
			nfail++;
			break;
		default:
			printf("# test process terminated (%s)\n",
			       WIFSIGNALED(status) ?
			       (WTERMSIG(status) == SIGALRM ?
				"watchdog timeout" : strsignal(WTERMSIG(status))) :
			       "unknown");
			printf("not ok %d - %s %s\n", num, t->id, t->title);
			nfail++;
			break;
		}

		if (ft_cfg.verbose)
			printf("# duration %lld ms\n",
			       (long long)(ft_now_ns() - ts) / 1000000);
	}

	printf("# %s: %d tests, %d passed (%d with DEVIATION, %d with REVIEW note), %d failed, %d skipped, %lld s\n",
	       suite, num, npass, ndev, nrev, nfail, nskip,
	       (long long)(ft_now_ns() - t0) / 1000000000);

	return nfail ? 1 : 0;
}
