#include "util.h"
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "config.h"

_Static_assert(INET_ADDRSTRLEN < INET6_ADDRSTRLEN);


const char *our_inet_ntop (
	const struct sockaddr *in_addr,
	char *out,
	const size_t size)
{
	static const uint8_t MAPPED_V4[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
	};
	const char *ret = NULL;

	if (in_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr = (const struct sockaddr_in6*)in_addr;

		if (memcmp(&addr->sin6_addr, MAPPED_V4, sizeof(MAPPED_V4)) == 0) {
// This is a Linux program. Accepting v4 clients using v6 server socket is a
// Linux thing. v4 addresses mapped in v6 are ugly so let's fix that.
			ret = inet_ntop(
				AF_INET,
				(const uint8_t*)&addr->sin6_addr + sizeof(MAPPED_V4),
				out,
				size);
		}
		else {
			// This is only for polyfill in case the kernel is not built w/ v6
			ret = inet_ntop(addr->sin6_family, &addr->sin6_addr, out, size);
		}
	}
	else if (in_addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr = (const struct sockaddr_in*)in_addr;

		ret = inet_ntop(addr->sin_family, &addr->sin_addr, out, size);
	}
	else {
		errno = EAFNOSUPPORT;
	}

	return ret;
}

bool setsockopt_int (
	const int fd,
	const int level,
	const int opt,
	const int v)
{
	return setsockopt(fd, level, opt, &v, sizeof(v)) == 0;
}

bool getsockopt_int (
	const int fd,
	const int level,
	const int opt,
	int *v,
	socklen_t *sl)
{
	socklen_t l = sizeof(int);
	const bool ret = getsockopt(fd, level, opt, v, &l) == 0;

	if (sl != NULL) {
		*sl = l;
	}

	return ret;
}

bool get_tcp_repair_window (
	const int fd,
	struct tcp_repair_window *trw,
	socklen_t *sl)
{
	socklen_t l = sizeof(struct tcp_repair_window);
	const bool ret = getsockopt(fd, SOL_TCP, TCP_REPAIR_WINDOW, trw, &l) == 0;

	if (sl != NULL) {
		*sl = l;
	}

	return ret;
}

bool get_tcp_info (const int fd, struct tcp_info *ti, socklen_t *sl) {
	socklen_t l = sizeof(struct tcp_info);
	const bool ret = getsockopt(fd, SOL_TCP, TCP_INFO, ti, &l) == 0;

	if (sl != NULL) {
		*sl = l;
	}

	return ret;
}

bool test_tcp_repair_window (const int fd, FILE *f, const char *tag_in) {
	int ov = -1;
	int saved_tcp_repair = -1;
	bool ret = false;
	struct tcp_repair_window trw = { 0, };

	if (!getsockopt_int(fd, SOL_TCP, TCP_REPAIR, &saved_tcp_repair, NULL)) {
		perror("test_tcp_repair_window: getsockopt_int(fd, SOL_TCP, TCP_REPAIR, ...)");
		return false;
	}

	if (!setsockopt_int(fd, SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)) {
		perror("test_tcp_repair_window: setsockopt_int(fd, SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)");
		return false;
	}

	if (!getsockopt_int(fd, SOL_TCP, TCP_REPAIR, &ov, NULL)) {
		perror("test_tcp_repair_window: getsockopt_int(fd, SOL_TCP, TCP_REPAIR, ...)");
		goto END;
	}
	assert(ov == TCP_REPAIR_ON);

	if (!get_tcp_repair_window(fd, &trw, NULL)) {
		perror("test_tcp_repair_window: get_tcp_repair_window(fd, &trw, NULL)");
		goto END;
	}

	if (f != NULL) {
		printf(
			"%s\n"
			"trw:\n"
			"  snd_wl1:     %"PRIu32"\n"
			"  snd_wnd:     %"PRIu32"\n"
			"  max_window:  %"PRIu32"\n"
			"  rcv_wnd:     %"PRIu32"\n"
			"  rcv_wup:     %"PRIu32"\n"
			,
			tag_in ? tag_in : "",
			trw.snd_wl1,
			trw.snd_wnd,
			trw.max_window,
			trw.rcv_wnd,
			trw.rcv_wup);
	}
	ret = true;

END:
	if (saved_tcp_repair >= 0) {
		setsockopt_int(fd, SOL_TCP, TCP_REPAIR, saved_tcp_repair);
	}
	return ret;
}

char *inet_ep_ntop (
		const struct sockaddr *in_addr,
		void *out,
		const size_t size)
{
	_Static_assert(INT_MAX >= INET_EP_ADDRSTRLEN);
	char addr_str[INET6_ADDRSTRLEN];
	int cnt = -1;

	if (our_inet_ntop(in_addr, addr_str, sizeof(addr_str)) == NULL) {
		return NULL;
	}

	if (in_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr = (const struct sockaddr_in6*)in_addr;
		cnt = snprintf(out, size, "[%s]:%"PRIu16, addr_str, ntohs(addr->sin6_port));
	}
	else if (in_addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr = (const struct sockaddr_in*)in_addr;
		cnt = snprintf(out, size, "%s:%"PRIu16, addr_str, ntohs(addr->sin_port));
	}
	else {
		errno = EINVAL;
		return NULL;
	}

	if (cnt < 0) {
		return NULL;
	}
	if ((size_t)cnt >= size) {
		errno = ENOSPC;
		return NULL;
	}

	return out;
}

int print_version (FILE *out) {
	return fprintf(out, "%s\n", SYNDIAG_VERSION);
}

bool setnonblock (const int fd, const bool onoff) {
	int ret;

	ret = fcntl(fd, F_GETFL, 0);
	if (ret < 0) {
		return false;
	}

	if (onoff) {
		ret |= O_NONBLOCK;
	}
	else {
		ret &= ~O_NONBLOCK;
	}
	ret = fcntl(fd, F_SETFL, ret);

	return ret == 0;
}
