#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <ctype.h>
#include <locale.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <netdb.h>
#include <getopt.h>
#include <errno.h>
#include "util.h"
#include "config.h"

#define ARGV0 "syndiag"

static struct {
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} remote_addr;
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} local_addr;
	int fd;
} client;

static struct {
	struct {
		const char *host;
		const char *service;
	} target;
	union {
		size_t all;
		struct {
			size_t help:1;
			size_t version:1;
			size_t v4:1;
			size_t v6:1;
		};
	} opts;
} param;

static int print_help (FILE *out, const char *argv0) {
#define HELP_STR \
"TCP SYN diagnostics tool\n" \
"Usage: %s [-hV46] [--] HOST [PORT]\n" \
"Options:\n" \
"  -h  print this message and exit\n" \
"  -V  print version and exit\n"\
"  -4  use IPv4 connectivity only\n"\
"  -6  use IPv6 connectivity only\n"

	return fprintf(out, HELP_STR, argv0);
#undef HELP_STR
}

static void init_param_defaults (void) {
	param.target.service = SYNDIAG_PORT_STR;
}

static void init_global (void) {
	client.fd = -1;
}

static void deinit_global (void) {
	CHK_CLOSE(client.fd);
	client.fd = -1;
}

static bool parse_argv (const int argc, const char **argv) {
	int c;

	do {
		c = getopt(argc, (char*const*)argv, "hV46");

		switch (c) {
		case -1: break;
		case '?': return false;
		case 'h': param.opts.help = true; break;
		case 'V': param.opts.version = true; break;
		case '4': param.opts.v4 = true; break;
		case '6': param.opts.v6 = true; break;
		default: abort();
		}
	} while (c >= 0);

	if (param.opts.v4 && param.opts.v6) {
		fprintf(stderr, ARGV0": only one -4 or -6 option may be specified\n");
		return false;
	}

	if (optind < argc) {
		param.target.host = argv[optind];
	}
	else if (!(param.opts.version || param.opts.help)) {
		fprintf(stderr, ARGV0": too few arguments. Use -h option for usage\n");
	}
	optind += 1;

	if (optind < argc) {
		param.target.service = argv[optind];
	}
	optind += 1;

	if (optind < argc) {
		errno = E2BIG;
		perror(ARGV0);
		return false;
	}

	return true;
}

static void do_param_sanity_check (void) {
	// nothing to do as of yet
}

static struct addrinfo *resolve_host (void) {
	struct addrinfo *ret = NULL;
	struct addrinfo hints = { 0, };
	int s;

	if (param.opts.v4) {
		hints.ai_family = AF_INET;
	}
	else if (param.opts.v6) {
		hints.ai_family = AF_INET6;
	}
	else {
		hints.ai_family = AF_UNSPEC;
	}
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
#ifdef AI_IDN
	hints.ai_flags |= AI_IDN;
#endif

	s = getaddrinfo(param.target.host, param.target.service, &hints, &ret);
	if (s != 0) {
		fprintf(stderr, "%s: %s\n", ARGV0, gai_strerror(s));
	}

	return ret;
}

static int do_eyeball (struct addrinfo *ai) {
	struct pollfd pfd[2] = { 0, };
	struct addrinfo *cand[2];
	int ret = -1;
	int fr;
	socklen_t sl;

	pfd[0].fd = pfd[1].fd = -1;
	pfd[0].events = pfd[1].events = POLLOUT;

	while (true) {
		CHK_CLOSE(pfd[0].fd);
		CHK_CLOSE(pfd[1].fd);

		pfd[0].fd = pfd[1].fd = -1;
		cand[0] = cand[1] = NULL;

		while (ai != NULL && (cand[0] == NULL || cand[1] == NULL)) {
			if (ai->ai_family > 0) {
				// prefer IPv6 connectivity
				if (cand[0] == NULL && ai->ai_family == AF_INET6) {
					cand[0] = ai;
				}
				else if (cand[1] == NULL && ai->ai_family == AF_INET) {
					cand[1] = ai;
				}
			}

			ai = ai->ai_next;
		}

		if (cand[0] == NULL && cand[1] == NULL) {
			// all the entries exhausted
			break;
		}

		for (size_t i = 0; i < 2; i += 1) {
			if (cand[i] == NULL) {
				continue;
			}

			pfd[i].fd = socket(
				cand[i]->ai_family,
				cand[i]->ai_socktype,
				cand[i]->ai_protocol);
			setnonblock(pfd[i].fd, true);
			fr = connect(pfd[i].fd, cand[i]->ai_addr, cand[i]->ai_addrlen);
			if (fr < 0 && errno != EINPROGRESS) {
				close(pfd[i].fd);
				pfd[i].fd = -1;
				cand[i]->ai_family = -1;
			}
		}

		pfd[0].revents = pfd[1].revents = 0;
		fr = poll(pfd, 2, 5000);
		if (fr == 0) {
			errno = ETIMEDOUT;
		}
		for (size_t i = 0; i < 2; i += 1) {
			if (pfd[i].revents == 0 || pfd[i].fd < 0) {
				continue;
			}
			fr = 0;
			sl = sizeof(fr);
			if (pfd[i].revents &&
					getsockopt(pfd[i].fd, SOL_SOCKET, SO_ERROR, &fr, &sl) != 0 ||
					fr != 0)
			{
				cand[i]->ai_family = -1;
				errno = fr;
				continue;
			}

			ret = pfd[i].fd;
			pfd[i].fd = -1;
			cand[i]->ai_family = -1;
			assert(sizeof(client.remote_addr) >= cand[i]->ai_addrlen);
			memcpy(
				&client.remote_addr,
				cand[i]->ai_addr,
				cand[i]->ai_addrlen);
			sl = sizeof(client.local_addr);
			getsockname(ret, &client.local_addr.sa, &sl);
			goto END;
		}
	}

END:
	CHK_CLOSE(pfd[0].fd);
	CHK_CLOSE(pfd[1].fd);
	return ret;
}

static void report_connected_host(void) {
	char str_buf[INET_EP_ADDRSTRLEN];
	char *str;

	str = inet_ep_ntop(&client.remote_addr.sa, str_buf, sizeof(str_buf));
	assert(str != NULL);
	fprintf(stderr, "connected to: %s\n", str);
}

static int mk_main_socket (void) {
	struct addrinfo *ai;
	int ret = -1;

	ai = resolve_host();
	if (ai == NULL) {
		goto END;
	}

	fprintf(stderr, "connecting to: %s\n", param.target.host);
	ret = do_eyeball(ai);
	if (ret < 0) {
		perror(ARGV0);
		goto END;
	}
	else {
		setnonblock(ret, false);
	}
	report_connected_host();

END:
	freeaddrinfo(ai);
	return ret;
}

static void print_preemble (void) {
	char ep_remote_str[INET_EP_ADDRSTRLEN] = { 0, };
	char ep_local_str[INET_EP_ADDRSTRLEN] = { 0, };
	uint32_t fl;

	if (client.remote_addr.sa.sa_family == AF_INET6) {
		fl = client.remote_addr.v6.sin6_family;
	}
	else {
		fl = 0;
	}
	inet_ep_ntop(&client.remote_addr.sa, ep_remote_str, sizeof(ep_remote_str));
	inet_ep_ntop(&client.local_addr.sa, ep_local_str, sizeof(ep_local_str));

	printf("syndiag report:\n");
	printf("  rev:        0\n");
	printf("  version:    "SYNDIAG_VERSION"\n");
	printf("  remote:     %s\n", ep_remote_str);
	printf("  local:      %s\n", ep_local_str);
	printf("  flow label: %"PRIu32"\n", fl);
}

static int print_our_diag (void) {
	int ret = -1;
	struct tcp_info ti = { 0, };
	struct tcp_repair_window trw = { 0, };
	struct {
		uint32_t fl;
		char addr_str[INET6_ADDRSTRLEN];
		uint16_t port;
	} addr = { 0, };

	if (!get_tcp_info(client.fd, &ti, NULL)) {
		perror(ARGV0": get_tcp_info()");
		goto END;
	}

	if (setsockopt_int(client.fd, SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)) {
		get_tcp_repair_window(client.fd, &trw, NULL);
		setsockopt_int(client.fd, SOL_TCP, TCP_REPAIR, TCP_REPAIR_OFF);
	}

	if (client.local_addr.sa.sa_family == AF_INET6) {
		addr.fl = client.local_addr.v6.sin6_family;
		addr.port = ntohs(client.local_addr.v6.sin6_port);
	}
	else {
		addr.fl = 0;
		addr.port = ntohs(client.local_addr.v4.sin_port);
	}
	our_inet_ntop(&client.local_addr.sa, addr.addr_str, sizeof(addr.addr_str));

	printf(
		"  ours:\n"
		"    address:           %s\n"
		"    port:              %"PRIu16"\n"
		"    flow label:        %"PRIu32"\n"
		"    trw.snd_wnd:       %"PRIu32"\n"
		"    trw.rcv_wnd:       %"PRIu32"\n"
		"    ti.tcpi_snd_mss:   %"PRIu32"\n"
		"    ti.tcpi_rcv_mss:   %"PRIu32"\n"
		"    ti.tcpi_advmss:    %"PRIu32"\n"
		"    ti.tcpi_rcv_space: %"PRIu32"\n"
		,
		addr.addr_str,
		addr.port,
		addr.fl,
		trw.snd_wnd,
		trw.rcv_wnd,
		ti.tcpi_snd_mss,
		ti.tcpi_rcv_mss,
		ti.tcpi_advmss,
		ti.tcpi_rcv_space
	);
	ret = 0;

END:
	return ret;
}

static bool is_writable_str (const char *s) {
	for (size_t i = 0; s[i] != 0; i += 1) {
		if (!(isprint(s[i]) || isspace(s[i]))) {
			return false;
		}
	}
	return true;
}

static void foreach_delim (char *s, const char *delim, void(*f)(const char *)) {
	char *needle;
	const size_t delim_len = strlen(delim);

	while (true) {
		needle = strstr(s, delim);

		if (needle == NULL) {
			f(s);
			break;
		}
		else {
			*needle = 0;
			f(s);
		}

		s = needle + delim_len;
	}
}

static void parse_daemon_line (const char *line) {
	if (line[0] == 0) {
		return;
	}
	printf("    %s\n", line);
}

static int print_their_diag (void) {
	int ret = 1;
	char rcv_buf[4096];
	ssize_t iofr;

	// Cue the server
	shutdown(client.fd, SHUT_WR);
	iofr = read(client.fd, rcv_buf, sizeof(rcv_buf) - 1);
	if (iofr < 0) {
		goto END;
	}
	shutdown(client.fd, SHUT_RD);
	rcv_buf[iofr] = 0;

	if (strstr(rcv_buf, "SYNDIAG:") != rcv_buf || !is_writable_str(rcv_buf)) {
		errno = EPROTO;
		goto END;
	}

	printf("  theirs:\n");
	foreach_delim(rcv_buf, "\r\n", parse_daemon_line);

	ret = 0;

END:
	return ret;
}

int main (const int argc, const char **argv) {
	int ec = 1;

	// override env locale
	setlocale(LC_ALL, "C");
	init_param_defaults();

	if (!parse_argv(argc, argv)) {
		return 2;
	}

	if (param.opts.version) {
		print_version(stdout);
	}
	if (param.opts.help) {
		print_help(stdout, argv[0]);
	}
	if (param.opts.version || param.opts.help) {
		return 0;
	}

	do_param_sanity_check();

	init_global();

	client.fd = mk_main_socket();
	if (client.fd < 0) {
		goto END;
	}

	print_preemble();
	ec = print_our_diag();
	if (ec != 0) {
		perror(ARGV0);
	}

	ec = print_their_diag();
	if (ec != 0) {
		perror(ARGV0);
	}

END:
	deinit_global();
	return ec;
}
