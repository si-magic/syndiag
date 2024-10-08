/*
 * Copyright (c) 2024 David Timber <dxdt@dev.snart.me>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "config.h"
#include "util.h"

#define ARGV0 "syndiagd"

static struct {
	struct {
		size_t nb_conns;
	} pool;
	// don't let the CC put this in register because the fd is closed in the
	// signal handler.
	volatile int fd;
} server;

static struct {
	size_t max_con;
	const char *pid_file;
	char hostname[256];
	char contact[256];
	unsigned int timeout;
	int sck_buf_size;
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} listen;
	union {
		size_t all;
		struct {
			size_t help:1;
			size_t version:1;
			size_t daemon:1;
			size_t mtu1280:1;
		};
	} opts;
} param;

static int print_help (FILE *out, const char *argv0) {
#define HELP_STR \
"TCP SYN diagnostics daemon\n" \
"Usage: %s [-hVDT] [-l BIND_ADDR] [-p PORT] [-m MAX_CONN] [-P PID_FILE]\n" \
"          [-H hostname] [-S SO_SNDBUF] [-C CONTACT]\n" \
"Options:\n" \
"  -h            print this message and exit\n" \
"  -V            print version and exit\n" \
"  -l BIND_ADDR  bind address (default: *)\n" \
"  -p PORT       listen port (default: %"PRIu16")\n" \
"  -m MAX_CONN   max number of connections (default: %zu)\n" \
"  -D            daemonize\n"\
"  -P PID_FILE   maintain a PID file\n" \
"  -H HOSTNAME   specify hostname (default: %s)\n"\
"  -S SO_SNDBUF  specify socket send buffer size\n"\
"                (you probably want to set this on top of sysctl)\n"\
"  -T            enable mtu1280 mode\n"\
"  -C CONTACT    set contact info in response body\n"

	return fprintf(
		out,
		HELP_STR,

		argv0,
		SYNDIAG_PORT,
		param.max_con,
		param.hostname);
#undef HELP_STR
}

static void init_param_defaults (void) {
	param.max_con = 1024;
	param.timeout = 5;
	param.listen.sa.sa_family = AF_INET6;
	param.listen.v6.sin6_port = htons(SYNDIAG_PORT);
	gethostname(param.hostname, sizeof(param.hostname));
}

static void init_global (void) {
	server.fd = -1;
}

static void deinit_global (void) {
	// nothing to do
}

static bool consume_incoming_zeros (
		const int fd,
		char *buf,
		size_t *read_zeros_len)
{
	ssize_t fr;
	size_t z;

	fr = read(fd, buf, SYNDIAG_TEST_MTU + 1);
	if (fr < 0) {
		return false;
	}
	else if (fr == 0) {
		*read_zeros_len = 0;
		return true;
	}
	else if ((size_t)fr > SYNDIAG_TEST_MTU || !ismemzero(buf, (size_t)fr)) {
		errno = EPROTO;
		return false;
	}
	z = (size_t)fr;

	fr = read(fd, buf, 1);
	if (fr > 0) {
		errno = EPROTO;
		return false;
	}
	else if (fr < 0) {
		return false;
	}

	*read_zeros_len = z;
	return true;
}

static bool cue_client (const int fd) {
	const uint8_t cue = 0;
	return send(fd, &cue, 1, MSG_OOB) == 1;
}

static int child_main (const int fd, const struct sockaddr *in_addr) {
	// tcp_info: mss, window
	// tcp_repair_window: window
	struct {
		char addr_str[INET6_ADDRSTRLEN];
		uint16_t port;
	} addr = { 0, };
	int ec = 1;
	struct tcp_info ti = { 0, };
	struct tcp_repair_window trw = { 0, };
	char io_buf[4096];
	int fr;
	ssize_t rwr;
	size_t snd_len;
	size_t read_zeros_len = 0;

	// ensure that io_buf is aligned, otherwise there will be a huge
	// performance impact in ismemzero();
	assert(ISMEMZERO_ALIGNED(io_buf));

	// for consume_incoming_zeros()
	static_assert(sizeof(io_buf) >= SYNDIAG_TEST_MTU + 1);

	// the child wants to die when the connection times out
	signal(SIGALRM, SIG_DFL);
	alarm(param.timeout);

	switch (in_addr->sa_family) {
	case AF_INET:
		addr.port = ntohs(((struct sockaddr_in*)in_addr)->sin_port);
		break;
	case AF_INET6:
		addr.port = ntohs(((struct sockaddr_in6*)in_addr)->sin6_port);
		break;
	default: abort();
	}

	// socket options
	// it's better to use sysctl because this will add to the time it takes for
	// the kernel to notify the updated window size.
	if (param.sck_buf_size > 0) {
		const bool fr =
#if HAVE_SO_RCVBUFFORCE
			setsockopt_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, param.sck_buf_size) ||
					setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, param.sck_buf_size);
#else
			setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, param.sck_buf_size);
#endif
		if (!fr) {
			perror("setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, ...)");
		}
	}

	// cue the client
	cue_client(fd);

	// wait for the client's cue
	fr = consume_incoming_zeros(fd, io_buf, &read_zeros_len);
	if (!fr) {
		perror("consume_incoming_zeros()");
		goto END;
	}

	// now, hopefully, the TRW state is up to date!

	if (!get_tcp_info(fd, &ti, NULL)) {
		perror("get_tcp_info()");
		goto END;
	}

	if (setsockopt_int(fd, SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)) {
		if (!get_tcp_repair_window(fd, &trw, NULL)) {
			perror("get_tcp_repair_window()");
			goto END;
		}

		setsockopt_int(fd, SOL_TCP, TCP_REPAIR, TCP_REPAIR_OFF);
	}
	else {
		perror("setsockopt_int(fd, SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)");
		goto END;
	}

	// for printf()
	static_assert(sizeof(uint32_t) == sizeof(trw.snd_wnd));
	static_assert(sizeof(uint32_t) == sizeof(trw.rcv_wnd));
	static_assert(sizeof(uint32_t) == sizeof(ti.tcpi_snd_mss));
	static_assert(sizeof(uint32_t) == sizeof(ti.tcpi_rcv_mss));
	static_assert(sizeof(uint32_t) == sizeof(ti.tcpi_advmss));
	static_assert(sizeof(uint32_t) == sizeof(ti.tcpi_rcv_space));

	if (our_inet_ntop(in_addr, addr.addr_str, sizeof(addr.addr_str)) == NULL) {
		// silently ignore this error
		addr.addr_str[0] = 0;
	}

	// bit of static memory safety checks
	static_assert(sizeof(
		"SYNDIAG:           'v255.255.255.255 REV 0'\r\n"
		"host:              '012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012'\r\n"
		"address:           '0000:0000:0000:0000:0000:0000:0000:0000'\r\n"
		"port:              65535\r\n"
		"trw.snd_wnd:       4294967295\r\n"
		"trw.rcv_wnd:       4294967295\r\n"
		"ti.tcpi_snd_mss:   4294967295\r\n"
		"ti.tcpi_rcv_mss:   4294967295\r\n"
		"ti.tcpi_advmss:    4294967295\r\n"
		"ti.tcpi_rcv_space: 4294967295\r\n"
		"mtu1280:           false\r\n"
		"contact:           '012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012'\r\n"
	) <= sizeof(io_buf));
	fr = snprintf(io_buf, sizeof(io_buf),
		"SYNDIAG:           'v%s REV 0'\r\n"
		"host:              '%s'\r\n"
		"address:           '%s'\r\n"
		"port:              %"PRIu16"\r\n"
		"trw.snd_wnd:       %"PRIu32"\r\n"
		"trw.rcv_wnd:       %"PRIu32"\r\n"
		"ti.tcpi_snd_mss:   %"PRIu32"\r\n"
		"ti.tcpi_rcv_mss:   %"PRIu32"\r\n"
		"ti.tcpi_advmss:    %"PRIu32"\r\n"
		"ti.tcpi_rcv_space: %"PRIu32"\r\n"
		"mtu1280:           %s\r\n"
		"contact:           '%s'\r\n"
		,
		SYNDIAG_VERSION,
		param.hostname,
		addr.addr_str,
		addr.port,
		trw.snd_wnd,
		trw.rcv_wnd,
		ti.tcpi_snd_mss,
		ti.tcpi_rcv_mss,
		ti.tcpi_advmss,
		ti.tcpi_rcv_space,
		param.opts.mtu1280 ? "true" : "false",
		param.contact
	);
	if (fr < 0) {
		perror("snprintf()");
		goto END;
	}

	snd_len = (size_t)fr;
	if (read_zeros_len > 0 && snd_len < SYNDIAG_TEST_MTU) {
		const size_t extra_len = SYNDIAG_TEST_MTU - snd_len;

		memset(io_buf + snd_len, 0, extra_len);
		snd_len += extra_len;
	}

	shutdown(fd, SHUT_RD);
	rwr = write(fd, io_buf, snd_len);
	shutdown(fd, SHUT_WR);
	ec = rwr == (ssize_t)snd_len ? 0 : 1;

END:
	close(fd);
	return ec;
}

static void reap_children (const bool hang) {
	pid_t c;
	const int saved_errno = errno;

	while (true) {
		c = waitpid(0, NULL, hang ? 0 : WNOHANG);
		if (c > 0) {
			server.pool.nb_conns -= 1;
		}
		else {
			break;
		}
	}

	errno = saved_errno;
}

static void report_new_conn (
		const int fd,
		const struct sockaddr *in_addr,
		const char *msg)
{
	char ep_str[INET_EP_ADDRSTRLEN];

	if (inet_ep_ntop(in_addr, ep_str, sizeof(ep_str)) == NULL) {
		abort();
	}

	if (msg != NULL && msg[0] != 0) {
		printf("New conn from %s: %s\n", ep_str, msg);
	}
	else {
		printf("New conn from %s\n", ep_str);
	}
}

static void report_ready (void) {
	char ep_str[INET_EP_ADDRSTRLEN] = { 0, };
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} local_addr = { 0, };
	socklen_t sl = sizeof(local_addr);

	getsockname(server.fd, &local_addr.sa, &sl);
	inet_ep_ntop(&local_addr.sa, ep_str, sizeof(ep_str));

	printf(
		"syndiagd v%s servicing on %s (max connections: %zu)...\n",
		SYNDIAG_VERSION,
		ep_str,
		param.max_con);
}

static int do_serve (void) {
	int new_fd;
	int accept_errno;
	struct sockaddr_in6 addr;
	socklen_t addr_len;
	pid_t child;

	report_ready();

	while (server.fd >= 0) {
		addr_len = sizeof(addr);
		// to wake up from accept() and reap the children that went missing
		alarm(1);
		new_fd = accept(server.fd, (struct sockaddr*)&addr, &addr_len);
		alarm(0);
		accept_errno = errno;

		reap_children(false);

		if (new_fd < 0) {
			switch (accept_errno) {
			case EINTR:
			case ECONNABORTED:
				break;
			default: perror("accept()");
			}

			switch (accept_errno) {
			// acceptable errnos:
			case ENOMEM:
			case ECONNABORTED:
			case EINTR:
				break;
			default: // unexpected errnos
				abort();
			}

			continue;
		}

		if (server.pool.nb_conns < param.max_con) {
			report_new_conn(new_fd, (struct sockaddr*)&addr, NULL);

			child = fork();
			if (child > 0) {
				server.pool.nb_conns += 1;
			}
			else if (child == 0) {
				return child_main(new_fd, (struct sockaddr*)&addr);
			}
			else {
				perror("fork()");
			}
		}
		else {
			report_new_conn(
				new_fd,
				(struct sockaddr*)&addr,
				"dropping due to max connections reached");
		}

		close(new_fd);
	}

	if (server.pool.nb_conns > 0) {
		fprintf(stderr, "Will wait for child processes to finish ...\n");
	}
	reap_children(true);

	return 0;
}

static void handle_exit_signal (const int sn) {
	if (server.fd >= 0) {
		close(server.fd);
		server.fd = -1;
	}
}

static void handle_parent_alarm (const int sn) {
	// do nothing so that the context is returned from accept() with EINTR
}

static int mk_main_socket (void) {
	int ret = -1;
	int fd;

	fd = socket(param.listen.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		perror("socket()");
		goto END;
	}

	if (param.opts.mtu1280) {
// Let the upstream router fragment the packets to see if the fragmented packets
// can make it to the client. The client sets this to IP_PMTUDISC_DO to test if
// ICMP is not blocked.
		setsockopt_int(fd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
	}
	setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);

	if (bind(fd, &param.listen.sa, sizeof(param.listen)) < 0) {
		perror("bind()");
		goto END;
	}

	if (listen(fd, param.max_con) < 0) {
		perror("listen()");
		goto END;
	}

	ret = fd;
	fd = -1;

END:
	if (fd >= 0) {
		close(fd);
	}

	return ret;
}

static void install_signal_handlers (void) {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_parent_alarm; // used to wake up from accept()
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_exit_signal;
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &sa, NULL);
}

static bool parse_argv (const int argc, const char **argv) {
#define RETURN_ERROR_OPT(s) {\
	errno = EINVAL; \
	fprintf(stderr, s" ");\
	perror(optarg);\
	return false;\
}
	int c;
	uint16_t port = 0;

	do {
		c = getopt(argc, (char*const*)argv, "hVl:p:m:DP:H:S:TC:");

		switch (c) {
		case -1: break;
		case '?': return false;
		case 'h': param.opts.help = true; break;
		case 'V': param.opts.version = true; break;
		case 'D': param.opts.daemon = true; break;
		case 'T': param.opts.mtu1280 = true; break;
		case 'p':
			if (sscanf(optarg, "%"SCNu16, &port) != 1 || port == 0) {
				RETURN_ERROR_OPT("-p");
			}
			break;
		case 'l':
			// TODO: use getaddrinfo() to support scope_id spec for link-local addresses?
			if (strlen(optarg) == 0) {
				// an empty address is treated as ANY by many platforms
				break;
			}
			else if (inet_pton(AF_INET, optarg, &param.listen.v4.sin_addr)) {
				param.listen.sa.sa_family = AF_INET;
				break;
			}
			else if (inet_pton(AF_INET6, optarg, &param.listen.v6.sin6_addr)) {
				param.listen.sa.sa_family = AF_INET6;
				break;
			}
			else {
				RETURN_ERROR_OPT("-l");
			}
			break;
		case 'm':
			if (sscanf(optarg, "%zu", &param.max_con) != 1 || param.max_con == 0) {
				RETURN_ERROR_OPT("-m");
			}
			break;
		case 'P':
			param.pid_file = optarg;
			break;
		case 'H':
			strncpy(param.hostname, optarg, sizeof(param.hostname) - 1);
			break;
		case 'S':
			if (sscanf(optarg, "%d", &param.sck_buf_size) != 1 ||
					param.sck_buf_size < 0)
			{
				RETURN_ERROR_OPT("-S");
			}
			break;
		case 'C':
			strncpy(param.contact, optarg, sizeof(param.contact) - 1);
			break;
		default: abort();
		}
	} while (c >= 0);

	if (port > 0) {
		if (param.listen.sa.sa_family == AF_INET) {
			param.listen.v4.sin_port = htons(port);
		}
		else if (param.listen.sa.sa_family == AF_INET6) {
			param.listen.v6.sin6_port = htons(port);
		}
		else {
			abort();
		}
	}

	if (optind < argc) {
		fprintf(stderr, ARGV0": too many arguments\n");
		return false;
	}

	return true;
#undef RETURN_ERROR_OPT
}

static void do_param_sanity_check (void) {
	// nothing to do as of yet
}

static bool do_pid_file (void) {
	bool ret = false;
	FILE *f = NULL;
	long pid = 0;

	if (param.pid_file == NULL || param.pid_file[0] == 0) {
		return true;
	}

	f = fopen(param.pid_file, "r");
	if (f != NULL) {
		fseek(f, 0, SEEK_SET);
		if (fscanf(f, "%ld", &pid) == 1) {
			if (kill(pid, 0) == 0) {
				errno = EEXIST;
				goto END;
			}
		}
		fclose(f);
	}

	f = fopen(param.pid_file, "w");
	if (f == NULL) {
		return false;
	}

	pid = (long)getpid();
	ret = fprintf(f, "%ld\n", pid) > 0;

END:
	if (f != NULL) {
		fclose(f);
	}

	return ret;
}

int main (const int argc, const char **argv) {
	int ec = 1;

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
	install_signal_handlers();

	server.fd = mk_main_socket();
	if (server.fd < 0) {
		goto END;
	}

	if (param.opts.daemon) {
		const pid_t child = fork();

		if (child == 0) {
			if (do_pid_file()) {
				ec = do_serve();
			}
			else {
				perror("Could not create PID file");
			}
		}
		else if (child < 0) {
			perror("Failed to daemonize");
		}
		else {
			ec = 0;
		}
	}
	else {
		if (do_pid_file()) {
			ec = do_serve();
		}
		else {
			perror("Could not create PID file");
		}
	}

END:
	deinit_global();
	return ec;
}
