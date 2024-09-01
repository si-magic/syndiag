#pragma once
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define CHK_CLOSE(x) if ((x) >= 0) { close((x)); }
// #ifndef MIN
// #define MIN(a,b) (((a)<(b))?(a):(b))
// #endif
// #ifndef MAX
// #define MAX(a,b) (((a)>(b))?(a):(b))
// #endif

const char *our_inet_ntop (
	const struct sockaddr *in_addr,
	char *out,
	const size_t size);
bool setsockopt_int (
	const int fd,
	const int level,
	const int opt,
	const int v);
bool getsockopt_int (
	const int fd,
	const int level,
	const int opt,
	int *v,
	socklen_t *sl);
bool get_tcp_repair_window (
	const int fd,
	struct tcp_repair_window *trw,
	socklen_t *sl);
bool get_tcp_info (const int fd, struct tcp_info *ti, socklen_t *sl);
bool test_tcp_repair_window (const int fd, FILE *f, const char *tag_in);
// IPv6 max str addr len + square brackets + colon + port number
#define INET_EP_ADDRSTRLEN (INET6_ADDRSTRLEN + 8)
char *inet_ep_ntop (const struct sockaddr *in_addr, void *out, const size_t size);
int print_version (FILE *out);
bool setnonblock (const int fd, const bool onoff);
unsigned int read_urand (void);
