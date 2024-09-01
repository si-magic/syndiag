#ifdef NDEBUG
// I want assert() in release builds as well
#undef NDEBUG
#endif
#include "util.h"
#include <string.h>
#include <assert.h>

_Static_assert(INET_EP_ADDRSTRLEN >= INET6_ADDRSTRLEN);

int main (void) {
	static char *ntop_ret;
	static char buf[INET_EP_ADDRSTRLEN];
	static union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr;
	static const uint8_t MAPPED_V4[] = {
		// ::ffff:255.255.255.255
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	static const uint8_t END_OF_WORLD[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff
	};
	static const char END_OF_WORLD_STR[] =
		"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535";
	_Static_assert(sizeof(END_OF_WORLD_STR) <= sizeof(buf));
	_Static_assert(sizeof(MAPPED_V4) == 16);
	_Static_assert(sizeof(END_OF_WORLD) == 16);

	// no mapped v4 BS
	memset(&addr, 0, sizeof(addr));
	addr.v6.sin6_family = AF_INET6;
	memcpy(&addr.v6.sin6_addr, MAPPED_V4, sizeof(MAPPED_V4));
	ntop_ret = (char*)our_inet_ntop(&addr.sa, buf, sizeof(buf));
	assert(ntop_ret == buf);
	assert(strcmp(ntop_ret, "255.255.255.255") == 0);

	// inet_ep_ntop short buffer edge cases
	memset(&addr, 0, sizeof(addr));
	addr.v6.sin6_family = AF_INET6;
	memcpy(&addr.v6.sin6_addr, END_OF_WORLD, sizeof(END_OF_WORLD));
	addr.v6.sin6_port = 65535; // same in both big-endian and little-endian!
	addr.v6.sin6_scope_id = 4294967295;
	// one: tight buffer
	ntop_ret = inet_ep_ntop(&addr.sa, buf, sizeof(END_OF_WORLD_STR));
	assert(ntop_ret == buf);
	assert(strcmp(ntop_ret, END_OF_WORLD_STR) == 0);
	// two: one short
	ntop_ret = inet_ep_ntop(
		&addr.sa,
		buf,
		sizeof(END_OF_WORLD_STR) - 1);
	assert(ntop_ret == NULL);

	return 0;
}
