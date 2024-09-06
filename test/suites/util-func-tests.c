#ifdef NDEBUG
// I want assert() in release builds as well
#undef NDEBUG
#endif
#include "util.h"
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

static_assert(INET_EP_ADDRSTRLEN >= INET6_ADDRSTRLEN);

static void test_inet (void) {
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
	static_assert(sizeof(END_OF_WORLD_STR) <= sizeof(buf));
	static_assert(sizeof(MAPPED_V4) == 16);
	static_assert(sizeof(END_OF_WORLD) == 16);

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
}

static void test_ismemzero (void) {
#define M_UNALIGNED_SIZE (4095)
#define M_ALIGNED_SIZE (4096)
	size_t i, j;
	// assume that the linker will aligned this for us
	static char m_aligned[M_ALIGNED_SIZE];
	// well, for this one, we'll have to do it ourselves
	char *m_unaligned = mmap(
		NULL,
		M_UNALIGNED_SIZE + 1,
		PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1,
		0);

	assert(m_unaligned != MAP_FAILED);
	m_unaligned += 1;
	assert((uintptr_t)m_unaligned % sizeof(uintptr_t) != 0);

	memset(m_aligned, 0, M_ALIGNED_SIZE);
	memset(m_unaligned, 0, M_UNALIGNED_SIZE);

	for (i = 0; i < M_ALIGNED_SIZE; i += 1) {
		for (j = i; j < M_ALIGNED_SIZE; j += 1) {
			assert(ismemzero(m_aligned + j, M_ALIGNED_SIZE - j));
		}
	}
	for (i = 0; i < M_UNALIGNED_SIZE; i += 1) {
		for (j = i; j < M_UNALIGNED_SIZE; j += 1) {
			assert(ismemzero(m_unaligned + j, M_UNALIGNED_SIZE - j));
		}
	}

	memset(m_aligned, 0, M_ALIGNED_SIZE);
	memset(m_unaligned, 0, M_UNALIGNED_SIZE);
	m_aligned[M_ALIGNED_SIZE - 1] = 1;
	m_unaligned[M_UNALIGNED_SIZE - 1] = 1;

	for (i = 0; i < M_ALIGNED_SIZE; i += 1) {
		assert(!ismemzero(m_aligned + i, M_ALIGNED_SIZE - i));
	}
	for (i = 0; i < M_UNALIGNED_SIZE; i += 1) {
		assert(!ismemzero(m_unaligned + i, M_UNALIGNED_SIZE - i));
	}

	munmap(m_unaligned, M_UNALIGNED_SIZE);
}

int main (void) {
	test_inet();
	test_ismemzero();

	return 0;
}
