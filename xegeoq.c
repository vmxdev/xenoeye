/*
 * Copyright (c) 2023, Vladimir Misyurov
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <sys/mman.h>

#include "xenoeye.h"
#include "geoip.h"
#include "ip-btrie.h"

/* geo */
static struct btrie_node_geo * _Atomic _geodb4 = NULL;
static size_t _geo4size = 0;
static struct btrie_node_geo * _Atomic _geodb6 = NULL;
static size_t _geo6size = 0;

/* as */
static struct btrie_node_as * _Atomic _asdb4 = NULL;
static size_t _as4size = 0;
static struct btrie_node_as * _Atomic _asdb6 = NULL;
static size_t _as6size = 0;


/* geo */
int
geoip_lookup4(uint32_t addr, struct geoip_info **g)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;
	struct btrie_node_geo *geo4 = atomic_load_explicit(&_geodb4,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(geo4, 4 * 8);

	*g = &geo4[node].g;

	return 1;
}

int
geoip_lookup6(xe_ip *addr, struct geoip_info **g)
{
	uint8_t *addr_ptr = (uint8_t *)addr;
	struct btrie_node_geo *geo6 = atomic_load_explicit(&_geodb6,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(geo6, 16 * 8);

	*g = &geo6[node].g;

	return 1;
}

/* as */
int
as_lookup4(uint32_t addr, struct as_info **a)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;
	struct btrie_node_as *as4 = atomic_load_explicit(&_asdb4,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(as4, 4 * 8);

	*a = &as4[node].a;

	return 1;
}

int
as_lookup6(xe_ip *addr, struct as_info **a)
{
	uint8_t *addr_ptr = (uint8_t *)addr;
	struct btrie_node_as *as6 = atomic_load_explicit(&_asdb6,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(as6, 16 * 8);

	*a = &as6[node].a;

	return 1;
}


static void *
mmap_db(const char *dbdir, const char *dbname, size_t *size)
{
	void *addr = NULL;
	struct stat st;
	int fd;

	char path[PATH_MAX + 8];

	*size = 0;
	sprintf(path, "%s/%s.db", dbdir, dbname);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		LOG("Can't open file '%s': %s", path, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) != 0) {
		LOG("fstat() failed on file '%s': %s", path, strerror(errno));
		goto fail_fstat;
	}

	*size = st.st_size;
	addr = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == (void *) -1) {
		LOG("mmap() failed on file '%s': %s", path, strerror(errno));
		addr = NULL;
		goto fail_mmap;
	}

fail_fstat:
fail_mmap:
	close(fd);

	return addr;
}

static void
print_info4(const char *addr, uint32_t ip4)
{
	struct geoip_info *g;
	struct as_info *a;

	if (!geoip_lookup4(ip4, &g)) {
		LOG("%s geo: ?", addr);
	} else {
		LOG("%s geo: %s, %s, %s, %s, %s, %s, %s, %s", addr,
			g->CONTINENT, g->COUNTRY_CODE,
			g->COUNTRY, g->STATE, g->CITY, g->ZIP,
			g->LAT, g->LONG);
	}

	if (!as_lookup4(ip4, &a)) {
		LOG("%s as: ?", addr);
	} else {
		LOG("%s as: %u, %s", addr, htobe32(a->asn), a->asd);
	}
}

static void
print_info6(const char *addr, xe_ip *ip6)
{
	struct geoip_info *g;
	struct as_info *a;

	if (!geoip_lookup6(ip6, &g)) {
		LOG("%s geo: ?", addr);
	} else {
		LOG("%s geo: %s, %s, %s, %s, %s, %s, %s, %s", addr,
			g->CONTINENT, g->COUNTRY_CODE,
			g->COUNTRY, g->STATE, g->CITY, g->ZIP,
			g->LAT, g->LONG);
	}

	if (!as_lookup6(ip6, &a)) {
		LOG("%s as: ?", addr);
	} else {
		LOG("%s as: %u, %s", addr, htobe32(a->asn), a->asd);
	}
}

static void
print_usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s [-i db_dir] ip_addr1 [ip_addr2 ...]\n", progname);
	fprintf(stderr, "\t-i /path/to/dir: where GeoIP/AS databases are placed\n");
	fprintf(stderr, "\tip_addr1, ip_addr2, etc.: IPv4 or IPv6 addresses to lookup\n");
	fprintf(stderr, "\n %s -h\n", progname);
	fprintf(stderr, "\t-h: print this message\n");
}


int
main(int argc, char *argv[])
{
	int opt, i;
	char in_dir[PATH_MAX] = "./"; /* current dir by default */

	openlog(NULL, LOG_PERROR, LOG_USER);

	while ((opt = getopt(argc, argv, "hi:")) != -1) {
		switch (opt) {
			case 'i':
				strcpy(in_dir, optarg);
				break;

			case 'h':
			default:
				print_usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (optind == argc) {
		LOG("No input files");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* create mappings */
	_geodb4 = mmap_db(in_dir, "geo4", &_geo4size);
	_geodb6 = mmap_db(in_dir, "geo6", &_geo6size);
	_asdb4 = mmap_db(in_dir, "as4", &_as4size);
	_asdb6 = mmap_db(in_dir, "as6", &_as6size);

	for (i=optind; i<argc; i++) {
		struct in_addr ip4;
		xe_ip ip6;

		char *addr = argv[i];

		if (inet_pton(AF_INET6, addr, &ip6) == 0) {
			/* can't parse as IPv6, so it's probably IPv4 */
			if (inet_aton(addr, &ip4) == 0) {
				LOG("Can't parse address '%s'", addr);
				continue;
			}
			print_info4(addr, ip4.s_addr);
		} else {
			/* IPv6 */
			print_info6(addr, &ip6);
		}
	}

	/* remove mappings */
#define UNMAP(X, S)                                                            \
do {                                                                           \
	if (X) {                                                               \
		if (munmap(X, S) != 0) {                                       \
			LOG("munmap() failed: %s", strerror(errno));           \
		}                                                              \
	}                                                                      \
} while (0)

	UNMAP(_geodb4, _geo4size);
	UNMAP(_geodb6, _geo6size);
	UNMAP(_asdb4, _as4size);
	UNMAP(_asdb6, _as6size);
#undef UNMAP

	return EXIT_SUCCESS;
}

