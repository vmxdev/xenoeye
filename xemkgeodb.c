/*
 * Copyright (c) 2023-2025, Vladimir Misyurov
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
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include "geoip.h"
#include "ip-btrie.h"

#define GEOIP_SIGN_IPAPI "ip_version,start_ip,end_ip,continent,country_code,"\
	"country,state,city,zip,timezone,latitude,longitude,accuracy"

#define GEOIP_SIGN_RKN_LOC "geoname_id,locale_code,continent_code,"\
	"continent_name,country_iso_code,country_name,subdivision_1_iso_code,"\
	"subdivision_1_name,subdivision_2_iso_code,subdivision_2_name,"\
	"city_name,metro_code,time_zone,is_in_european_union"

#define GEOIP_SIGN_RKN_DATA "network,geoname_id,registered_country_geoname_id,"\
	"represented_country_geoname_id,is_anonymous_proxy,"\
	"is_satellite_provider,postal_code,latitude,longitude,accuracy_radius,"\
	"is_anycast"

#define AS_SIGN_RKN "network,autonomous_system_number,"\
	"autonomous_system_organization"

struct rkn_loc
{
	int id;
	char continent_code[3];
	char country_code[3];
	char country[128];
	char state[128];
	char city[128];
};

static int verbose = 0;

static int
geodb_add4(struct btrie_node_geo *db, size_t *db_size,
	uint32_t addr, int mask, struct geoip_info *g)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD_MMAP(db, *db_size, btrie_node_geo);

	db[node].g = *g;
	return 1;
}

static int
geodb_add6(struct btrie_node_geo *db, size_t *db_size,
	xe_ip addr, int mask, struct geoip_info *g)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD_MMAP(db, *db_size, btrie_node_geo);

	db[node].g = *g;
	return 1;
}

/* as */
static int
asdb_add4(struct btrie_node_as *db, size_t *db_size,
	uint32_t addr, int mask, struct as_info *a)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD_MMAP(db, *db_size, btrie_node_as);

	db[node].a = *a;
	return 1;
}

static int
asdb_add6(struct btrie_node_as *db, size_t *db_size,
	xe_ip addr, int mask, struct as_info *a)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD_MMAP(db, *db_size, btrie_node_as);

	db[node].a = *a;
	return 1;
}


static void
add_range4(struct btrie_node_geo *geodb, size_t *geodb_size,
	struct btrie_node_as *asdb, size_t *asdb_size,
	uint32_t ip1, uint32_t ip2, struct geoip_info *g,
	struct as_info *a)
{
	uint32_t subnet_first, subnet_last, end;

	subnet_first = be32toh(ip1);
	end = be32toh(ip2);

	for (;;) {
		int mask_bits;

		if (subnet_first > end) {
			break;
		} else if (subnet_first == end) {
			if (g) {
				geodb_add4(geodb, geodb_size,
					htobe32(subnet_first), 32, g);
			} else {
				asdb_add4(asdb, asdb_size,
					htobe32(subnet_first), 32, a);
			}
			break;
		}

		if (subnet_first != 0) {
			mask_bits = __builtin_ctz(subnet_first);
			subnet_last = subnet_first + (1 << mask_bits) - 1;
		} else {
			mask_bits = 32;
			subnet_last = subnet_first - 1;
		}

		if (subnet_last == end) {
			if (g) {
				geodb_add4(geodb, geodb_size,
					htobe32(subnet_first),
					32 - mask_bits, g);
			} else {
				asdb_add4(asdb, asdb_size,
					htobe32(subnet_first),
					32 - mask_bits, a);
			}
			break;
		} else if (subnet_last > end) {
			uint32_t diff = end - subnet_first + 1;
			int p =  32 - __builtin_clz(diff) - 1;
			uint32_t ndiff = 1 << p;

			if (g) {
				geodb_add4(geodb, geodb_size,
					htobe32(subnet_first), 32 - p, g);
			} else {
				asdb_add4(asdb, asdb_size,
					htobe32(subnet_first), 32 - p, a);
			}

			subnet_first += ndiff;
		} else {
			if (g) {
				geodb_add4(geodb, geodb_size,
					htobe32(subnet_first),
					32 - mask_bits, g);
			} else {
				asdb_add4(asdb, asdb_size,
					htobe32(subnet_first),
					32 - mask_bits, a);
			}

			subnet_first = subnet_last + 1;
		}
	}
}


inline int
clz_128(xe_ip x)
{
	int count = 0;
	while (!(x & ((xe_ip)1 << (128 - 1)))) {
		x = x << 1;
		count++;
	}
	return count;
}

inline int
ctz_128(xe_ip x)
{
	int count = 0;
	while ((x & 1) == 0) {
		x = x >> 1;
		count++;
	}
	return count;
}

static void
add_range6(struct btrie_node_geo *geodb, size_t *geodb_size,
	struct btrie_node_as *asdb, size_t *asdb_size,
	xe_ip *ip1, xe_ip *ip2, struct geoip_info *g, struct as_info *a)
{
	xe_ip subnet_first, subnet_last, end;

	/* FIXME: check endianess? */
	subnet_first = bswap128(*ip1);
	end = bswap128(*ip2);

	for (;;) {
		int mask_bits;

		if (subnet_first > end) {
			break;
		} else if (subnet_first == end) {
			if (g) {
				geodb_add6(geodb, geodb_size,
					bswap128(subnet_first),
					128, g);
			} else {
				asdb_add6(asdb, asdb_size,
					bswap128(subnet_first),
					128, a);
			}
			break;
		}

		if (subnet_first != 0) {
			mask_bits = ctz_128(subnet_first);
			subnet_last = subnet_first + ((xe_ip)1 << mask_bits)
				- 1;
		} else {
			mask_bits = 128;
			subnet_last = subnet_first - 1;
		}

		if (subnet_last == end) {
			if (g) {
				geodb_add6(geodb, geodb_size,
					bswap128(subnet_first),
					128 - mask_bits, g);
			} else {
				asdb_add6(asdb, asdb_size,
					bswap128(subnet_first),
					128 - mask_bits, a);
			}
			break;
		} else if (subnet_last > end) {
			xe_ip diff = end - subnet_first + 1;
			int p =  128 - clz_128(diff) - 1;
			xe_ip ndiff = (xe_ip)1 << p;

			if (g) {
				geodb_add6(geodb, geodb_size,
					bswap128(subnet_first),
					128 - p, g);
			} else {
				asdb_add6(asdb, asdb_size,
					bswap128(subnet_first),
					128 - p, a);
			}

			subnet_first += ndiff;
		} else {
			if (g) {
				geodb_add6(geodb, geodb_size,
					bswap128(subnet_first),
					128 - mask_bits, g);
			} else {
				asdb_add6(asdb, asdb_size,
					bswap128(subnet_first),
					128 - mask_bits, a);
			}

			subnet_first = subnet_last + 1;
		}
	}
}


/* geo */
static int
process_line_ipapi(struct btrie_node_geo *geodb4, size_t *geodb_size4,
	struct btrie_node_geo *geodb6, size_t *geodb_size6,
	char *line, char *err)
{
	char *lptr = line;

	struct geoip_info g;
	char ip_ver[5];
	char addr1[100], addr2[100];
	char tz[100];
	struct in_addr ip, ip2;
	size_t i;

	memset(&g, 0, sizeof(g));

	csv_next(&lptr, ip_ver);
	csv_next(&lptr, addr1);
	csv_next(&lptr, addr2);
	csv_next(&lptr, g.CONTINENT);
	csv_next(&lptr, g.COUNTRY_CODE);
	csv_next(&lptr, g.COUNTRY);
	csv_next(&lptr, g.STATE);
	csv_next(&lptr, g.CITY);
	csv_next(&lptr, g.ZIP);
	csv_next(&lptr, tz);
	csv_next(&lptr, g.LAT);
	csv_next(&lptr, g.LONG);

	for (i=0; i<strlen(g.CONTINENT); i++) {
		g.CONTINENT[i] = tolower(g.CONTINENT[i]);
	}
	for (i=0; i<strlen(g.COUNTRY_CODE); i++) {
		g.COUNTRY_CODE[i] = tolower(g.COUNTRY_CODE[i]);
	}

	if (strcmp(ip_ver, "6") == 0) {
		/* IPv6 */
		xe_ip ipv6_1, ipv6_2;
		if (inet_pton(AF_INET6, addr1, &ipv6_1) == 0) {
			sprintf(err, "can't parse IPv6 address 1'%s'",
				addr1);
			return 0;
		}
		if (inet_pton(AF_INET6, addr2, &ipv6_2) == 0) {
			sprintf(err, "can't parse IPv6 address 2'%s'",
				addr2);
			return 0;
		}
		add_range6(geodb6, geodb_size6, NULL, NULL,
			&ipv6_1, &ipv6_2, &g, NULL);
	} else {
		/* IPv4 */
		if (inet_aton(addr1, &ip) == 0) {
			sprintf(err, "can't parse IPv4 address 1'%s'",
				addr1);
			return 0;
		}
		if (inet_aton(addr2, &ip2) == 0) {
			sprintf(err, "can't parse IPv4 address 2'%s'",
				addr2);
			return 0;
		}

		add_range4(geodb4, geodb_size4, NULL, NULL,
			ip.s_addr, ip2.s_addr, &g, NULL);
	}
	return 1;
}

static void
geoip_add_file_ipapi(const char *path, FILE *f,
	struct btrie_node_geo *geodb4, size_t *geodb_size4,
	struct btrie_node_geo *geodb6, size_t *geodb_size6)
{
	char line[4096];
	char *line_ptr;
	size_t line_num = 2;

	LOG("geoip: loading ipapi file '%s'", path);
	for (;;) {
		char err[256];

		fgets(line, sizeof(line), f);
		if (feof(f)) {
			break;
		}

		line_ptr = string_trim(line);
		if (!process_line_ipapi(geodb4, geodb_size4,
			geodb6, geodb_size6, line_ptr, err)) {

			LOG("geoip: file '%s', line #%lu: %s", path,
				line_num, err);
		}

		line_num++;
		if (verbose) {
			if ((line_num % 100000) == 0) {
				LOG("geoip: file '%s', %lu lines loaded",
					path, line_num);
			}
		}
	}

	LOG("geoip: ipapi file '%s' added, %lu lines", path, line_num);
}

/* RKN database */
static int
process_line_rkn_loc(struct rkn_loc *lc, char *line, char *err)
{
	char *lptr = line;

	char id[10];
	char locale[10];
	char continent_name[20];
	char unused[256];
	size_t i;

	memset(lc, 0, sizeof(struct rkn_loc));

#define CHECK_PARSE_ERROR(X, F)                           \
	if (X[0] == '\0') {                               \
		sprintf(err, "Can't parse field '%s'", F);\
		return 0; }

	csv_next(&lptr, id);
	CHECK_PARSE_ERROR(id, "geoname_id");
	lc->id = atoi(id);
	if (lc->id < 0) {
		sprintf(err, "incorrect geoid '%s'", id);
		return 0;
	}

	csv_next(&lptr, locale);
	CHECK_PARSE_ERROR(locale, "locale_code");

	csv_next(&lptr, lc->continent_code);
	CHECK_PARSE_ERROR(lc->continent_code, "continent_code");

	csv_next(&lptr, continent_name);
	CHECK_PARSE_ERROR(continent_name, "continent_name");

	csv_next(&lptr, lc->country_code);
	CHECK_PARSE_ERROR(lc->country_code, "country_iso_code");

	csv_next(&lptr, lc->country);
	CHECK_PARSE_ERROR(lc->country, "country_name");

	csv_next(&lptr, unused); /* subdivision_1_iso_code */
	csv_next(&lptr, lc->state);
	csv_next(&lptr, unused); /* subdivision_2_iso_code*/
	csv_next(&lptr, unused); /* subdivision_2_name */

	csv_next(&lptr, lc->city);
	CHECK_PARSE_ERROR(lc->city, "city_name");
#undef CHECK_PARSE_ERROR

	for (i=0; i<strlen(lc->continent_code); i++) {
		lc->continent_code[i] = tolower(lc->continent_code[i]);
	}

	for (i=0; i<strlen(lc->country_code); i++) {
		lc->country_code[i] = tolower(lc->country_code[i]);
	}

	return 1;
}

static void
geoip_add_rkn_loc(const char *path, FILE *f, struct rkn_loc **lcs, size_t *nl)
{
	char line[4096];
	char *line_ptr;
	size_t line_num = 2;

	LOG("geoip: loading RKN locations file '%s'", path);
	for (;;) {
		struct rkn_loc lc;
		char err[256];

		fgets(line, sizeof(line), f);
		if (feof(f)) {
			break;
		}

		line_ptr = string_trim(line);
		if (!process_line_rkn_loc(&lc, line_ptr, err)) {
			LOG("geoip: file '%s', line #%lu: %s", path,
				line_num, err);
		} else {
			/* append new location */
			struct rkn_loc *tmp = realloc(*lcs,
				sizeof(struct rkn_loc) * (*nl + 1));
			if (!tmp) {
				LOG("realloc() failed: %s", strerror(errno));
				return;
			}
			tmp[*nl] = lc;
			*lcs = tmp;
			(*nl)++;
		}
		line_num++;
	}

	LOG("geoip: RKN locations file '%s' loaded, %lu lines", path, line_num);
}

static int
process_line_rkn(struct rkn_loc *lc, size_t nlc,
	struct btrie_node_geo *geodb4, size_t *geodb_size4,
	struct btrie_node_geo *geodb6, size_t *geodb_size6,
	char *line, char *err)
{
	char *lptr = line;
	char *slash;

	struct geoip_info g;

	int geoid;
	char addr[100];
	char unused[256];
	char id[10];

	uint32_t ipv4;
	xe_ip ipv6;

	size_t i;
	int found = 0;
	int mask = -1;

	memset(&g, 0, sizeof(g));

	csv_next(&lptr, addr);

	csv_next(&lptr, id);
	geoid = atoi(id);
	if (geoid < 0) {
		sprintf(err, "incorrect geoid '%s'", id);
		return 0;
	}

	csv_next(&lptr, unused); /* registered_country_geoname_id */
	csv_next(&lptr, unused); /* represented_country_geoname_id */
	csv_next(&lptr, unused); /* is_anonymous_proxy */
	csv_next(&lptr, unused); /* is_satellite_provider */
	csv_next(&lptr, g.ZIP);  /* postal_code */
	csv_next(&lptr, g.LAT);
	csv_next(&lptr, g.LONG);

	for (i=0; i<nlc; i++) {
		if (lc[i].id == geoid) {
			/* found */
			strcpy(g.CONTINENT, lc->continent_code);
			strcpy(g.COUNTRY_CODE, lc->country_code);
			strcpy(g.COUNTRY, lc->country);
			strcpy(g.STATE, lc->state);
			strcpy(g.CITY, lc->city);
			found = 1;
		}
	}

	if (!found) {
		sprintf(err, "unknown geoid '%s'", id);
		return 0;
	}

	slash = strchr(addr, '/');
	if (slash) {
		*slash = '\0';
		slash++;
		mask = atoi(slash);
	}

	if (inet_pton(AF_INET6, addr, &ipv6) == 1) {
		if (mask < 0) {
			mask = 128;
		}
		geodb_add6(geodb6, geodb_size6, ipv6, mask, &g);
	} else {
		/* IPv4? */
		if (inet_pton(AF_INET, addr, &ipv4) != 1) {
			sprintf(err, "Can't parse address '%s'", addr);
			return 0;
		}
		if (mask < 0) {
			mask = 32;
		}
		geodb_add4(geodb4, geodb_size4, ipv4, mask, &g);
	}

	return 1;
}


static void
geoip_add_rkn_blocks(const char *path, FILE *f, struct rkn_loc *lc, size_t nlc,
	struct btrie_node_geo *geodb4, size_t *geodb_size4,
	struct btrie_node_geo *geodb6, size_t *geodb_size6)
{
	char line[4096];
	char *line_ptr;
	size_t line_num = 2;

	LOG("geoip: loading RKN file '%s'", path);
	for (;;) {
		char err[256];

		fgets(line, sizeof(line), f);
		if (feof(f)) {
			break;
		}

		line_ptr = string_trim(line);
		if (!process_line_rkn(lc, nlc, geodb4, geodb_size4,
			geodb6, geodb_size6, line_ptr, err)) {

			LOG("geoip: file '%s', line #%lu: %s", path,
				line_num, err);
		}

		line_num++;
		if (verbose) {
			if ((line_num % 100000) == 0) {
				LOG("geoip: file '%s', %lu lines loaded",
					path, line_num);
			}
		}
	}

	LOG("geoip: RKN file '%s' added, %lu lines", path, line_num);
}


static int
geoip_add_file(struct rkn_loc **rkn_lc, size_t *n_rkn_lc,
	struct btrie_node_geo *geodb4, size_t *geodb_size4,
	struct btrie_node_geo *geodb6, size_t *geodb_size6,
	const char *path)
{
	FILE *f;
	char line[4096];
	int ret = 0;

	f = fopen(path, "r");
	if (!f) {
		LOG("geoip: can't open file '%s': %s", path, strerror(errno));
		return 0;
	}

	/* read first line */
	fgets(line, sizeof(line), f);
	if (feof(f)) {
		LOG("geoip: file '%s' too short", path);
		goto fail;
	}

	if (strcmp(string_trim(line), GEOIP_SIGN_IPAPI) == 0) {
		geoip_add_file_ipapi(path, f, geodb4, geodb_size4,
			geodb6, geodb_size6);
	} else if (strcmp(string_trim(line), GEOIP_SIGN_RKN_LOC) == 0) {
		/* RKN locations */
		geoip_add_rkn_loc(path, f, rkn_lc, n_rkn_lc);
	} else if (strcmp(string_trim(line), GEOIP_SIGN_RKN_DATA) == 0) {
		/* RKN blocks */
		if (!rkn_lc) {
			LOG("geoip: RKN location file must be before "
				"the blocks file");
			goto fail;
		}

		geoip_add_rkn_blocks(path, f, *rkn_lc, *n_rkn_lc,
			geodb4, geodb_size4, geodb6, geodb_size6);
	} else {
		LOG("geoip: file '%s': unknown format", path);
	}

	ret = 1;
fail:
	fclose(f);

	return ret;
}

static int
process_line_as(struct btrie_node_as *asdb4, size_t *asdb_size4,
	struct btrie_node_as *asdb6, size_t *asdb_size6,
	char *line, char *err)
{
	char *lptr = line;

	struct as_info a;
	char addr1[100], addr2[100];
	char asn[10];
	struct in_addr ip, ip2;
	xe_ip ipv6_1, ipv6_2;

	memset(&a, 0, sizeof(a));

	csv_next(&lptr, addr1);
	csv_next(&lptr, addr2);
	csv_next(&lptr, asn);
	csv_next(&lptr, a.asd);

	a.asn = htobe32(atoi(asn));

	if (inet_pton(AF_INET6, addr1, &ipv6_1) == 0) {
		/* can't parse as IPv6, so it's probably IPv4 */
		if (inet_aton(addr1, &ip) == 0) {
			sprintf(err, "can't parse address 1'%s'", addr1);
			return 0;
		}
		if (inet_aton(addr2, &ip2) == 0) {
			sprintf(err, "can't parse address 2'%s'", addr2);
			return 0;
		}
		add_range4(NULL, NULL, asdb4, asdb_size4,
			ip.s_addr, ip2.s_addr, NULL, &a);
	} else {
		/* IPv6 */
		if (inet_pton(AF_INET6, addr2, &ipv6_2) == 0) {
			sprintf(err, "can't parse IPv6 address 2'%s'", addr2);
			return 0;
		}
		add_range6(NULL, NULL, asdb6, asdb_size6,
			&ipv6_1, &ipv6_2, NULL, &a);
	}

	return 1;
}

static int
process_line_as_rkn(struct btrie_node_as *asdb4, size_t *asdb_size4,
	struct btrie_node_as *asdb6, size_t *asdb_size6,
	char *line, char *err)
{
	char *lptr = line;

	struct as_info a;
	char addr[100];
	char asn[10];
	struct in_addr ip;
	xe_ip ipv6;

	char *slash;
	int mask;

	memset(&a, 0, sizeof(a));

	csv_next(&lptr, addr);

	slash = strchr(addr, '/');
	if (!slash) {
		sprintf(err, "net '%s' has not mask", addr);
		return 0;
	}
	*slash = '\0';
	slash++;
	mask = atoi(slash);
	if (mask <= 0) {
		sprintf(err, "inkorrect mask '%s'", slash);
		return 0;
	}

	csv_next(&lptr, asn);
	csv_next(&lptr, a.asd);

	a.asn = htobe32(atoi(asn));

	if (inet_pton(AF_INET6, addr, &ipv6) == 0) {
		/* can't parse as IPv6, so it's probably IPv4 */
		if (inet_aton(addr, &ip) == 0) {
			sprintf(err, "can't parse address '%s'", addr);
			return 0;
		}
		asdb_add4(asdb4, asdb_size4, ip.s_addr, mask, &a);
	} else {
		/* IPv6 */
		asdb_add6(asdb6, asdb_size6, ipv6, mask, &a);
	}

	return 1;
}

static int
as_add_file_rkn(FILE *f, const char *path,
	struct btrie_node_as *asdb4, size_t *asdb_size4,
	struct btrie_node_as *asdb6, size_t *asdb_size6)
{
	char line[4096];
	size_t line_num = 2;
	char *line_ptr;

	for (;;) {
		char err[256];
		fgets(line, sizeof(line), f);
		if (feof(f)) {
			break;
		}

		line_ptr = string_trim(line);
		if (!process_line_as_rkn(asdb4, asdb_size4,
			asdb6, asdb_size6,
			line_ptr, err)) {

			LOG("as: RKN file '%s', line #%lu: %s",
				path, line_num, err);
		}

		line_num++;
		if (verbose) {
			if ((line_num % 100000) == 0) {
				LOG("as: RKN file '%s', %lu lines loaded",
					path, line_num);
			}
		}

	}
	LOG("as: RKN file '%s' added, %lu lines", path, line_num);
	fclose(f);
	return 1;
}

static int
as_add_file(struct btrie_node_as *asdb4, size_t *asdb_size4,
	struct btrie_node_as *asdb6, size_t *asdb_size6,
	const char *path)
{
	FILE *f;
	char line[4096];
	size_t line_num = 1;
	char *line_ptr;
	int ret = 0;

	f = fopen(path, "r");
	if (!f) {
		LOG("as: can't open file '%s': %s", path, strerror(errno));
		return 0;
	}

	LOG("as: loading file '%s'", path);
	/* read first line */
	fgets(line, sizeof(line), f);
	if (feof(f)) {
		LOG("as: file '%s' too short", path);
		goto fail;
	}

	if (strcmp(string_trim(line), AS_SIGN_RKN) == 0) {
		return as_add_file_rkn(f, path, asdb4, asdb_size4,
			asdb6, asdb_size6);
	}

	for (;;) {
		char err[256];

		line_ptr = string_trim(line);
		if (!process_line_as(asdb4, asdb_size4,
			asdb6, asdb_size6,
			line_ptr, err)) {

			LOG("as: file '%s', line #%lu: %s",
				path, line_num, err);
		}

		line_num++;
		if (verbose) {
			if ((line_num % 100000) == 0) {
				LOG("as: file '%s', %lu lines loaded",
					path, line_num);
			}
		}

		fgets(line, sizeof(line), f);
		if (feof(f)) {
			break;
		}
	}

	LOG("as: file '%s' added, %lu lines", path, line_num);
	ret = 1;

fail:
	fclose(f);

	return ret;
}



static void
print_usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s [-o out_dir] [-s max_file_size] [-v] -t type "
		"dbfile1.csv [dbfile2.csv ...]\n",
		progname);
	fprintf(stderr, "\t-o /path/to/dir: where output files will be placed\n");
	fprintf(stderr, "\t-s max_file_size: max size (in megabytes)"
		" of a single result file\n");
	fprintf(stderr, "\t-v show message on each 100000 lines loaded\n");
	fprintf(stderr, "\t-t geo: data files of GeoIP\n");
	fprintf(stderr, "\t-t as: data files of AS info\n");
	fprintf(stderr, "\tdbfile1.csv, dbfile2.csv, etc.: data files\n");
	fprintf(stderr, "\n %s -h\n", progname);
	fprintf(stderr, "\t-h: print this message\n");
}

static void *
make_cache(const char *cache, off_t max_size)
{
	void *addr = NULL;
	int fd;

	fd = open(cache, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		LOG("Can't open cache file '%s': %s", cache, strerror(errno));
		goto fail_open;
		return NULL;
	}

	if (ftruncate(fd, max_size) != 0) {
		LOG("ftruncate() failed on file '%s': %s",
			cache, strerror(errno));
		goto fail_trunc;
	}

	addr = mmap(NULL, max_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == (void *) -1) {
		LOG("mmap() failed on file '%s': %s", cache, strerror(errno));
		addr = NULL;
		goto fail_mmap;
	}

fail_mmap:
fail_trunc:
	close(fd);

fail_open:
	return addr;
}


int
main(int argc, char *argv[])
{
	int opt, i;
	char out_dir[PATH_MAX] = "./"; /* current dir by default */
	char type[10] = "";
	int max_size_m = 4*1024; /* 4G by default */
	size_t max_size;
	void *db4, *db6;
	size_t db4_size, db6_size;
	char path4[PATH_MAX + 32], path6[PATH_MAX + 32];

	/* RKN db locations */
	struct rkn_loc *rkn_lc = NULL;
	size_t n_rkn_lc = 0;

	openlog(NULL, LOG_PERROR, LOG_USER);

	while ((opt = getopt(argc, argv, "ho:s:t:v")) != -1) {
		switch (opt) {
			case 'o':
				strcpy(out_dir, optarg);
				break;

			case 's':
				max_size_m = atoi(optarg);
				if (max_size_m <= 0) {
					LOG("Incorrect value for"
						" max file size '%s'", optarg);
					print_usage(argv[0]);
					return EXIT_FAILURE;
				}
				break;

			case 't':
				strcpy(type, optarg);
				break;

			case 'v':
				verbose = 1;
				break;

			case 'h':
			default:
				print_usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	max_size = (size_t)max_size_m * 1024 * 1024;

	if (type[0] == '\0') {
		LOG("Type ('geo' or 'as') not specified");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if ((strcmp(type, "geo") != 0) && (strcmp(type, "as") != 0)) {
		LOG("Unknown type '%s', should be 'geo' or 'as'", type);
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (optind == argc) {
		LOG("No input files");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}


	sprintf(path4, "%s/%s4.db", out_dir, type);
	db4 = make_cache(path4, max_size);
	if (!db4) {
		return EXIT_FAILURE;
	}

	sprintf(path6, "%s/%s6.db", out_dir, type);
	db6 = make_cache(path6, max_size);
	if (!db6) {
		return EXIT_FAILURE;
	}

	db4_size = db6_size = 0;
	for (i=optind; i<argc; i++) {
		char *filename;

		filename = argv[i];
		if (strcmp(type, "geo") == 0) {
			geoip_add_file(&rkn_lc, &n_rkn_lc,
				db4, &db4_size, db6, &db6_size, filename);
		} else {
			as_add_file(db4, &db4_size, db6, &db6_size, filename);
		}
	}

	munmap(db4, max_size);
	munmap(db6, max_size);

	if (strcmp(type, "geo") == 0) {
		truncate(path4, db4_size * sizeof(struct btrie_node_geo));
		truncate(path6, db6_size * sizeof(struct btrie_node_geo));
	} else {
		truncate(path4, db4_size * sizeof(struct btrie_node_as));
		truncate(path6, db6_size * sizeof(struct btrie_node_as));
	}

	free(rkn_lc);

	return EXIT_SUCCESS;
}

