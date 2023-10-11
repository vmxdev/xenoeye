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

#include "geoip.h"
#include "ip-btrie.h"

#define GEOIP_SIGN_IPAPI "ipVersion,network,continent,country_code,country,"\
	"state,city,zip,timezone,latitude,longitude,accuracy"

enum GEO_FILE
{
	GEO_FILE_UNKNOWN,
	GEO_FILE_IPAPI
};

struct btrie_node
{
	uint32_t next[2];
	int  is_leaf;
	struct geoip_info g;
};

struct btrie_node_as
{
	uint32_t next[2];
	int  is_leaf;
	struct as_info a;
};

/* geo */
static struct btrie_node *geodb4 = NULL;
static size_t geodb4_size = 0;

static struct btrie_node *geodb6 = NULL;
static size_t geodb6_size = 0;

/* as */
static struct btrie_node_as *asdb4 = NULL;
static size_t asdb4_size = 0;

static struct btrie_node_as *asdb6 = NULL;
static size_t asdb6_size = 0;

/* geo */
static int
geodb_add4(uint32_t addr, int mask, struct geoip_info *g)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD(geodb4, geodb4_size, btrie_node);

	geodb4[node].g = *g;
	return 1;
}

static int
geodb_add6(xe_ip addr, int mask, struct geoip_info *g)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD(geodb6, geodb6_size, btrie_node);

	geodb6[node].g = *g;
	return 1;
}

/* as */
static int
asdb_add4(uint32_t addr, int mask, struct as_info *a)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD(asdb4, asdb4_size, btrie_node_as);

	asdb4[node].a = *a;
	return 1;
}

static int
asdb_add6(xe_ip addr, int mask, struct as_info *a)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_ADD(asdb6, asdb6_size, btrie_node_as);

	asdb6[node].a = *a;
	return 1;
}

/* geo */
int
geoip_lookup4(uint32_t addr, struct geoip_info **g)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_LOOKUP(geodb4, 4 * 8);

	*g = &geodb4[node].g;

	return 1;
}

int
geoip_lookup6(xe_ip *addr, struct geoip_info **g)
{
	uint8_t *addr_ptr = (uint8_t *)addr;

	IP_BTRIE_LOOKUP(geodb6, 16 * 8);

	*g = &geodb6[node].g;

	return 1;
}

/* as */
int
as_lookup4(uint32_t addr, struct as_info **a)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;

	IP_BTRIE_LOOKUP(asdb4, 4 * 8);

	*a = &asdb4[node].a;

	return 1;
}

int
as_lookup6(xe_ip *addr, struct as_info **a)
{
	uint8_t *addr_ptr = (uint8_t *)addr;

	IP_BTRIE_LOOKUP(asdb6, 16 * 8);

	*a = &asdb6[node].a;

	return 1;
}

static void
add_range4(uint32_t ip1, uint32_t ip2, struct geoip_info *g,
	struct as_info *a)
{
	uint32_t subnet_first, subnet_last, end;

	subnet_first = be32toh(ip1);
	end = be32toh(ip2);

	for (;;) {
		if (subnet_first > end) {
			break;
		} else if (subnet_first == end) {
			if (g) {
				geodb_add4(htobe32(subnet_first), 32, g);
			} else {
				asdb_add4(htobe32(subnet_first), 32, a);
			}
			break;
		}

		int mask_bits = __builtin_ctz(subnet_first);
		subnet_last = subnet_first + (1 << mask_bits) - 1;

		if (subnet_last == end) {
			if (g) {
				geodb_add4(htobe32(subnet_first),
					32 - mask_bits, g);
			} else {
				asdb_add4(htobe32(subnet_first),
					32 - mask_bits, a);
			}
			break;
		} else if (subnet_last > end) {
			uint32_t diff = end - subnet_first + 1;
			int p =  32 - __builtin_clz(diff) - 1;
			uint32_t ndiff = 1 << p;

			if (g) {
				geodb_add4(htobe32(subnet_first), 32 - p, g);
			} else {
				asdb_add4(htobe32(subnet_first), 32 - p, a);
			}

			subnet_first += ndiff;
		} else {
			if (g) {
				geodb_add4(htobe32(subnet_first),
					32 - mask_bits, g);
			} else {
				asdb_add4(htobe32(subnet_first),
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
add_range6(xe_ip *ip1, xe_ip *ip2, struct geoip_info *g, struct as_info *a)
{
	xe_ip subnet_first, subnet_last, end;

	/* FIXME: check endianess? */
	subnet_first = __builtin_bswap128(*ip1);
	end = __builtin_bswap128(*ip2);

	for (;;) {
		if (subnet_first > end) {
			break;
		} else if (subnet_first == end) {
			if (g) {
				geodb_add6(__builtin_bswap128(subnet_first),
					128, g);
			} else {
				asdb_add6(__builtin_bswap128(subnet_first),
					128, a);
			}
			break;
		}

		int mask_bits = ctz_128(subnet_first);
		subnet_last = subnet_first + ((xe_ip)1 << mask_bits) - 1;

		if (subnet_last == end) {
			if (g) {
				geodb_add6(__builtin_bswap128(subnet_first),
					128 - mask_bits, g);
			} else {
				asdb_add6(__builtin_bswap128(subnet_first),
					128 - mask_bits, a);
			}
			break;
		} else if (subnet_last > end) {
			xe_ip diff = end - subnet_first + 1;
			int p =  128 - clz_128(diff) - 1;
			xe_ip ndiff = (xe_ip)1 << p;

			if (g) {
				geodb_add6(__builtin_bswap128(subnet_first),
					128 - p, g);
			} else {
				asdb_add6(__builtin_bswap128(subnet_first),
					128 - p, a);
			}

			subnet_first += ndiff;
		} else {
			if (g) {
				geodb_add6(__builtin_bswap128(subnet_first),
					128 - mask_bits, g);
			} else {
				asdb_add6(__builtin_bswap128(subnet_first),
					128 - mask_bits, a);
			}

			subnet_first = subnet_last + 1;
		}
	}
}

/* geo */
static int
process_line_ipapi(char *line, char *err)
{
	char *lptr = line;

	struct geoip_info g;
	char ip_ver[5];
	char addr[100], addr1[100], addr2[100];
	char tz[100];
	char *maskpos;
	int mask;
	struct in_addr ip, ip2;
	size_t i;

	memset(&g, 0, sizeof(g));
	csv_next(&lptr, ip_ver);
	csv_next(&lptr, addr);
	csv_next(&lptr, g.CONTINENT);
	csv_next(&lptr, g.COUNTRY);
	csv_next(&lptr, g.COUNTRY_FULL);
	csv_next(&lptr, g.STATE);
	csv_next(&lptr, g.CITY);
	csv_next(&lptr, g.ZIP);
	csv_next(&lptr, tz);
	csv_next(&lptr, g.LAT);
	csv_next(&lptr, g.LONG);

	for (i=0; i<strlen(g.CONTINENT); i++) {
		g.CONTINENT[i] = tolower(g.CONTINENT[i]);
	}
	for (i=0; i<strlen(g.COUNTRY); i++) {
		g.COUNTRY[i] = tolower(g.COUNTRY[i]);
	}

	if (strcmp(ip_ver, "ipv6") == 0) {
		xe_ip ipv6_1, ipv6_2;
		if (strchr(addr, '-')) {
			/* range */
			sscanf(addr, "%s - %s", addr1, addr2);

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
			add_range6(&ipv6_1, &ipv6_2, &g, NULL);
		} else {
			/* single network */
			maskpos = strchr(addr, '/');
			if (maskpos) {
				mask = atoi(maskpos + 1);
				*maskpos = '\0';
			} else {
				mask = 128;
			}
			if (inet_pton(AF_INET6, addr, &ipv6_1) == 0) {
				sprintf(err, "can't parse IPv6 address '%s'",
					addr);
				return 0;
			}
			geodb_add6(ipv6_1, mask, &g);
		}
	} else {
		/* ipv4 */
		if (strchr(addr, '-')) {
			/* range */
			sscanf(addr, "%s - %s", addr1, addr2);

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

			add_range4(ip.s_addr, ip2.s_addr, &g, NULL);
		} else {
			/* single network */
			maskpos = strchr(addr, '/');
			if (maskpos) {
				mask = atoi(maskpos + 1);
				*maskpos = '\0';
			} else {
				mask = 32;
			}
			if (inet_aton(addr, &ip) == 0) {
				sprintf(err, "can't parse IPv4 address '%s'",
					addr);
				return 0;
			}
			geodb_add4(ip.s_addr, mask, &g);
		}
	}
	return 1;
}

int
geoip_add_file(const char *path)
{
	FILE *f;
	char line[4096];
	char *line_ptr;
	size_t line_num = 2;
	enum GEO_FILE type = GEO_FILE_UNKNOWN;

	f = fopen(path, "r");
	if (!f) {
		LOG("geoip: can't open file '%s': %s", path, strerror(errno));
		return 0;
	}

	/* skip first line */
	fgets(line, sizeof(line), f);
	if (feof(f)) {
		LOG("geoip: file '%s' too short", path);
		return 0;
	}

	if (strcmp(string_trim(line), GEOIP_SIGN_IPAPI) == 0) {
		type = GEO_FILE_IPAPI;
	} else {
		LOG("geoip: file '%s': unknown format", path);
		goto fail_format;
	}

	LOG("geoip: loading file '%s'", path);
	for (;;) {
		char err[256];

		fgets(line, sizeof(line), f);
		if (feof(f)) {
			break;
		}

		line_ptr = string_trim(line);
		switch (type) {
			case GEO_FILE_IPAPI:
				if (!process_line_ipapi(line_ptr, err)) {
					LOG("geoip: file '%s', line #%lu: %s",
						path, line_num, err);
				}
				break;
			default:
				break;
		}

		line_num++;
	}

	LOG("geoip: file '%s' added, tree has %lu items (%lu bytes)",
		path, geodb4_size + geodb6_size,
		(geodb4_size + geodb6_size) * sizeof(struct btrie_node));

fail_format:
	fclose(f);

	return 1;
}

static int
process_line_as(char *line, char *err)
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
		/* probably IPv4 */
		if (inet_aton(addr1, &ip) == 0) {
			sprintf(err, "can't parse address 1'%s'", addr1);
			return 0;
		}
		if (inet_aton(addr2, &ip2) == 0) {
			sprintf(err, "can't parse address 2'%s'", addr2);
			return 0;
		}
		add_range4(ip.s_addr, ip2.s_addr, NULL, &a);
	} else {
		/* IPv6 */
		if (inet_pton(AF_INET6, addr2, &ipv6_2) == 0) {
			sprintf(err, "can't parse IPv6 address 2'%s'", addr2);
			return 0;
		}
		add_range6(&ipv6_1, &ipv6_2, NULL, &a);
	}

	return 1;
}
int
as_add_file(const char *path)
{
	FILE *f;
	char line[4096];
	size_t line_num = 1;
	char *line_ptr;

	f = fopen(path, "r");
	if (!f) {
		LOG("as: can't open file '%s': %s", path, strerror(errno));
		return 0;
	}

	LOG("as: loading file '%s'", path);
	for (;;) {
		char err[256];
		fgets(line, sizeof(line), f);
		if (feof(f)) {
			break;
		}

		line_ptr = string_trim(line);
		if (!process_line_as(line_ptr, err)) {
			LOG("as: file '%s', line #%lu: %s",
				path, line_num, err);
		}

		line_num++;
	}

	LOG("as: file '%s' added, tree has %lu items (%lu bytes)",
		path, asdb4_size + asdb6_size,
		(asdb4_size + asdb6_size) * sizeof(struct btrie_node_as));

	fclose(f);

	return 1;
}

