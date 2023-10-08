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

static struct btrie_node *geodb4 = NULL;
static size_t geodb4_size = 0;

static struct btrie_node *geodb6 = NULL;
static size_t geodb6_size = 0;

static int
geodb_add4(uint32_t addr, int mask, struct geoip_info *g)
{
	int i;
	uint32_t node, next;
	uint8_t *addr_ptr = (uint8_t *)&addr;

	if (!geodb4) {
		/* empty database */
		geodb4 = calloc(1, sizeof(struct btrie_node));
		if (!geodb4) {
			LOG("Not enough memory");
			return 0;
		}
		geodb4_size = 1;
	}

	node = 0;

	for (i=0; i<mask; i++) {
		struct btrie_node *tmp;
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = geodb4[node].next[bit];
		if (next) {
			node = next;
			continue;
		}

		tmp = realloc(geodb4,
			(geodb4_size + 1) * sizeof(struct btrie_node));

		if (!tmp) {
			LOG("Not enough memory");
			free(geodb4);
			geodb4 = NULL;
			return 0;
		}

		geodb4 = tmp;
		memset(&geodb4[geodb4_size], 0, sizeof(struct btrie_node));
		geodb4[node].next[bit] = geodb4_size;
		node = geodb4_size;
		geodb4_size++;
	}
	geodb4[node].is_leaf = 1;
	geodb4[node].g = *g;
	return 1;
}

static int
geodb_add6(xe_ip addr, int mask, struct geoip_info *g)
{
	int i;
	uint32_t node, next;
	uint8_t *addr_ptr = (uint8_t *)&addr;

	if (!geodb6) {
		/* empty database */
		geodb6 = calloc(1, sizeof(struct btrie_node));
		if (!geodb6) {
			LOG("Not enough memory");
			return 0;
		}
		geodb6_size = 1;
	}

	node = 0;

	for (i=0; i<mask; i++) {
		struct btrie_node *tmp;
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = geodb6[node].next[bit];
		if (next) {
			node = next;
			continue;
		}

		tmp = realloc(geodb6,
			(geodb6_size + 1) * sizeof(struct btrie_node));
		if (!tmp) {
			LOG("Not enough memory");
			free(geodb6);
			geodb6 = NULL;
			return 0;
		}
		geodb6 = tmp;

		memset(&geodb6[geodb6_size], 0, sizeof(struct btrie_node));
		geodb6[node].next[bit] = geodb6_size;
		node = geodb6_size;
		geodb6_size++;
	}
	geodb6[node].is_leaf = 1;
	geodb6[node].g = *g;
	return 1;
}

int
geoip_lookup4(uint32_t addr, struct geoip_info **g)
{
	int i;
	uint32_t node = 0, next = 0;
	uint8_t *addr_ptr = (uint8_t *)&addr;

	if (!geodb4) {
		return 0;
	}

	for (i=0; i<32; i++) {
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = geodb4[node].next[bit];
		if (!next) {
			break;
		}
		node = next;
	}

	if (!geodb4[node].is_leaf) {
		return 0;
	}

	*g = &geodb4[node].g;

	return 1;
}

int
geoip_lookup6(xe_ip *addr, struct geoip_info **g)
{
	int i;
	uint32_t node = 0, next = 0;
	uint8_t *addr_ptr = (uint8_t *)addr;

	if (!geodb6) {
		return 0;
	}

	for (i=0; i<16*8; i++) {
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = geodb6[node].next[bit];
		if (!next) {
			break;
		}
		node = next;
	}

	if (!geodb6[node].is_leaf) {
		return 0;
	}

	*g = &geodb6[node].g;

	return 1;
}

static char *
csv_scan_field(char *line, char *val, int lower_case)
{
	size_t i;

	if (!line) {
		val[0] = '\0';
		return NULL;
	}

	if (line[0] == '\"') {
		char *quote = strchr(line + 1, '\"');
		if (!quote) {
			val[0] = '\0';
			return NULL;
		}
		*quote = '\0';

		strcpy(val, line + 1);
		if (lower_case) {
			for (i=0; i<strlen(val); i++) {
				val[i] = tolower(val[i]);
			}
		}

		char *comma = strchr(line, ',');
		if (comma) {
			line = comma + 1;
			return line;
		} else {
			line = quote + 1;
			return line;
		}
	}

	char *comma = strchr(line, ',');
	if (!comma) {
		val[0] = '\0';
		return NULL;
	}

	*comma = '\0';
	strcpy(val, line);
	if (lower_case) {
		for (i=0; i<strlen(val); i++) {
			val[i] = tolower(val[i]);
		}
	}

	line = comma + 1;

	return line;
}

static void
add_range4(uint32_t ip1, uint32_t ip2, struct geoip_info *g)
{
	uint32_t subnet_first, subnet_last, end;

	subnet_first = be32toh(ip1);
	end = be32toh(ip2);

	for (;;) {
		if (subnet_first > end) {
			break;
		} else if (subnet_first == end) {
			geodb_add4(htobe32(subnet_first), 32, g);
			break;
		}

		int mask_bits = __builtin_ctz(subnet_first);
		subnet_last = subnet_first + (1 << mask_bits) - 1;

		if (subnet_last == end) {
			geodb_add4(htobe32(subnet_first), 32 - mask_bits, g);
			break;
		} else if (subnet_last > end) {
			uint32_t diff = end - subnet_first + 1;
			int p =  32 - __builtin_clz(diff) - 1;
			uint32_t ndiff = 1 << p;

			geodb_add4(htobe32(subnet_first), 32 - p, g);

			subnet_first += ndiff;
		} else {
			geodb_add4(htobe32(subnet_first), 32 - mask_bits, g);

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

void xe_ip2str(xe_ip ip, char *s)
{
	uint64_t low = (uint64_t)ip;
	uint64_t high = (ip >> 64);
	sprintf(s, "%lx:%lx", high, low);
}

static void
add_range6(xe_ip *ip1, xe_ip *ip2, struct geoip_info *g)
{
	xe_ip subnet_first, subnet_last, end;

	/* FIXME: check endianess? */
	subnet_first = __builtin_bswap128(*ip1);
	end = __builtin_bswap128(*ip2);

	for (;;) {
		if (subnet_first > end) {
			break;
		} else if (subnet_first == end) {
			geodb_add6(__builtin_bswap128(subnet_first), 128, g);
			break;
		}

		int mask_bits = ctz_128(subnet_first);
		subnet_last = subnet_first + ((xe_ip)1 << mask_bits) - 1;

		if (subnet_last == end) {
			geodb_add6(__builtin_bswap128(subnet_first),
				128 - mask_bits, g);
			break;
		} else if (subnet_last > end) {
			xe_ip diff = end - subnet_first + 1;
			int p =  128 - clz_128(diff) - 1;
			xe_ip ndiff = (xe_ip)1 << p;

			geodb_add6(__builtin_bswap128(subnet_first),
				128 - p, g);

			subnet_first += ndiff;
		} else {
			geodb_add6(__builtin_bswap128(subnet_first),
				128 - mask_bits, g);

			subnet_first = subnet_last + 1;
		}
	}
}


static int
process_line_ipapi(char *line, char *err)
{
	char *lptr = line;

	struct geoip_info g;
	char ip_ver[5];
	char addr[100], addr1[100], addr2[100];
	char *maskpos;
	int mask;
	struct in_addr ip, ip2;

	lptr = csv_scan_field(lptr, ip_ver, 0);
	lptr = csv_scan_field(lptr, addr, 0);
	lptr = csv_scan_field(lptr, g.continent, 1);
	lptr = csv_scan_field(lptr, g.country, 1);
	lptr = csv_scan_field(lptr, g.country_full, 0);
	lptr = csv_scan_field(lptr, g.state, 0);
	lptr = csv_scan_field(lptr, g.city, 0);
	lptr = csv_scan_field(lptr, g.zip, 0);

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
			add_range6(&ipv6_1, &ipv6_2, &g);
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

			add_range4(ip.s_addr, ip2.s_addr, &g);
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

		switch (type) {
			case GEO_FILE_IPAPI:
				if (!process_line_ipapi(line, err)) {
					LOG("geoip: file '%s', line #%lu: %s",
						path, line_num, err);
				}
				break;
			default:
				break;
		}

		line_num++;
		if (line_num > 1000) {
			//break;
		}
	}

	LOG("geoip: file '%s' added, tree has %lu items (%lu bytes)",
		path, geodb4_size + geodb6_size,
		(geodb4_size + geodb6_size) * sizeof(struct btrie_node));

fail_format:
	fclose(f);

	return 1;
}

void
geoip_free()
{
	if (geodb4) {
		free(geodb4);
		geodb4 = NULL;
		geodb4_size = 0;
	}

	if (geodb6) {
		free(geodb6);
		geodb6 = NULL;
		geodb6_size = 0;
	}
}

