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
#include "utils.h"

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

static struct btrie_node *geodb = NULL;
static size_t geodb_size = 0;

static int
geodb_add(uint32_t key, int mask, struct geoip_info *g)
{
	int i;
	uint32_t node;
	uint32_t next;

	if (!geodb) {
		/* empty database */
		geodb = calloc(1, sizeof(struct btrie_node));
		if (!geodb) {
			LOG("Not enough memory");
			return 0;
		}
		geodb_size = 1;
	}

	node = 0;
	key = ntohl(key);
	for (i=0; i<mask; i++) {
		struct btrie_node *tmp;
		int pos, bit;

		pos = 31 - i;
		bit = !!(key & (1 << pos));

		next = geodb[node].next[bit];
		if (next) {
			node = next;
			continue;
		}

		tmp = realloc(geodb,
			(geodb_size + 1) * sizeof(struct btrie_node));
		if (!tmp) {
			LOG("Not enough memory");
			free(geodb);
			geodb = NULL;
			return 0;
		}
		geodb = tmp;

		memset(&geodb[geodb_size], 0, sizeof(struct btrie_node));
		geodb[node].next[bit] = geodb_size;
		node = geodb_size;
		geodb_size++;
	}
	geodb[node].is_leaf = 1;
	geodb[node].g = *g;
	return 1;
}

int
geoip_lookup4(uint32_t key, struct geoip_info **g)
{
	int i;
	uint32_t node = 0, next = 0;

	if (!geodb) {
		return 0;
	}

	key = ntohl(key);
	for (i=0; i<32; i++) {
		int pos, bit;

		pos = 31 - i;
		bit = !!(key & (1 << pos));


		next = geodb[node].next[bit];
		if (!next) {
			break;
		}
		node = next;
	}

	*g = &geodb[node].g;

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
add_range(uint32_t ip1, uint32_t ip2, struct geoip_info *g)
{
	uint32_t subnet_first, subnet_last, end;

	subnet_first = be32toh(ip1);
	end = be32toh(ip2);

	for (;;) {
		if (subnet_first > end) {
			break;
		} else if (subnet_first == end) {
			geodb_add(htobe32(subnet_first), 32, g);
			break;
		}

		int mask_bits = __builtin_ctz(subnet_first);
		subnet_last = subnet_first + (1 << mask_bits) - 1;

		if (subnet_last == end) {
			geodb_add(htobe32(subnet_first), 32 - mask_bits, g);
			break;
		} else if (subnet_last > end) {
			uint32_t diff = end - subnet_first + 1;
			int p =  32 - __builtin_clz(diff) - 1;
			uint32_t ndiff = 1 << p;

			geodb_add(htobe32(subnet_first), 32 - p, g);

			subnet_first += ndiff;
		} else {
			geodb_add(htobe32(subnet_first), 32 - mask_bits, g);

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

	if (strchr(addr, '-')) {
		/* range */
		sscanf(addr, "%s - %s", addr1, addr2);

		if (inet_aton(addr1, &ip) == 0) {
			sprintf(err, "can't parse IP address 1'%s'", addr1);
			return 0;
		}
		if (inet_aton(addr2, &ip2) == 0) {
			sprintf(err, "can't parse IP address 2'%s'", addr2);
			return 0;
		}

		add_range(ip.s_addr, ip2.s_addr, &g);
	} else {
		/* single network */
		maskpos = strchr(addr, '/');
		mask = atoi(maskpos + 1);
		*maskpos = '\0';
		if (inet_aton(addr, &ip) == 0) {
			sprintf(err, "can't parse IP address '%s'", addr);
			return 0;
		}
		geodb_add(ip.s_addr, mask, &g);
	}
	return 1;
}

int
geoip_add_file(const char *path)
{
	FILE *f;
	char line[4096];
	size_t line_num = 1;
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
		path, geodb_size, geodb_size * sizeof(struct btrie_node));

fail_format:
	fclose(f);

	return 1;
}

void
geoip_free()
{
	if (geodb) {
		free(geodb);
		geodb = NULL;
		geodb_size = 0;
	}
}

