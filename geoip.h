#ifndef geoip_h_included
#define geoip_h_included

#include <stdint.h>
#include "utils.h"

#define DEFAULT_GEODB_DIR "/var/lib/xenoeye/geoip/"


/* string sizes taken from files geolocationDatabaseIPv4.csv and
 * geolocationDatabaseIPv6.csv */

#define FOR_LIST_OF_GEOIP_FIELDS \
	DO(CONTINENT, 3)         \
	DO(COUNTRY_CODE, 3)      \
	DO(COUNTRY, 35)          \
	DO(STATE, 64)            \
	DO(CITY, 51)             \
	DO(ZIP, 15)              \
	DO(LAT, 20)              \
	DO(LONG, 23)

enum GEOIP_FIELD
{
#define DO(FIELD, SIZE) GEOIP_##FIELD,
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
};

struct geoip_info
{
#define DO(FIELD, SIZE) char FIELD[SIZE];
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
};

struct as_info
{
	uint32_t asn;
	char asd[200];
};

struct btrie_node_geo
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


int geoip_lookup4(uint32_t addr, struct geoip_info **g);
int geoip_lookup6(xe_ip *addr, struct geoip_info **g);

int as_lookup4(uint32_t addr, struct as_info **a);
int as_lookup6(xe_ip *addr, struct as_info **a);

void *geoip_thread(void *arg);

static inline
char *geoip_get_field(struct geoip_info *g, enum GEOIP_FIELD f)
{
	switch (f) {
#define DO(FIELD, SIZE) case GEOIP_##FIELD: return g->FIELD; break;
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
	}
	return NULL;
}

static inline
int geoip_get_field_size(enum GEOIP_FIELD f)
{
	switch (f) {
#define DO(FIELD, SIZE) case GEOIP_##FIELD: return SIZE; break;
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
	}
	return 0;
}

#endif

