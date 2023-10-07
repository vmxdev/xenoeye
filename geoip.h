#ifndef geoip_h_included
#define geoip_h_included

/* string sizes taken from files geolocationDatabaseIPv4.csv and
 * geolocationDatabaseIPv6.csv */
struct geoip_info
{
	char country[3];
	char continent[3];

	char country_full[35];
	char state[64];
	char city[51];
	char zip[15];
	char latitude[20], longitude[23];
};

int  geoip_add_file(const char *dp_path);
void geoip_free(void);

int geoip_lookup4(uint32_t key, struct geoip_info **g);

#endif

