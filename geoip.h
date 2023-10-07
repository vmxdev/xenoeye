#ifndef geoip_h_included
#define geoip_h_included

struct geoip_info
{
	char country[2];
	char continent[2];

	char country_full[50];
	char state[10];
	char city[25];
	char zip[20];
	char latitude[10], longitude[10];
};

int  geoip_add_file(const char *dp_path);
void geoip_free(void);

int geoip_lookup4(uint32_t key, struct geoip_info **g);

#endif

