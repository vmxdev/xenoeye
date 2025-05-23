#ifndef devices_h_included
#define devices_h_included

#include <stdint.h>
#include "utils.h"

struct flow_packet_info;

struct device
{
	int use_ip;
	int ip_ver;
	xe_ip ip;

	int use_id;
	uint32_t id;

	/* marks support */
	size_t n_exprs;
	struct filter_expr **exprs;
	int mark;
	int skip_unmarked;

	int sampling_rate;
};

int devices_load(const char *filename);

int device_get_sampling_rate(struct device *d);
int device_rules_check(struct flow_info *flow, struct flow_packet_info *fpi);

#endif

