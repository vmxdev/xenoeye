#ifndef devices_h_included
#define devices_h_included

#include <stdint.h>
#include "utils.h"

struct flow_packet_info;

struct device
{
	int in_db;

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

	unsigned int sflow_skip_tag;
};

int devices_load(const char *filename);

int device_rules_check(struct device *dev, struct flow_info *fi);
void device_get(struct device *dev, struct flow_packet_info *fpi);

#endif

