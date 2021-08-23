#ifndef netflow_templates_h_included
#define netflow_templates_h_included

#include "netflow.h"

/*
 * template key: source IP address version (4 or 6), Netflow version,
 * template ID, source IP, source ID and time
 */
struct template_key
{
	uint8_t  src_ip_version;
	uint8_t  nf_version;
	uint16_t template_id;

	xe_ip source_ip;

	uint32_t source_id;
	uint32_t epoch;
} PACKED;

int netflow_templates_init(struct xe_data *data);
void netflow_templates_shutdown(void);

void *netflow_template_find(struct template_key *tkey,
	int allow_templates_in_future);

int netflow_template_add(struct template_key *tkey, void *t, size_t size);

#endif

