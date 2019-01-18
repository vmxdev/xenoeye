#ifndef netflow_templates_h_included
#define netflow_templates_h_included

#include "netflow.h"

struct template_key
{
	/* template key: template ID, source IP, source ID and time */
	uint8_t data[sizeof(uint16_t) + sizeof(uint32_t)
		+ sizeof(uint32_t) + sizeof(uint32_t)];
	/* size depends on size of source IP address (but currently we handle
	   only IPv4) */
	size_t size;
};

int netflow_templates_init(void);
void netflow_templates_shutdown(void);

struct nf9_template_item *netflow_template_find(struct template_key *tkey);
int netflow_template_add(struct template_key *tkey,
	struct nf9_template_item *t);

#endif

