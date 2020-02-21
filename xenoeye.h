#ifndef xenoeye_h_included
#define xenoeye_h_included

#include <limits.h>

struct nf_flow_info;

struct monit_item
{
	char name[PATH_MAX];
};

struct xe_data
{
	size_t nmonit_items;
	struct monit_item *monit_items;
};

int monit_items_init(struct xe_data *data);
int monit_items_free(struct xe_data *data);

int monit_item_match(struct monit_item *mi, struct nf_flow_info *fi);

#endif

