#ifndef monit_object_common_h_included
#define monit_object_common_h_included

#include "filter.h"

/* some helper functions */
static inline uint64_t
monit_object_nf_val(struct nf_flow_info *flow, struct field *fld)
{
	uint64_t val;
	uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;

	switch (fld->size) {
		case sizeof(uint64_t):
			val = be64toh(*(uint64_t *)flow_fld);
			break;
		case sizeof(uint32_t):
			val = be32toh(*(uint32_t *)flow_fld);
			break;
		default:
			val = 0;
			break;
	}

	return val;
}


#endif

