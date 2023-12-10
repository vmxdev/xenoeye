#ifndef monit_object_common_h_included
#define monit_object_common_h_included

#include "filter.h"

/* FIXME: remove this function? */
static inline uint64_t
monit_object_nf_val(struct flow_info *flow, struct field *fld)
{
	uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;
	return get_nf_val(flow_fld, fld->size);
}


#endif

