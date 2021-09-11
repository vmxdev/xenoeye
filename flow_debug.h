#ifndef flow_debug_h_included
#define flow_debug_h_included

#include <stdint.h>
#include "aajson/aajson.h"

#include "xenoeye.h"

int flow_debug_config(struct aajson *a, aajson_val *value,
	struct xe_debug *dbg);

void flow_debug_add_field(struct xe_debug *debug, int flength, int ftype,
	uint8_t *fptr, char *debug_flow_str);

void flow_dump_str(struct xe_debug *debug, const char *flow_str);

#endif

