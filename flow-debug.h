#ifndef flow_debug_h_included
#define flow_debug_h_included

#include <stdint.h>
#include "aajson/aajson.h"

#include "xenoeye.h"

void flow_debug_init(void);

int flow_debug_config(struct aajson *a, aajson_val *value,
	struct xe_debug *debug);

void flow_debug_add_field(int flength, int ftype, uint8_t *fptr,
	char *debug_flow_str);

void flow_print_str(struct xe_debug *debug, struct flow_info *fi,
	char *flow_str, int is_sflow);

void sflow_debug_print(struct flow_info *fi, char *str);

#endif

