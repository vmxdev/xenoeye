#include <string.h>
#include "xenoeye.h"
#include "sflow.h"


#define USER_TYPE struct flow_info *

#include "rawparse.h"

static inline int
sf5_eth(struct sfdata *s, uint8_t *p, uint8_t *end, uint32_t header_len)
{
	if (p + header_len > end) {
		return 0;
	}

	if (rawpacket_parse(p, header_len, s->flow) < RP_PARSER_STATE_NO_IP) {
		/* Skip non-IP samples */
		return 0;
	}

	return 1;
}

#include "sflow-impl.h"

int
main()
{
	return 0;
}

