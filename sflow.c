#include "utils.h"
#include "flow-info.h"
#include "sflow.h"
#include "filter.h"
#include "flow-debug.h"

#define COPY_TO_FLOW(D, F, R, N)  \
do {                              \
	memcpy(D->F, R, N);       \
	D->has_##F = 1;           \
	D->F##_size = N;          \
} while (0)

#define USER_TYPE struct flow_info *

#define ON_VLAN1(D, V)                                  \
	COPY_TO_FLOW(D, src_vlan, &V->h_vlan_TCI, 2);   \
	COPY_TO_FLOW(D, dst_vlan, &V->h_vlan_TCI, 2);

#define ON_VLAN2(D, V)                                  \
	COPY_TO_FLOW(D, dot1q_vlan, &V->h_vlan_TCI, 2);

#define ON_IP(D, V)                                     \
	COPY_TO_FLOW(D, ip4_src_addr, &V->saddr, 4);    \
	COPY_TO_FLOW(D, ip4_dst_addr, &V->daddr, 4);    \
	COPY_TO_FLOW(D, src_tos, &V->tos, 1);           \
	COPY_TO_FLOW(D, dst_tos, &V->tos, 1);           \
	COPY_TO_FLOW(D, min_ttl, &V->ttl, 1);           \
	COPY_TO_FLOW(D, max_ttl, &V->ttl, 1);           \
	COPY_TO_FLOW(D, protocol, &V->protocol, 1);
/* TODO: fragmented packets? */

#define ON_IP6(D, V)                                    \
	COPY_TO_FLOW(D, ip6_src_addr, &V->ip6_src, 16); \
	COPY_TO_FLOW(D, ip6_dst_addr, &V->ip6_src, 16); \
	COPY_TO_FLOW(D, min_ttl, &V->ip6_ctlun.ip6_un1.ip6_un1_hlim, 1); \
	COPY_TO_FLOW(D, max_ttl, &V->ip6_ctlun.ip6_un1.ip6_un1_hlim, 1); \
	COPY_TO_FLOW(D, protocol, &nexthdr, 1);

#define ON_TCP(D, V)                                    \
	COPY_TO_FLOW(D, l4_src_port, &V->source, 2);    \
	COPY_TO_FLOW(D, l4_dst_port, &V->dest, 2);      \
	COPY_TO_FLOW(D, tcp_flags, &V->th_flags, 1);

#define ON_UDP(D, V)                                    \
	COPY_TO_FLOW(D, l4_src_port, &V->source, 2);    \
	COPY_TO_FLOW(D, l4_dst_port, &V->dest, 2);

#define ON_ICMP(D, V)                                   \
	COPY_TO_FLOW(D, icmp_type, &V->type, 1);
/* TODO: ICMP code? */

#include "rawparse.h"


static inline int
sf5_eth(struct sfdata *s, uint8_t *p, uint8_t *end, enum RP_TYPE t,
	uint32_t header_len)
{
	size_t t_id;

	if (p + header_len > end) {
		return 0;
	}

	if (rawpacket_parse(p, p + header_len, t, s->flow)
		< RP_PARSER_STATE_NO_IP) {

		/* Skip non-IP samples */
		return 0;
	}

	for (t_id=0; t_id<s->global->nmonit_objects; t_id++) {
		struct monit_object *mo = &s->global->monit_objects[t_id];

		if (!filter_match(mo->expr, s->flow)) {
			continue;
		}

		monit_object_process_nf(s->global, mo, s->thread_id,
			s->fpi->time_ns, s->flow);

		if (mo->debug.print_flows) {
			char debug_flow_str[1024];
			sflow_debug_print(s->flow, debug_flow_str);

			flow_print_str(&mo->debug, s->flow, debug_flow_str);
		}
	}
#ifdef FLOWS_CNT
	atomic_fetch_add_explicit(&data->nflows, 1, memory_order_relaxed);
#endif
	return 1;
}

/* disable logging */
#undef LOG
#define LOG(...)

#include "sflow-impl.h"

