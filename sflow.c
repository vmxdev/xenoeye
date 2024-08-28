#include "utils.h"
#include "flow-info.h"
#include "sflow.h"
#include "filter.h"
#include "flow-debug.h"
#include "devices.h"

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

#define ON_PAYLOAD(D, V) D->payload_ptr = V;

#include "rawparse.h"

static int xe_sni(uint8_t *p, uint8_t *end, char *domain);
static int xe_dns(uint8_t *p, uint8_t *end, char *domain, char *ips);

static int
device_rules_check(struct flow_info *flow, struct flow_packet_info *fpi)
{
	struct device dev;
	uint32_t mark;

	/* FIXME: add IPv6 */
	dev.ip_ver = 4;
	dev.ip = 0;
	memcpy(&dev.ip, &fpi->src_addr_ipv4, 4);

	dev.id = fpi->source_id;

	if (!device_get_mark(&dev, flow)) {
		/* device not found */
		return 1;
	}

	if (dev.skip_unmarked && (dev.mark == 0)) {
		return 0;
	}

	mark = htobe32(dev.mark);
	memcpy(&flow->dev_mark[0], &mark, sizeof(uint32_t));
	flow->dev_mark_size = sizeof(uint32_t);
	flow->has_dev_mark = 1;

	return 1;
}


static inline int
sf5_eth(struct sfdata *s, uint8_t *p, enum RP_TYPE t, uint32_t header_len)
{
	size_t t_id;
	uint8_t *end = p + header_len;

	if (rawpacket_parse(p, end, t, s->flow)
		< RP_PARSER_STATE_NO_IP) {

		/* Skip non-IP samples */
		return 1;
	}
	/* check interfaces */
	if (!device_rules_check(s->flow, s->fpi)) {
		/* no error */
		return 1;
	}

	/* debug print */
	if (s->global->debug.print_flows) {
		char debug_flow_str[1024];
		sflow_debug_print(s->flow, debug_flow_str);

		flow_print_str(&s->global->debug, s->flow, debug_flow_str);
	}

	for (t_id=0; t_id<s->global->nmonit_objects; t_id++) {
		struct monit_object *mo = &s->global->monit_objects[t_id];

		if (!filter_match(mo->expr, s->flow)) {
			continue;
		}

		if (mo->payload_parse_dns && s->flow->payload_ptr) {
			if (xe_dns(s->flow->payload_ptr, end,
				(char *)s->flow->dns_name,
				(char *)s->flow->dns_ips)) {

				s->flow->has_dns_name = 1;
				s->flow->has_dns_ips = 1;
			}
		}

		if (mo->payload_parse_sni && s->flow->payload_ptr) {
			if (xe_sni(s->flow->payload_ptr,
				end, (char *)s->flow->sni)) {

				s->flow->has_sni = 1;
			}
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

#include "xe-sni.h"
#include "xe-dns.h"

#include "sflow-impl.h"

