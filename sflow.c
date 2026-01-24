/*
 * xenoeye
 *
 * Copyright (c) 2025, Vladimir Misyurov
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

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

#define ON_ETH(D, V)                                          \
	COPY_TO_FLOW(D, dst_mac, &V->h_dest, MAC_ADDR_SIZE);  \
	COPY_TO_FLOW(D, src_mac, &V->h_source, MAC_ADDR_SIZE);

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
	COPY_TO_FLOW(D, l4_src_port, &V->th_sport, 2);  \
	COPY_TO_FLOW(D, l4_dst_port, &V->th_dport, 2);  \
	COPY_TO_FLOW(D, tcp_flags, &V->th_flags, 1);

#define ON_UDP(D, V)                                    \
	COPY_TO_FLOW(D, l4_src_port, &V->uh_sport, 2);  \
	COPY_TO_FLOW(D, l4_dst_port, &V->uh_dport, 2);

#define ON_ICMP(D, V)                                   \
	COPY_TO_FLOW(D, icmp_type, &V->type, 1);
/* TODO: ICMP code? */

#define ON_PAYLOAD(D, V) D->payload_ptr = V;

#include "rawparse.h"

static int xe_sni(uint8_t *p, uint8_t *end, char *domain);
static int xe_dns(uint8_t *p, uint8_t *end, char *domain, char *ips);

static void
process_mo_sflow_rec(struct sfdata *s, uint8_t *end, struct monit_object *mos,
	size_t n_mo)
{
	size_t i;
	for (i=0; i<n_mo; i++) {
		struct monit_object *mo = &mos[i];

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

			flow_print_str(&mo->debug, s->flow, debug_flow_str, 1);
		}

		/* child objects */
		if (mo->n_mo) {
			process_mo_sflow_rec(s, end, mo->mos, mo->n_mo);
		}
	}
}

static inline int
sf5_parsed(struct sfdata *s, uint8_t *p, uint32_t header_len)
{
	uint8_t *end = p + header_len;

	/* check interfaces */
	if (!device_rules_check(s->flow, s->fpi)) {
		/* no error */
		return 1;
	}

	/* debug print */
	if (s->global->debug.print_flows) {
		char debug_flow_str[1024];
		sflow_debug_print(s->flow, debug_flow_str);

		flow_print_str(&s->global->debug, s->flow, debug_flow_str, 1);
	}

	process_mo_sflow_rec(s, end,
		s->global->monit_objects, s->global->nmonit_objects);

#ifdef FLOWS_CNT
	atomic_fetch_add_explicit(&s->global->nflows, 1, memory_order_relaxed);
#endif
	return 1;
}

static inline int
sf5_eth(struct sfdata *s, uint8_t *p, enum RP_TYPE t, uint32_t header_len)
{
	uint8_t *end = p + header_len;

	if (rawpacket_parse(p, end, t, s->flow)
		< RP_PARSER_STATE_NO_IP) {

		/* Skip non-IP samples */
		return 1;
	}
	return sf5_parsed(s, p, header_len);
}

/* disable logging */
#undef LOG
#define LOG(...)

#include "xe-sni.h"
#include "xe-dns.h"

#include "sflow-impl.h"

