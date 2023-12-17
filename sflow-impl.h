#include "flow-info.h"

enum SF5_ADDR_TYPE
{
	SF5_ADDR_UNKNOWN  = 0,
	SF5_ADDR_IP_V4    = 1,
	SF5_ADDR_IP_V6    = 2
};

enum SF5_SAMPLE_TAG
{
	SF5_SAMPLE_FLOW = 1,
	SF5_SAMPLE_COUNTERS = 2,
	SF5_SAMPLE_FLOW_EXPANDED = 3,
	SF5_SAMPLE_COUNTERS_EXPANDED = 4,
	SF5_SAMPLE_DISCARDED_PACKET = 5
};

enum SF5_FLOW_TAG
{
	SF5_FLOW_HEADER = 1
};

enum SF5_HEADER_TYPE
{
	SF5_HEADER_ETHERNET_ISO8023 = 1,
	SF5_HEADER_IPv4 = 11,
	SF5_HEADER_IPv6 = 12
};

#define ALIGN_4(X) (((X % 4) == 0)? X : X + (4 - (X % 4)))

#define READ_SF_BYTES(R, RLEN, P, END)               \
do {                                                 \
	if ((P + RLEN) >= END) {                     \
		LOG("Malformed sFlow packet");       \
		return 0;                            \
	}                                            \
	memcpy(R, P, RLEN);                          \
	P += ALIGN_4(RLEN);                          \
} while (0)

#define READ32_H(R, P, END)                          \
do {                                                 \
	READ_SF_BYTES(&R, sizeof(uint32_t), P, END); \
	R = be32toh(R);                              \
} while (0)


static inline int
sf5_flow(struct sfdata *s, uint8_t **p, uint8_t *end)
{
	uint32_t l, seq, src, nel;
	uint32_t v;
	uint32_t j;
	uint32_t ifidx, ifidx_be;

	/* sample length */
	READ32_H(l, *p, end);
	LOG("\tlength:  %u", l);

	READ32_H(seq, *p, end);
	LOG("\tsequence: %u", seq);

	READ32_H(src, *p, end);
	LOG("\tsrc id: %u", src);

	READ32_H(v, *p, end);
	LOG("\tsampling rate: %u", v);
	s->flow->sampling_rate = v;

	READ32_H(v, *p, end);
	LOG("\tsample pool: %u", v);
	READ32_H(v, *p, end);
	LOG("\tdrop events: %u", v);

	READ32_H(ifidx, *p, end);
	ifidx &= 0x3fffffff;
	LOG("\tinput interface: %u", ifidx);
	ifidx_be = htobe32(ifidx);
	memcpy(s->flow->input_snmp, &ifidx_be, sizeof(uint32_t));
	s->flow->has_input_snmp = 1;
	s->flow->input_snmp_size = sizeof(uint32_t);

	READ32_H(ifidx, *p, end);
	ifidx &= 0x3fffffff;
	LOG("\toutput interface: %u", ifidx);
	ifidx_be = htobe32(ifidx);
	memcpy(s->flow->output_snmp, &ifidx_be, sizeof(uint32_t));
	s->flow->has_output_snmp = 1;
	s->flow->output_snmp_size = sizeof(uint32_t);

	READ32_H(nel, *p, end);
	LOG("\tnumber of elements: %u", nel);

	for (j=0; j<nel; j++) {
		uint32_t tag, ell;

		LOG("\t\telement #%u", j);
		READ32_H(tag, *p, end);
		LOG("\t\ttag: %u", tag);

		READ32_H(ell, *p, end);
		LOG("\t\telement length: %u bytes", ell);

		if (tag == SF5_FLOW_HEADER) {
			uint32_t header_proto;
			uint32_t stripped, header_len;

			READ32_H(header_proto, *p, end);

			READ_SF_BYTES(&s->flow->in_bytes[4], sizeof(uint32_t),
				*p, end);
			s->flow->has_in_bytes = 1;
			s->flow->in_bytes_size = sizeof(uint64_t);

			s->flow->in_pkts[7] = 1;
			s->flow->has_in_pkts = 1;
			s->flow->in_pkts_size = sizeof(uint64_t);

			READ32_H(stripped, *p, end);

			READ32_H(header_len, *p, end);

			LOG("\t\theader protocol: %u", header_proto);
			LOG("\t\theader len: %u", header_len);

			LOG("\t\tsampled size: %lu",
				be64toh(*((uint64_t *)s->flow->in_bytes)));

			if (header_proto == SF5_HEADER_ETHERNET_ISO8023) {
				if (!sf5_eth(s, *p, end, RP_TYPE_ETHER,
					header_len)) {

					return 0;
				}
			} else if (header_proto == SF5_HEADER_IPv4) {
				if (!sf5_eth(s, *p, end, RP_TYPE_IPv4,
					header_len)) {

					return 0;
				}
			} else if (header_proto == SF5_HEADER_IPv6) {
				if (!sf5_eth(s, *p, end, RP_TYPE_IPv6,
					header_len)) {

					return 0;
				}
			} else {
				LOG("\t\tUnknown header protocol %u",
					header_proto);
				return 0;
			}
			*p += ALIGN_4(header_len);
		} else {
			/* unknown tag */
			LOG("\t\tUnknown tag %u", tag);
			*p += ell;
		}
	}
	return 1;
}

int
sflow_process(struct xe_data *global, size_t thread_id,
	struct flow_packet_info *fpi, int len)
{
	uint32_t i, nsmpl;
	uint32_t v;
	uint8_t *p = fpi->rawpacket;
	uint8_t *end = p + len;
	struct flow_info flow;
	struct sfdata sfd;

	sfd.global = global;
	sfd.thread_id = thread_id;
	sfd.fpi = fpi;
	sfd.flow = &flow;

	memset(&flow, 0, sizeof(struct flow_info));

	READ32_H(v, p, end);
	LOG("version: %u", v);
	if (v != 5) {
		LOG("Unknown sFlow version %u", v);
		return 0;
	}

	READ32_H(v, p, end);
	LOG("agent address type: %u", v);
	if (v == SF5_ADDR_IP_V4) {
		char s[INET_ADDRSTRLEN + 1];

		READ_SF_BYTES(flow.dev_ip, sizeof(uint32_t), p, end);
		flow.has_dev_ip = 1;
		flow.dev_ip_size = sizeof(uint32_t);

		inet_ntop(AF_INET, &flow.dev_ip, s, INET_ADDRSTRLEN);
		LOG("agent address (IPv4): %s", s);
	} else if (v == SF5_ADDR_IP_V6) {
		char s[INET6_ADDRSTRLEN + 1];

		READ_SF_BYTES(flow.dev_ip6, sizeof(xe_ip), p, end);
		flow.has_dev_ip6 = 1;
		flow.dev_ip6_size = sizeof(xe_ip);

		inet_ntop(AF_INET6, &flow.dev_ip6, s, INET6_ADDRSTRLEN);
		LOG("agent address (IPv6): %s", s);
	} else {
		LOG("Unknown agent address type %u", v);
		return 0;
	}

	READ_SF_BYTES(flow.dev_id, sizeof(uint32_t), p, end);
	flow.has_dev_id = 1;
	flow.dev_id_size = sizeof(uint32_t);
	LOG("agent id: %u", be32toh(*((uint32_t *)flow.dev_id)));

	READ32_H(v, p, end);
	LOG("sequence: %u", v);

	READ32_H(v, p, end);
	LOG("uptime: %u", v);

	READ32_H(nsmpl, p, end);
	LOG("samples: %u", nsmpl);

	for (i=0; i<nsmpl; i++) {
		/* sample type */
		LOG("\tsample #%u", i);
		READ32_H(v, p, end);

		if (v == SF5_SAMPLE_FLOW) {
			LOG("\tsample type: %u (SF5_SAMPLE_FLOW)", v);
			if (!sf5_flow(&sfd, &p, end)) {
				return 0;
			}
		} else if (v == SF5_SAMPLE_COUNTERS) {
			uint32_t l;
			LOG("\tsample type: %u (SF5_SAMPLE_COUNTERS)", v);
			READ32_H(l, p, end);
			LOG("\tskipping this sample type (%u bytes)", l);
			p += l;
		} else {
			uint32_t l;
			LOG("\tUnknown sample type %u", v);
			READ32_H(l, p, end);
			LOG("\tskipping %u bytes", l);
			p += l;
		}
	}

	return 1;
}

