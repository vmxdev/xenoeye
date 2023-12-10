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
	SF5_HEADER_ETHERNET_ISO8023 = 1
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
sf5_flow(struct sfdata *s, uint8_t *p, uint8_t *end)
{
	uint32_t l, seq, src, nel;
	uint32_t inp, outp;
	uint32_t v;
	uint32_t j;

	/* sample length */
	READ32_H(l, p, end);
	LOG(">SFLOW len:  %u", l);

	READ32_H(seq, p, end);
	LOG(">SFLOW: seq %u", seq);

	/* (TODO: expanded) */

	READ32_H(src, p, end);
	LOG(">SFLOW: src %u", src);

	READ32_H(v, p, end);
	LOG(">SFLOW: skip %u", v);
	READ32_H(v, p, end);
	LOG(">SFLOW: sample pool %u", v);
	READ32_H(v, p, end);
	LOG(">SFLOW: drop events %u", v);

	READ32_H(inp, p, end);
	READ32_H(outp, p, end);

	LOG(">SFLOW: inp: %u/%u", inp, inp & 0x3fffffff);
	LOG(">SFLOW: outp: %u/%u", outp, outp & 0x3fffffff);

	READ32_H(nel, p, end);
	LOG(">SFLOW: nel %u", nel);

	for (j=0; j<nel; j++) {
		uint32_t tag, ell;

		READ32_H(tag, p, end);
		LOG(">>[%u]SFLOW: tag %u", j, tag);

		READ32_H(ell, p, end);
		LOG(">>[%u]SFLOW: ell %u", j, ell);

		if (tag == SF5_FLOW_HEADER) {
			uint32_t header_proto, sampled_size;
			uint32_t stripped, header_len;

			READ32_H(header_proto, p, end);
			READ32_H(sampled_size, p, end);
			READ32_H(stripped, p, end);

			READ32_H(header_len, p, end);

			LOG(">>[%u]SFLOW: header_proto %u", j, header_proto);
			LOG(">>[%u]SFLOW: header_len %u(%u)", j, header_len, ALIGN_4(header_len));
			LOG(">>[%u]SFLOW: sampled_size %u", j, sampled_size);

			if (header_proto == SF5_HEADER_ETHERNET_ISO8023) {
				if (!sf5_eth(s, p, end, header_len)) {
					return 0;
				}
			} else {
				LOG("Unknown header_proto '%u'", header_proto);
				return 0;
			}
			p += ALIGN_4(header_len); /* ??? */
		} else {
			/* unknown tag */
			p += ell;
		}
	}
	return 1;
}

int
sflow_process(struct xe_data *global, size_t thread_id,
	struct flow_packet_info *fpi, int len)
{
	uint32_t i, nrecs;
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
	LOG("SFLOW: ver %u", v);
	if (v != 5) {
		LOG("Unknown sFlow version %u", v);
		return 0;
	}

	READ32_H(v, p, end);
	LOG("SFLOW: addr_type %u", v);
	if (v == SF5_ADDR_IP_V4) {
		READ_SF_BYTES(flow.dev_ip, sizeof(uint32_t), p, end);
		flow.has_dev_ip = 1;
		flow.dev_ip_size = sizeof(uint32_t);
		LOG("SFLOW: addr %u.%u.%u.%u", flow.dev_ip[0], flow.dev_ip[1],
			flow.dev_ip[2], flow.dev_ip[3]);
	} else if (v == SF5_ADDR_IP_V6) {
		READ_SF_BYTES(flow.dev_ip6, sizeof(xe_ip), p, end);
		flow.has_dev_ip6 = 1;
		flow.dev_ip6_size = sizeof(xe_ip);
	} else if (v == SF5_ADDR_UNKNOWN) {
	} else {
		LOG("Unknown address type %u", v);
		return 0;
	}

	//LOG("SFLOW: subagent %u", v);
	READ_SF_BYTES(flow.dev_id, sizeof(uint32_t), p, end);
	flow.has_dev_id = 1;
	flow.dev_id_size = sizeof(uint32_t);

	READ32_H(v, p, end);
	LOG("SFLOW: seq %u", v);

	READ32_H(v, p, end);
	LOG("SFLOW: uptime %u", v);

	READ32_H(nrecs, p, end);
	LOG("SFLOW: records %u", nrecs);

	for (i=0; i<nrecs; i++) {
		/* sample type */
		READ32_H(v, p, end);
		LOG("SFLOW: type %u", v);

		if (v == SF5_SAMPLE_FLOW) {
			if (!sf5_flow(&sfd, p, end)) {
				return 0;
			}
		} else if (v == SF5_SAMPLE_COUNTERS) {
			uint32_t l;
			READ32_H(l, p, end);
			LOG(">SFLOW COUNTER SKIP:  %u", l);
			p += l;
		} else {
		}
	}

	return 1;
}

