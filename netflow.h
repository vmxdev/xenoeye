#ifndef netflow_h_included
#define netflow_h_included

#include <netinet/in.h>
#include <sys/types.h>
#include <stdint.h>

#include "xenoeye.h"

#define MAX_NF_PACKET_SIZE (64*1024)

#define MAX_FLOWS_PER_PACKET 100

#define MAX_FIELDS_PER_FLOW 100

#define MAX_FLOW_VAL_LEN 32

enum NF_FIELD_TYPE
{
	NF_FIELD_IP_ADDR,
	NF_FIELD_INT,
	NF_FIELD_STRING,
	NF_FIELD_BYTES
};

/* netflow v5 */
struct nf5_header
{
	uint16_t version;
	uint16_t count;
	uint32_t sys_uptime;
	uint32_t unix_secs;
	uint32_t unix_nsecs;

	uint32_t flow_sequence;
	uint8_t engine_type;
	uint8_t engine_id;
	uint16_t sampling;
} __attribute__ ((__packed__));

#define NF5_FIELDS                                       \
	FIELD(1, uint32_t, src_addr, ip4_src_addr, 8)    \
	FIELD(1, uint32_t, dst_addr, ip4_dst_addr, 12)   \
	FIELD(1, uint32_t, next_hop, ip4_next_hop, 15)   \
	FIELD(1, uint16_t, input_snmp, input_snmp, 10)   \
	FIELD(1, uint16_t, output_snmp, output_snmp, 14) \
	FIELD(1, uint32_t, packets, in_pkts, 2)          \
	FIELD(1, uint32_t, octets, in_bytes, 1)          \
	FIELD(1, uint32_t, first, first_switched, 22)    \
	FIELD(1, uint32_t, last, last_switched, 21)      \
	FIELD(1, uint16_t, src_port, l4_src_port, 7)     \
	FIELD(1, uint16_t, dst_port, l4_dst_port, 11)    \
	FIELD(0, uint8_t, pad1, pad1, 65530)             \
	FIELD(1, uint8_t, tcp_flags, tcp_flags, 6)       \
	FIELD(1, uint8_t, protocol, protocol, 4)         \
	FIELD(1, uint8_t, tos, src_tos, 5)               \
	FIELD(1, uint16_t, src_as, src_as, 16)           \
	FIELD(1, uint16_t, dst_as, dst_as, 17)           \
	FIELD(1, uint8_t, src_mask, src_mask, 9)         \
	FIELD(1, uint8_t, dst_mask, dst_mask, 13)        \
	FIELD(0, uint16_t, pad2, pad2, 65531)

struct nf5_flow
{
#define FIELD(USE, TYPE, V5, V9, ID) \
	TYPE V5;
	NF5_FIELDS
#undef FIELD
} __attribute__ ((__packed__));

struct nf5_packet
{
	struct nf5_header header;
	struct nf5_flow flows[1];
} __attribute__ ((__packed__));

/* netflow v9 */
struct nf9_header
{
	uint16_t version;
	uint16_t count;
	uint32_t sys_uptime;
	uint32_t unix_secs;

	uint32_t package_sequence;
	uint32_t source_id;
} __attribute__ ((__packed__));

struct nf9_fieldtype_and_len
{
	uint16_t type;
	uint16_t length;
} __attribute__ ((__packed__));

struct nf9_flowset_header
{
	uint16_t flowset_id;
	uint16_t length;
} __attribute__ ((__packed__));

struct nf9_template_item
{
	uint16_t template_id;
	uint16_t field_count;
	struct nf9_fieldtype_and_len typelen[1];
} __attribute__ ((__packed__));

/* IPFIX */
struct ipfix_header
{
	uint16_t version;
	uint16_t length;
	uint32_t export_time;

	uint32_t sequence_number;
	uint32_t observation_domain;
} __attribute__ ((__packed__));

/* IPFIX templates */
struct ipfix_template_header
{
	uint16_t template_id;
	uint16_t field_count;
} __attribute__ ((__packed__));

struct ipfix_inf_element_iana
{
	uint16_t id;
	uint16_t length;
} __attribute__ ((__packed__));

struct ipfix_inf_element_enterprise
{
	uint16_t id;
	uint16_t length;
	uint32_t number;
} __attribute__ ((__packed__));

struct ipfix_stored_template
{
	struct ipfix_template_header header;

	struct ipfix_inf_element_enterprise elements[1];
} __attribute__ ((__packed__));

/* flowset */
struct ipfix_flowset_header
{
	uint16_t flowset_id;
	uint16_t length;
} __attribute__ ((__packed__));


struct nf_flow_info
{
#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX) \
	uint8_t NAME[SIZEMAX];                              \
	int NAME##_size;                                    \
	int has_##NAME;
#include "netflow.def"
	/* virtual fields for export devices */
	uint8_t dev_ip[4];
	int dev_ip_size;
	int has_dev_ip;

	uint8_t dev_id[4];
	int dev_id_size;
	int has_dev_id;

	uint32_t sampling_rate;
};

struct nf_packet_info
{
	struct sockaddr src_addr;
	uint32_t src_addr_ipv4;

	uint32_t source_id;
	uint32_t epoch;
	uint64_t time_ns; /* nanoseconds */
	uint8_t rawpacket[MAX_NF_PACKET_SIZE];

	int sampling_rate;
};

void netflow_process_init(void);
int netflow_process(struct xe_data *data, size_t thread_id,
	struct nf_packet_info *npi, int len);


#endif

