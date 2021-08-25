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
	NF_FIELD_BYTES
};

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
#define NF_V9_FIELD(NAME, DESC, FLDTYPE, FLDID,SIZEMIN, SIZEMAX) \
	uint8_t NAME[SIZEMAX];                                   \
	int NAME##_size;                                         \
	int has_##NAME;
#include "netflow_v9.def"
};

struct nf_packet_info
{
	struct sockaddr src_addr;
	uint32_t src_addr_ipv4;

	uint32_t source_id;
	uint32_t epoch;
	uint32_t uptime;
	time_t tmin, tmax;
	uint8_t rawpacket[MAX_NF_PACKET_SIZE];
};

int netflow_process(struct xe_data *data, struct nf_packet_info *npi, int len);


#endif

