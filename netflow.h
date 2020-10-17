#ifndef netflow_h_included
#define netflow_h_included

#include <netinet/in.h>
#include <sys/types.h>
#include <stdint.h>

#define MAX_NF_PACKET_SIZE (64*1024)

#define MAX_FLOWS_PER_PACKET 100

#define MAX_FIELDS_PER_FLOW 100

#define MAX_FLOW_VAL_LEN 32

#ifdef _MSC_VER
#define PACKED
#pragma pack(push,1)
#else
#define PACKED __attribute__ ((__packed__))
#endif

struct nf9_header
{
	uint16_t version;
	uint16_t count;
	uint32_t sys_uptime;
	uint32_t unix_secs;

	uint32_t package_sequence;
	uint32_t source_id;
} PACKED;

struct nf9_fieldtype_and_len
{
	uint16_t type;
	uint16_t length;
} PACKED;

struct nf9_flowset_header
{
	uint16_t flowset_id;
	uint16_t length;
} PACKED;

struct nf9_template_item
{
	uint16_t template_id;
	uint16_t field_count;
	struct nf9_fieldtype_and_len typelen[1];
} PACKED;

/* IPFIX (we call it netflow 10) */
struct nf10_header
{
	uint16_t version;
	uint16_t length;
	uint32_t export_time;

	uint32_t sequence_number;
	uint32_t observation_domain;
} PACKED;

/* IPFIX templates */
struct nf10_template_header
{
	uint16_t template_id;
	uint16_t field_count;
} PACKED;

struct nf10_inf_element_iana
{
	uint16_t id;
	uint16_t length;
} PACKED;

struct nf10_inf_element_enterprise
{
	uint16_t id;
	uint16_t length;
	uint32_t number;
} PACKED;

struct nf10_stored_template
{
	struct nf10_template_header header;

	struct nf10_inf_element_enterprise elements[1];
} PACKED;

/* flowset */
struct nf10_flowset_header
{
	uint16_t flowset_id;
	uint16_t length;
} PACKED;


#ifdef _MSC_VER
#pragma pack(pop)
#undef PACKED
#else
#undef PACKED
#endif

struct nf_flow_info
{
#define NF_V9_FIELD(NAME, FIELDTYPE, SIZEMIN, SIZEMAX)     \
	uint8_t NAME[SIZEMAX];                             \
	int NAME##_size;                                   \
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

#endif

