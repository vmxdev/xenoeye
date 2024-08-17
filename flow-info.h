#ifndef flow_info_h_included
#define flow_info_h_included

#include <stdint.h>
#include <netinet/in.h>

#define MAX_NF_PACKET_SIZE (64*1024)
#define CLASS_NAME_MAX 32

struct flow_info
{
#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX) \
	uint8_t NAME[SIZEMAX];                              \
	int NAME##_size;                                    \
	int has_##NAME;
#include "netflow.def"
	void *payload_ptr;

	/* virtual fields for export devices */
	uint8_t dev_ip[4];
	int dev_ip_size;
	int has_dev_ip;

	uint8_t dev_ip6[16];
	int dev_ip6_size;
	int has_dev_ip6;

	uint8_t dev_id[4];
	int dev_id_size;
	int has_dev_id;

	uint8_t dev_mark[4];
	int dev_mark_size;
	int has_dev_mark;

	uint32_t sampling_rate;
};

struct flow_packet_info
{
	struct sockaddr src_addr;
	uint32_t src_addr_ipv4;

	uint32_t source_id;
	uint32_t epoch;
	uint64_t time_ns; /* nanoseconds */
	uint8_t rawpacket[MAX_NF_PACKET_SIZE];

	int sampling_rate;
};


#endif

