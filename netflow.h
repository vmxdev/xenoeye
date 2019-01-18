#ifndef netflow_h_included
#define netflow_h_included

#include <sys/types.h>
#include <stdint.h>

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

#ifdef _MSC_VER
#pragma pack(pop)
#undef PACKED
#else
#undef PACKED
#endif

#endif

