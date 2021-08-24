/*
 * xenoeye
 *
 * Copyright (c) 2020-2021, Vladimir Misyurov, Michael Kogan
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <endian.h>
#include <alloca.h>

#include "utils.h"
#include "netflow.h"
#include "netflow_templates.h"
#include "xenoeye.h"
#include "filter.h"

#include "tkvdb.h"

/* construct template key, used as key in persistent k-v templates storage */
static void
make_template_key(struct template_key *tkey, uint16_t template_id,
	struct nf_packet_info *npi, uint8_t version)
{
	xe_ip addr;
	/* currently we support only IPv4 */
	tkey->src_ip_version = 4;

	tkey->nf_version = version;
	tkey->template_id = template_id;

	addr = npi->src_addr_ipv4;
	memcpy(&tkey->source_ip, &addr, sizeof(xe_ip));

	tkey->source_id = npi->source_id;
	tkey->epoch = npi->epoch;
}

static void
template_dump(struct template_key *tkey)
{
	size_t i;
	char buf[512];
	unsigned char *data = (unsigned char *)tkey;

	buf[0] = '\0';
	for (i=0; i<sizeof(struct template_key); i++) {
		char sym[5];

		sprintf(sym, "%02x ", data[i]);
		strcat(buf, sym);
	}
	LOG("%s", buf);
}

static int
table_process(struct xe_data *data, struct filter_expr *expr,
	struct nf_flow_info *flow)
{
	int ret;

	ret = filter_match(expr, flow);
/*	LOG("MATCH: %d", ret);*/
	return ret;
}


static int
parse_netflow_v9_template(struct xe_data *data, struct nf_packet_info *npi,
	uint8_t **ptr, int length)
{
	struct nf9_template_item *tmplitem, *ptmpl;
	uint16_t template_id, field_count;
	struct template_key tkey;
	int template_size;

	ptmpl = (struct nf9_template_item *)(*ptr);
	template_id = ptmpl->template_id;
	field_count = ntohs(ptmpl->field_count);

	template_size = 4 + field_count * 4;
	if (template_size > length) {
		/* packet too short */
		LOG("Template is too short (size: %d, packet length %d)",
			template_size, length);
		LOG("******************");
		return 0;
	}
/*
	LOG("Template id %d, field count: %u", ntohs(template_id),
		field_count);
*/
	/* search for template in database */
	make_template_key(&tkey, template_id, npi, 9);
	tmplitem = netflow_template_find(&tkey,
		data->allow_templates_in_future);

	*ptr += template_size;

	if (!tmplitem) {
		LOG("Unknown template, id %d", ntohs(template_id));
		template_dump(&tkey);
		return netflow_template_add(&tkey, ptmpl, template_size);
	}

	if (memcmp(ptmpl, tmplitem, template_size) != 0) {
		LOG("Template modified");
		return netflow_template_add(&tkey, ptmpl, template_size);
	}

	return 1;
}

static int
parse_netflow_v9_flowset(struct xe_data *data, struct nf_packet_info *npi,
	uint8_t **ptr, int flowset_id, int length, int count)
{
	uint8_t *fptr;
	int cnt, i;
	struct nf9_template_item *tmpl;
	struct template_key tkey;
	int template_field_count;
	size_t t_id;
/*
	LOG("v9 data, flowset: %d, length == %d, count = %d",
		ntohs(flowset_id), length, count);
*/
	make_template_key(&tkey, flowset_id, npi, 9);
	tmpl = netflow_template_find(&tkey, data->allow_templates_in_future);

	if (!tmpl) {
/*		LOG("Unknown flowset id %d", ntohs(flowset_id));*/
		return 0;
	}

	template_field_count = ntohs(tmpl->field_count);

	fptr = (*ptr);
	for (cnt=0; cnt<count; cnt++) {
		struct nf_flow_info flow;

		memset(&flow, 0, sizeof(struct nf_flow_info));

/*		LOG("Flowset #%d", cnt);*/
		for (i=0; i<template_field_count; i++) {
			int flength, ftype;

			flength = ntohs(tmpl->typelen[i].length);
			ftype = ntohs(tmpl->typelen[i].type);

#define NF_V9_FIELD(NAME, FIELDTYPE, SIZEMIN, SIZEMAX)                        \
if (ftype == FIELDTYPE) {                                                     \
	if ((flength < SIZEMIN) || (flength > SIZEMAX)) {                     \
		LOG("Incorrect '" #NAME                                       \
			"' field size (got %d, expected from %d to %d)",      \
			flength, SIZEMIN, SIZEMAX);                           \
	} else {                                                              \
		memcpy(&flow.NAME, fptr, flength);                            \
		/*LOG("Field: '"#NAME"', length: %d", flength);*/             \
		flow.has_##NAME = 1;                                          \
		flow.NAME##_size = flength;                                   \
	}                                                                     \
}
#include "netflow_v9.def"


			fptr += flength;

			if ((fptr - (*ptr)) >= length) {
				break;
			}
		}

		for (t_id=0; t_id<data->nmonit_items; t_id++) {
			table_process(data, data->monit_items[t_id].expr,
				&flow);
		}
/*
		if (flow.has_last_switched) {
			uint32_t *time = (uint32_t *)flow.last_switched;
			LOG("LAST SWITCHED: %d (%u/%d)",
			npi->uptime - (unsigned int)*time,
			(unsigned int)*time,
			npi->uptime);
		}
*/
	}
	(*ptr) += length;
	return 1;
}

static int
parse_netflow_v9(struct xe_data *data, struct nf_packet_info *npi, int len)
{
	struct nf9_header *header;
	int flowset_id, flowset_id_host, length, count;
	uint8_t *ptr;

	npi->tmin = 0;
	npi->tmax = 0;

	header = (struct nf9_header *)npi->rawpacket;
	npi->source_id = header->source_id;
	npi->epoch = header->unix_secs;
	npi->uptime = htonl(header->sys_uptime);
/*
	LOG("got v9, package sequence: %u, source id %u, length %d",
		ntohl(header->package_sequence),
		ntohl(npi->source_id),
		len);
*/

	ptr = (uint8_t *)npi->rawpacket + sizeof(struct nf9_header);

	while (ptr < ((uint8_t *)npi->rawpacket + len)) {
		struct nf9_flowset_header *flowset_header;

		flowset_header = (struct nf9_flowset_header *)ptr;

		flowset_id = flowset_header->flowset_id;
		flowset_id_host = ntohs(flowset_id);
		length = ntohs(flowset_header->length);
		count = ntohs(header->count);

		ptr += 4;

		if (flowset_id_host == 0) {
			if (!parse_netflow_v9_template(data, npi, &ptr,
				length)) {
				/* something went wrong in template parser */
				return 0;
			}
		} else if (flowset_id_host == 1) {
			LOG("options template");
			break;
		} else {
			if (!parse_netflow_v9_flowset(data, npi, &ptr,
				flowset_id, length, count)) {

				break;
			}
		}
	}
/*
	LOG("end of v9");
	LOG("========================");
*/
	return 1;
}

/*
 * each item (both ipfix_inf_element_iana and ipfix_inf_element_enterprise)
 * in template converted to ipfix_inf_element_enterprise
 */
static void
ipfix_template_convert(struct ipfix_stored_template *tmpl, uint8_t **ptr,
	unsigned int field_count)
{
	unsigned int i;

	/* copy template header */
	memcpy(tmpl, *ptr, sizeof(struct ipfix_template_header));

	/* skip header, seek to data */
	*ptr += sizeof(struct ipfix_template_header);

	for (i=0; i<field_count; i++) {
		struct ipfix_inf_element_enterprise *ent;

		ent = (struct ipfix_inf_element_enterprise *)(*ptr);
		LOG("id: %d, length: %d", ntohs(ent->id), ntohs(ent->length));
		if ((ntohs(ent->id) >> 15) & 1) {
			/* enterprise */
			tmpl->elements[i].id = ent->id;
			tmpl->elements[i].length = ent->length;
			tmpl->elements[i].number = ent->number;
			*ptr += sizeof(struct ipfix_inf_element_enterprise);
		} else {
			/* iana */
			tmpl->elements[i].id = ent->id;
			tmpl->elements[i].length = ent->length;
			tmpl->elements[i].number = 0;
			*ptr += sizeof(struct ipfix_inf_element_iana);
		}
	}
}

static int
parse_ipfix_template(struct xe_data *data, struct nf_packet_info *npi,
	uint8_t **ptr, int length)
{
	struct ipfix_template_header *tmpl_header;
	struct ipfix_stored_template *tmpl_db, *tmpl;

	uint16_t template_id, field_count;
	struct template_key tkey;
	size_t template_size;

	tmpl_header = (struct ipfix_template_header *)(*ptr);
	template_id = tmpl_header->template_id;
	field_count = ntohs(tmpl_header->field_count);

	LOG("ipfix: template id %d, field count: %u", ntohs(template_id),
		field_count);

	/* search for template in database */
	if (field_count < 1) {
		LOG("ipfix: incorrect field count %u", field_count);
		return 0;
	}

	template_size = sizeof(struct ipfix_template_header)
		+ sizeof(struct ipfix_inf_element_enterprise) * field_count;
	tmpl = alloca(template_size);

	ipfix_template_convert(tmpl, ptr, field_count);

	make_template_key(&tkey, template_id, npi, 10);
	tmpl_db = netflow_template_find(&tkey,
		data->allow_templates_in_future);

	if (!tmpl_db) {
		return netflow_template_add(&tkey, tmpl, template_size);
	}

	if (memcmp(tmpl_db, tmpl, template_size) != 0) {
		LOG("Template ipfix modified");
		return netflow_template_add(&tkey, tmpl, template_size);
	}

	return 1;
}

static int
parse_ipfix_flowset(struct xe_data *data, struct nf_packet_info *npi,
	uint8_t **ptr, int flowset_id, int length)
{
	uint8_t *fptr;
	int i;
	struct ipfix_stored_template *tmpl;
	struct template_key tkey;
	int template_field_count;
	int stop = 0;
	int flow_num = 0;

	LOG("ipfix data, flowset: %d, length == %d", ntohs(flowset_id),
		length);

	make_template_key(&tkey, flowset_id, npi, 10);
	tmpl = netflow_template_find(&tkey, data->allow_templates_in_future);

	if (!tmpl) {
		LOG("Unknown flowset id %d", ntohs(flowset_id));
		return 0;
	}

	template_field_count = ntohs(tmpl->header.field_count);

	fptr = (*ptr);

	while (!stop) {
/*		struct nf_flow_info flow_info;*/

		if ((length - (fptr - (*ptr))) < template_field_count) {
			break;
		}

		LOG("flow #%d", flow_num);
/*		memset(&flow_info, 0, sizeof(flow_info));*/

		for (i=0; i<template_field_count; i++) {
			int flength, ftype;

			flength = ntohs(tmpl->elements[i].length);
			ftype = ntohs(tmpl->elements[i].id);

			if (ftype == 2) {
				uint64_t packets;

				memcpy(&packets, fptr, flength);
				packets = be64toh(packets);
				LOG("packets: %lu", packets);
/*				flow_info.packets = packets;*/
			}
			if (ftype == 153) {
				uint64_t last_uptime;

				memcpy(&last_uptime, fptr, flength);
				last_uptime = be64toh(last_uptime);
				LOG("flowStartMilliseconds: %lu (uptime: %u)",
					 last_uptime, npi->uptime);
/*				flow_info.end = last_uptime;*/
			}
			if (ftype == 152) {
				uint64_t first_uptime;

				memcpy(&first_uptime, fptr, flength);
				first_uptime = be64toh(first_uptime);
				LOG("flowEndMilliseconds: %lu",
					first_uptime);
/*				flow_info.start = first_uptime;*/
			}

			LOG("Field type: %d, length == %d, first byte == %d",
				ftype, flength, fptr[0]);
			fptr += flength;

			if ((fptr - (*ptr)) >= length) {
				stop = 1;
				break;
			}
		}
		flow_num++;
/*		printf("%lu %lu\n", flow_info.end / 1000, flow_info.packets);*/
	}
	return 1;
}


static int
parse_ipfix(struct xe_data *data, struct nf_packet_info *npi, int len)
{
	struct ipfix_header *header;
	int flowset_id, flowset_id_host, length;
	uint8_t *ptr;

	npi->tmin = 0;
	npi->tmax = 0;

	header = (struct ipfix_header *)npi->rawpacket;
	npi->source_id = header->observation_domain;
	npi->epoch = header->export_time;
	npi->uptime = 0;

	LOG("got ipfix, package sequence: %u, source id %u, length %d",
		ntohl(header->sequence_number),
		ntohl(npi->source_id),
		len);


	ptr = (uint8_t *)npi->rawpacket + sizeof(struct ipfix_header);

	while (ptr < ((uint8_t *)npi->rawpacket + len)) {
		struct ipfix_flowset_header *flowset_header;

		flowset_header = (struct ipfix_flowset_header *)ptr;

		flowset_id = flowset_header->flowset_id;
		flowset_id_host = ntohs(flowset_id);
		length = ntohs(flowset_header->length);

		ptr += sizeof(struct ipfix_flowset_header);

		LOG("Flowset %u, length %u", flowset_id_host, length);

		if (flowset_id_host == 2) {
			if (!parse_ipfix_template(data, npi, &ptr,
				length)) {
				/* something went wrong in template parser */
				break;
			}
		} else if (flowset_id_host == 3) {
			LOG("options template ipfix, skipping");
		} else if (flowset_id_host > 255) {
			/* data */
			if (!parse_ipfix_flowset(data, npi, &ptr,
				flowset_id, length)) {

				break;
			}
		} else {
			LOG("unknown flowset id %u", flowset_id_host);
			/* skip flowset */
		}

		ptr += length - sizeof(struct ipfix_flowset_header);
	}
	LOG("end of ipfix");
	LOG("========================");
	return 1;
}

int
netflow_process(struct xe_data *data, struct nf_packet_info *npi, int len)
{
	uint16_t *version_ptr;
	int version;
	int ret = 0;

	version_ptr = (uint16_t *)npi->rawpacket;
	version = ntohs(*version_ptr);
	switch (version) {
		case 5:
			LOG("not supported yet");
			break;
		case 9:
			ret = parse_netflow_v9(data, npi, len);
			break;
		case 10:
			ret = parse_ipfix(data, npi, len);
			break;
		default:
			LOG("Unknown netflow version %u", version);
			break;
	}

	return ret;
}

