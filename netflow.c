/*
 * xenoeye
 *
 * Copyright (c) 2020-2025, Vladimir Misyurov, Michael Kogan
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
#include <endian.h>

#include "tkvdb.h"

#include "utils.h"
#include "netflow.h"
#include "netflow-templates.h"
#include "xenoeye.h"
#include "filter.h"
#include "flow-debug.h"
#include "devices.h"
#include "flow-info.h"


typedef void (*flow_parse_func_t)(struct flow_info *, int, uint8_t *);

struct nf_parse_data
{
	struct nf9_template_item *tmpl_9;
	struct ipfix_stored_template *tmpl_ipfix;
	int template_field_count;
	uint8_t **ptr;
	uint8_t *tmpfptr;
	int length;
};

static flow_parse_func_t flow_parse_functions[UINT16_MAX];

/* construct template key, used as key in persistent k-v templates storage */
static void
make_template_key(struct template_key *tkey, uint16_t template_id,
	struct flow_packet_info *fpi, uint8_t version)
{
	xe_ip addr;
	/* currently we support only IPv4 */
	tkey->src_ip_version = 4;

	tkey->nf_version = version;
	tkey->template_id = template_id;

	addr = fpi->src_addr_ipv4;
	memcpy(&tkey->source_ip, &addr, sizeof(xe_ip));

	tkey->source_id = fpi->source_id;
	/*tkey->epoch = fpi->epoch;*/
	tkey->epoch = time(NULL);
}

/* make a separate function for each known field */
#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)                   \
static void                                                                   \
flow_parse_##FLDID(struct flow_info *flow, int flength, uint8_t *fptr)        \
{                                                                             \
	if ((flength < SIZEMIN) || (flength > SIZEMAX)) {                     \
		LOG("Incorrect '" #NAME                                       \
			"' field size (got %d, expected from %d to %d)",      \
			flength, SIZEMIN, SIZEMAX);                           \
	} else {                                                              \
		if (FLDTYPE == NF_FIELD_STRING) {                             \
			memcpy(&flow->NAME[0], fptr, flength);                \
		} else {                                                      \
			memcpy(&flow->NAME[SIZEMAX - flength], fptr, flength);\
		}                                                             \
		/*LOG("Field: '"#NAME"', length: %d", flength);*/             \
		flow->has_##NAME = 1;                                         \
		flow->NAME##_size = flength;                                  \
	}                                                                     \
}
#include "netflow.def"

/* function for unknown field */
static void
flow_parse_unknown(struct flow_info *flow, int flength, uint8_t *fptr)
{
	(void)flow;
	(void)flength;
	(void)fptr;

	/* do nothing */
}


static void
virtual_fields_init(struct flow_info *flow, struct flow_packet_info *fpi)
{
	memcpy(&flow->dev_ip[0], &fpi->src_addr_ipv4, sizeof(uint32_t));
	flow->dev_ip_size = sizeof(uint32_t);
	flow->has_dev_ip = 1;

	memcpy(&flow->dev_id[0], &fpi->source_id, sizeof(uint32_t));
	flow->dev_id_size = sizeof(uint32_t);
	flow->has_dev_id = 1;

	flow->sampling_rate = fpi->sampling_rate;
}

static void
sampling_rate_init(struct flow_packet_info *fpi)
{
	struct device dev;

	/* FIXME: add IPv6 */
	dev.ip_ver = 4;
	dev.ip = 0;
	memcpy(&dev.ip, &fpi->src_addr_ipv4, 4);

	dev.id = fpi->source_id;

	if (device_get_sampling_rate(&dev)) {
		fpi->sampling_rate = dev.sampling_rate;
	} else {
		/* device not found in database */
		fpi->sampling_rate = 1;
	}
}


static int
parse_netflow_v9_template(struct xe_data *data, struct flow_packet_info *fpi,
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
		return 0;
	}

	/* search for template in database */
	make_template_key(&tkey, template_id, fpi, 9);
	tmplitem = netflow_template_find(&tkey,
		data->allow_templates_in_future);

	*ptr += template_size;

	if (!tmplitem) {
		LOG("Unknown template, id %d", ntohs(template_id));
		return netflow_template_add(&tkey, ptmpl, template_size);
	}

	if (memcmp(ptmpl, tmplitem, template_size) != 0) {
		LOG("Template modified");
		return netflow_template_add(&tkey, ptmpl, template_size);
	}

	return 1;
}

static void
print_netflow_v9_flowset(struct nf_parse_data *pd, char *debug_flow_str)
{
	int i;

	debug_flow_str[0] = '\0';
	for (i=0; i<pd->template_field_count; i++) {
		int flength, ftype;

		flength = ntohs(pd->tmpl_9->typelen[i].length);
		ftype = ntohs(pd->tmpl_9->typelen[i].type);

		flow_debug_add_field(flength, ftype, pd->tmpfptr,
			debug_flow_str);

		pd->tmpfptr += flength;

		if ((pd->tmpfptr - (*(pd->ptr))) >= pd->length) {
			break;
		}
	}
}


static void
process_mo_nf9_rec(struct xe_data *globl, struct flow_packet_info *fpi,
	size_t thread_id, struct flow_info *flow,
	struct nf_parse_data *pd,
	struct monit_object *mos, size_t n_mo)
{
	size_t i;
	for (i=0; i<n_mo; i++) {
		struct monit_object *mo = &mos[i];

		if (!filter_match(mo->expr, flow)) {
			continue;
		}

		monit_object_process_nf(globl, mo, thread_id, fpi->time_ns,
			flow);

		if (mo->debug.print_flows) {
			char debug_flow_str[1024];

			print_netflow_v9_flowset(pd, debug_flow_str);

			flow_print_str(&mo->debug, flow, debug_flow_str);
		}

		/* child objects */
		if (mo->n_mo) {
			process_mo_nf9_rec(globl, fpi, thread_id, flow, pd,
				mo->mos, mo->n_mo);
		}
	}
}

static int
parse_netflow_v9_flowset(struct xe_data *globl, size_t thread_id, 
	struct flow_packet_info *fpi, uint8_t **ptr,
	int flowset_id, int length, int count)
{
	struct nf_parse_data pd;

	uint8_t *fptr;
	int cnt, i;
	struct template_key tkey;

	pd.ptr = ptr;
	pd.length = length;

	make_template_key(&tkey, flowset_id, fpi, 9);
	pd.tmpl_9 = netflow_template_find(&tkey,
		globl->allow_templates_in_future);

	if (!pd.tmpl_9) {
/*		LOG("Unknown flowset id %d", ntohs(flowset_id));*/
		return 0;
	}

	pd.template_field_count = ntohs(pd.tmpl_9->field_count);

	fptr = (*ptr);
	for (cnt=0; cnt<count; cnt++) {
		struct flow_info flow;

		memset(&flow, 0, sizeof(struct flow_info));
		pd.tmpfptr = fptr;

		for (i=0; i<pd.template_field_count; i++) {
			int flength, ftype;

			flength = ntohs(pd.tmpl_9->typelen[i].length);
			ftype = ntohs(pd.tmpl_9->typelen[i].type);

			flow_parse_functions[ftype](&flow, flength, fptr);

			fptr += flength;

			if ((fptr - (*ptr)) >= length) {
				break;
			}
		}
		/* virtual fields */
		virtual_fields_init(&flow, fpi);
		if (!device_rules_check(&flow, fpi)) {
			continue;
		}

		/* debug print */
		if (globl->debug.print_flows) {
			char debug_flow_str[1024];

			print_netflow_v9_flowset(&pd, debug_flow_str);

			flow_print_str(&globl->debug, &flow, debug_flow_str);
		}

		process_mo_nf9_rec(globl, fpi, thread_id, &flow, &pd,
				globl->monit_objects, globl->nmonit_objects);

#ifdef FLOWS_CNT
		atomic_fetch_add_explicit(&data->nflows, 1,
			memory_order_relaxed);
#endif
	}
	(*ptr) += length;
	return 1;
}

static int
parse_netflow_v9(struct xe_data *data, size_t thread_id,
	struct flow_packet_info *fpi, int len)
{
	struct nf9_header *header;
	int flowset_id, flowset_id_host, length, count;
	uint8_t *ptr;

	header = (struct nf9_header *)fpi->rawpacket;
	fpi->source_id = header->source_id;
	fpi->epoch = header->unix_secs;

	sampling_rate_init(fpi);

	ptr = (uint8_t *)fpi->rawpacket + sizeof(struct nf9_header);

	while (ptr < ((uint8_t *)fpi->rawpacket + len)) {
		struct nf9_flowset_header *flowset_header;

		flowset_header = (struct nf9_flowset_header *)ptr;

		flowset_id = flowset_header->flowset_id;
		flowset_id_host = ntohs(flowset_id);
		length = ntohs(flowset_header->length);
		count = ntohs(header->count);

		ptr += 4;

		if (flowset_id_host == 0) {
			if (!parse_netflow_v9_template(data, fpi, &ptr,
				length)) {
				/* something went wrong in template parser */
				return 0;
			}
		} else if (flowset_id_host == 1) {
			LOG("options template");
			break;
		} else {
			if (!parse_netflow_v9_flowset(data, thread_id, fpi,
				&ptr, flowset_id, length, count)) {

				break;
			}
		}
	}
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
parse_ipfix_template(struct xe_data *data, struct flow_packet_info *fpi,
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

	/* search for template in database */
	if (field_count < 1) {
		LOG("ipfix: incorrect field count %u", field_count);
		return 0;
	}

	template_size = sizeof(struct ipfix_template_header)
		+ sizeof(struct ipfix_inf_element_enterprise) * field_count;
	tmpl = alloca(template_size);

	ipfix_template_convert(tmpl, ptr, field_count);

	make_template_key(&tkey, template_id, fpi, 10);
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

static void
print_ipfix_flowset(struct nf_parse_data *pd,
	char *debug_flow_str)
{
	int i;

	debug_flow_str[0] = '\0';
	for (i=0; i<pd->template_field_count; i++) {
		int flength, ftype;

		flength = ntohs(pd->tmpl_ipfix->elements[i].length);
		ftype = ntohs(pd->tmpl_ipfix->elements[i].id);

		flow_debug_add_field(flength, ftype, pd->tmpfptr,
			debug_flow_str);

		pd->tmpfptr += flength;

		if ((pd->tmpfptr - (*(pd->ptr))) >= pd->length) {
			break;
		}
	}
}

static void
process_mo_ipfix_rec(struct xe_data *globl, struct flow_packet_info *fpi,
	size_t thread_id, struct flow_info *flow,
	struct nf_parse_data *pd,
	struct monit_object *mos, size_t n_mo)
{
	size_t i;
	for (i=0; i<n_mo; i++) {
		struct monit_object *mo = &mos[i];

		if (!filter_match(mo->expr, flow)) {
			continue;
		}

		monit_object_process_nf(globl, mo, thread_id, fpi->time_ns,
			flow);

		if (mo->debug.print_flows) {
			char debug_flow_str[1024];

			print_ipfix_flowset(pd, debug_flow_str);

			flow_print_str(&mo->debug, flow, debug_flow_str);
		}

		/* child objects */
		if (mo->n_mo) {
			process_mo_ipfix_rec(globl, fpi, thread_id, flow, pd,
				mo->mos, mo->n_mo);
		}
	}
}

static int
parse_ipfix_flowset(struct xe_data *globl, size_t thread_id,
	struct flow_packet_info *fpi, uint8_t **ptr, int flowset_id, int length)
{
	struct nf_parse_data pd;

	uint8_t *fptr;
	int i;
	struct template_key tkey;
	int stop = 0;

	pd.ptr = ptr;
	pd.length = length;

	make_template_key(&tkey, flowset_id, fpi, 10);
	pd.tmpl_ipfix = netflow_template_find(&tkey,
		globl->allow_templates_in_future);

	if (!pd.tmpl_ipfix) {
		LOG("Unknown flowset id %d", ntohs(flowset_id));
		return 0;
	}

	pd.template_field_count = ntohs(pd.tmpl_ipfix->header.field_count);

	fptr = (*ptr);
	while (!stop) {
		struct flow_info flow;

		if ((length - (fptr - (*ptr))) < pd.template_field_count) {
			break;
		}

		memset(&flow, 0, sizeof(struct flow_info));
		pd.tmpfptr = fptr;

		for (i=0; i<pd.template_field_count; i++) {
			int flength, ftype;

			flength = ntohs(pd.tmpl_ipfix->elements[i].length);
			ftype = ntohs(pd.tmpl_ipfix->elements[i].id);

			flow_parse_functions[ftype](&flow, flength, fptr);

			fptr += flength;

			if ((fptr - (*ptr)) >= length) {
				stop = 1;
				break;
			}
		}
		/* virtual fields */
		virtual_fields_init(&flow, fpi);
		if (!device_rules_check(&flow, fpi)) {
			continue;
		}

		if (globl->debug.print_flows) {
			char debug_flow_str[1024];

			print_ipfix_flowset(&pd, debug_flow_str);

			flow_print_str(&globl->debug, &flow,
				debug_flow_str);
		}

		process_mo_ipfix_rec(globl, fpi, thread_id, &flow, &pd,
			globl->monit_objects, globl->nmonit_objects);

#ifdef FLOWS_CNT
		atomic_fetch_add_explicit(&data->nflows, 1,
			memory_order_relaxed);
#endif
	}
	return 1;
}


static int
parse_ipfix(struct xe_data *data, size_t thread_id,
	struct flow_packet_info *fpi, int len)
{
	struct ipfix_header *header;
	int flowset_id, flowset_id_host, length;
	uint8_t *ptr;

	header = (struct ipfix_header *)fpi->rawpacket;
	fpi->source_id = header->observation_domain;
	fpi->epoch = header->export_time;

	sampling_rate_init(fpi);

	ptr = (uint8_t *)fpi->rawpacket + sizeof(struct ipfix_header);

	while (ptr < ((uint8_t *)fpi->rawpacket + len)) {
		struct ipfix_flowset_header *flowset_header;

		flowset_header = (struct ipfix_flowset_header *)ptr;

		flowset_id = flowset_header->flowset_id;
		flowset_id_host = ntohs(flowset_id);
		length = ntohs(flowset_header->length);

		ptr += sizeof(struct ipfix_flowset_header);

		if (flowset_id_host == 2) {
			if (!parse_ipfix_template(data, fpi, &ptr,
				length)) {
				/* something went wrong in template parser */
				break;
			}
		} else if (flowset_id_host == 3) {
			LOG("options template ipfix, skipping");
		} else if (flowset_id_host > 255) {
			/* data */
			if (!parse_ipfix_flowset(data, thread_id, fpi, &ptr,
				flowset_id, length)) {

				break;
			}
		} else {
			LOG("unknown flowset id %u", flowset_id_host);
			/* skip flowset */
		}

		ptr += length - sizeof(struct ipfix_flowset_header);
	}
	return 1;
}

static void
print_netflow_v5_flowset(struct flow_info *flow, char *debug_flow_str)
{
	debug_flow_str[0] = '\0';

#define FIELD(USE, TYPE, V5, V9, ID)                                 \
	if (USE) {                                                   \
		flow_debug_add_field(sizeof(flow->V9), ID, flow->V9, \
			debug_flow_str);                             \
	}
NF5_FIELDS
#undef FIELD

}

static void
process_mo_nf5_rec(struct xe_data *globl, struct flow_packet_info *fpi,
	size_t thread_id, struct flow_info *flow,
	struct monit_object *mos, size_t n_mo)
{
	size_t i;
	for (i=0; i<n_mo; i++) {
		struct monit_object *mo = &mos[i];

		if (!filter_match(mo->expr, flow)) {
			continue;
		}

		monit_object_process_nf(globl, mo, thread_id, fpi->time_ns,
			flow);

		if (mo->debug.print_flows) {
			char debug_flow_str[1024];

			print_netflow_v5_flowset(flow, debug_flow_str);

			flow_print_str(&mo->debug, flow, debug_flow_str);
		}

		/* child objects */
		if (mo->n_mo) {
			process_mo_nf5_rec(globl, fpi, thread_id, flow,
				mo->mos, mo->n_mo);
		}
	}
}

static int
parse_netflow_v5(struct xe_data *globl, size_t thread_id,
	struct flow_packet_info *fpi, int length)
{
	int i;
	struct nf5_packet *pkt = (struct nf5_packet *)fpi->rawpacket;
	int nflows = ntohs(pkt->header.count);

	if ((int)(sizeof(struct nf5_header) + sizeof(struct nf5_flow) * nflows)
		!= length) {

		LOG("Invalid number of flows: %d", nflows);
		return 0;
	}

	fpi->source_id = pkt->header.engine_id;
	fpi->epoch = pkt->header.unix_secs;

	sampling_rate_init(fpi);

	for (i=0; i<nflows; i++) {
		struct flow_info flow;
//		size_t t_id;

		memset(&flow, 0, sizeof(struct flow_info));

		/* parse flow */
#define FIELD(USE, TYPE, V5, V9, ID)                                      \
	if (USE) {                                                        \
		size_t shift = sizeof(flow.V9) - sizeof(TYPE);            \
		memcpy(&flow.V9[shift], &pkt->flows[i].V5, sizeof(TYPE)); \
		flow.has_##V9 = 1;                                        \
		flow.V9##_size = sizeof(TYPE);                            \
	}
NF5_FIELDS
#undef FIELD

		virtual_fields_init(&flow, fpi);
		if (!device_rules_check(&flow, fpi)) {
			continue;
		}

		/* debug print */
		if (globl->debug.print_flows) {
			char debug_flow_str[1024];

			print_netflow_v5_flowset(&flow, debug_flow_str);
			flow_print_str(&globl->debug, &flow, debug_flow_str);
		}

		process_mo_nf5_rec(globl, fpi, thread_id, &flow,
			globl->monit_objects, globl->nmonit_objects);

#ifdef FLOWS_CNT
		atomic_fetch_add_explicit(&data->nflows, 1,
			memory_order_relaxed);
#endif
	}

	return 1;
}

int
netflow_process(struct xe_data *data, size_t thread_id,
	struct flow_packet_info *fpi, int len)
{
	uint16_t *version_ptr;
	int version;
	struct timespec tmsp;
	int ret = 0;

	/* get time for moving averages */
	if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
		LOG("clock_gettime() failed: %s", strerror(errno));
		return 0;
	}
	fpi->time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

	version_ptr = (uint16_t *)fpi->rawpacket;
	version = ntohs(*version_ptr);
	switch (version) {
		case 5:
			ret = parse_netflow_v5(data, thread_id, fpi, len);
			break;
		case 9:
			ret = parse_netflow_v9(data, thread_id, fpi, len);
			break;
		case 10:
			ret = parse_ipfix(data, thread_id, fpi, len);
			break;
		default:
			LOG("Unknown netflow version %u", version);
			break;
	}

	return ret;
}

void
netflow_process_init(void)
{
	int i;

	for (i=0; i<UINT16_MAX; i++) {
		flow_parse_functions[i] = &flow_parse_unknown;
	}

#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)                   \
	flow_parse_functions[FLDID] = flow_parse_##FLDID;
#include "netflow.def"

}

