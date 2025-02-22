/*
 * xenoeye
 *
 * Copyright (c) 2021-2023, Vladimir Misyurov, Michael Kogan
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

#include <errno.h>
#include "netflow.h"
#include "utils.h"

#include "flow-debug.h"
#include "flow-info.h"

typedef void (*flow_fldprnt_func_t)(char *str, int flength, uint8_t *fptr);
static flow_fldprnt_func_t flow_fldprnt_functions[UINT16_MAX];

static void
flow_field_print_bytes(char *str, int flength, char *desc, uint8_t *fptr)
{
	int i;

	sprintf(str, "%s: ", desc);
	for (i=0; i<flength; i++) {
		sprintf(str + strlen(str), "0x%02x ", *(fptr + i));
	}
}

#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)                   \
static void                                                                   \
flow_field_print_##FLDID(char *str, int flength, uint8_t *fptr)               \
{                                                                             \
	if (FLDTYPE == NF_FIELD_BYTES) {                                      \
		flow_field_print_bytes(str, flength, DESC, fptr);             \
		return;                                                       \
	}                                                                     \
	if (flength == 1) {                                                   \
		sprintf(str, "%s: %u", DESC, *fptr);                          \
	} else if (flength == 2) {                                            \
		sprintf(str, "%s: %u", DESC, ntohs(*((uint16_t *)fptr)));     \
	} else if (flength == 4) {                                            \
		if (FLDTYPE == NF_FIELD_IP_ADDR) {                            \
			sprintf(str, "%s: %u.%u.%u.%u", DESC,                 \
				*(fptr + 0), *(fptr + 1),                     \
				*(fptr + 2), *(fptr + 3));                    \
		} else {                                                      \
			sprintf(str, "%s: %u", DESC,                          \
				ntohl(*((uint32_t *)fptr)));                  \
		}                                                             \
	} else if ((flength == 8) && (FLDTYPE == NF_FIELD_INT)) {             \
		sprintf(str, "%s: %lu", DESC,                                 \
			be64toh(*((uint64_t *)fptr)));                        \
	} else if ((flength == 16) && (FLDTYPE == NF_FIELD_IP_ADDR)) {        \
		/* FIXME: hmm */                                              \
		sprintf(str, "%s: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"       \
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x", DESC,          \
			*(fptr + 0), *(fptr + 1), *(fptr + 2), *(fptr + 3),   \
			*(fptr + 4), *(fptr + 5), *(fptr + 6), *(fptr + 7),   \
			*(fptr + 8), *(fptr + 9), *(fptr + 10), *(fptr + 11), \
			*(fptr + 12), *(fptr + 13), *(fptr + 14), *(fptr + 15));\
	} else {                                                              \
		flow_field_print_bytes(str, flength, DESC, fptr);             \
	}                                                                     \
}
#include "netflow.def"

void
flow_debug_add_field(int flength, int ftype, uint8_t *fptr,
	char *debug_flow_str)
{
	char flow_str[128];

	if (debug_flow_str[0]) {
		strcat(debug_flow_str, "; ");
	}

	if (flow_fldprnt_functions[ftype]) {
		flow_fldprnt_functions[ftype](flow_str, flength, fptr);
	} else {
		int i;
		sprintf(flow_str, "Unknown field %d: ", ftype);
		for (i=0; i<flength; i++) {
			sprintf(flow_str + strlen(flow_str),
				"0x%02x ", *(fptr + i));
		}
	}

	strcat(debug_flow_str, flow_str);
}

void
flow_print_str(struct xe_debug *debug, struct flow_info *fi, char *flow_str,
	int is_sflow)
{
	char devinfo[128];
	char classinfo[16 + CLASS_NAME_MAX];
	uint32_t dev_id;

	/* print classes */
#define DO(ID, CLASS)                                               \
	if (fi->has_##CLASS) {                                      \
		sprintf(classinfo, "; *"#CLASS": %s", fi->CLASS);   \
		strcat(flow_str, classinfo);                        \
	}
FOR_LIST_OF_CLASSES
#undef DO

	memcpy(&dev_id, &fi->dev_id[0], sizeof(uint32_t));

	if (is_sflow) {
		sprintf(devinfo, "; *dev-id: %d, *rate: %u",
			ntohl(dev_id),
			fi->sampling_rate);
	} else {
		sprintf(devinfo, "; *dev-ip: %d.%d.%d.%d; *dev-id: %d, *rate: %u",
			fi->dev_ip[0], fi->dev_ip[1],
			fi->dev_ip[2], fi->dev_ip[3],
			ntohl(dev_id),
			fi->sampling_rate);
	}

	strcat(flow_str, devinfo);

	if (debug->print_to_syslog) {
		LOG("%s", flow_str);
	} else {
		fprintf(debug->fout, "%s\n", flow_str);
	}
}

void
sflow_debug_print(struct flow_info *flow, char *resstr)
{
	char str[128];
	uint8_t *fptr;
	resstr[0] = '\0';
#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)                   \
	fptr = flow->NAME;                                                    \
	if (flow->has_##NAME) {                                               \
		if (flow->NAME##_size == 1) {                                 \
			sprintf(str, "%s: %u", DESC, *fptr);                  \
		} else if (flow->NAME##_size == 2) {                          \
			sprintf(str, "%s: %u", DESC,                          \
				be16toh(*((uint16_t *)fptr)));                \
		} else if (flow->NAME##_size == 4) {                          \
			if (FLDTYPE == NF_FIELD_IP_ADDR) {                    \
				sprintf(str, "%s: %u.%u.%u.%u", DESC,         \
					*(fptr + 0), *(fptr + 1),             \
					*(fptr + 2), *(fptr + 3));            \
			} else {                                              \
				sprintf(str, "%s: %u", DESC,                  \
					be32toh(*((uint32_t *)fptr)));        \
			}                                                     \
		} else if ((flow->NAME##_size == 8)                           \
			&& (FLDTYPE == NF_FIELD_INT)) {                       \
			sprintf(str, "%s: %lu", DESC,                         \
				be64toh(*((uint64_t *)fptr)));                \
		} else if ((flow->NAME##_size == 16)                          \
			&& (FLDTYPE == NF_FIELD_IP_ADDR)) {                   \
			/* FIXME: hmm */                                      \
			sprintf(str,                                          \
				"%s: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"    \
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x", DESC,  \
				*(fptr + 0), *(fptr + 1),                     \
				*(fptr + 2), *(fptr + 3),                     \
				*(fptr + 4), *(fptr + 5),                     \
				*(fptr + 6), *(fptr + 7),                     \
				*(fptr + 8), *(fptr + 9),                     \
				*(fptr + 10), *(fptr + 11),                   \
				*(fptr + 12), *(fptr + 13),                   \
				*(fptr + 14), *(fptr + 15));                  \
		} else {                                                      \
			flow_field_print_bytes(str, flow->NAME##_size,        \
				DESC, fptr);                                  \
		}                                                             \
		if (resstr[0]) strcat(resstr, "; ");                          \
		strcat(resstr, str);                                          \
	}
#include "netflow.def"
}

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

int
flow_debug_config(struct aajson *a, aajson_val *value, struct xe_debug *debug)
{
	if (STRCMP(a, 2, "dump-flows") == 0) {
		debug->print_flows = 1;

		if (strcmp(value->str, "none") == 0) {
			debug->print_flows = 0;
		} else if (strcmp(value->str, "syslog") == 0) {
			debug->print_to_syslog = 1;
		} else if (strcmp(value->str, "stdout") == 0) {
			debug->fout = stdout;
		} else {
			/* file */
			debug->fout = fopen(value->str, "a");
			if (!debug->fout) {
				LOG("Can't open file '%s': %s", value->str,
					strerror(errno));
				return 0;
			}
		}
	}

	return 1;
}
#undef STRCMP

void
flow_debug_init(void)
{
	int i;
	for (i=0; i<UINT16_MAX; i++) {
		flow_fldprnt_functions[i] = NULL;
	}

#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)                   \
	flow_fldprnt_functions[FLDID] = flow_field_print_##FLDID;
#include "netflow.def"

}

