/*
 * xenoeye
 *
 * Copyright (c) 2021, Vladimir Misyurov, Michael Kogan
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

#include "netflow.h"
#include "utils.h"

#include "flow_debug.h"

static void
flow_field_dump_bytes(char *str, int flength, char *desc, uint8_t *fptr)
{
	int i;

	sprintf(str, "%s: ", desc);
	for (i=0; i<flength; i++) {
		sprintf(str + strlen(str), "0x%02x ", *(fptr + i));
	}
}

static void
flow_field_dump(char *str, enum NF_FIELD_TYPE type, int flength,
	char *desc, uint8_t *fptr)
{
	if (type == NF_FIELD_BYTES) {
		flow_field_dump_bytes(str, flength, desc, fptr);
		return;
	}

	if (flength == 1) {
		sprintf(str, "%s: %u", desc, *fptr);
	} else if (flength == 2) {
		sprintf(str, "%s: %u", desc, ntohs(*((uint16_t *)fptr)));
	} else if (flength == 4) {
		if (type == NF_FIELD_IP_ADDR) {
			sprintf(str, "%s: %u.%u.%u.%u", desc,
				*(fptr + 0), *(fptr + 1),
				*(fptr + 2), *(fptr + 3));
		} else {
			sprintf(str, "%s: %u", desc,
				ntohl(*((uint32_t *)fptr)));
		}
	} else if ((flength == 8) && (type == NF_FIELD_INT)) {
		sprintf(str, "%s: %lu", desc,
			be64toh(*((uint64_t *)fptr)));
	} else if ((flength == 16) && (type == NF_FIELD_IP_ADDR)) {
		/* FIXME: hmm */
		sprintf(str, "%s: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", desc,
			*(fptr + 0), *(fptr + 1), *(fptr + 2), *(fptr + 3),
			*(fptr + 4), *(fptr + 5), *(fptr + 6), *(fptr + 7),
			*(fptr + 8), *(fptr + 9), *(fptr + 10), *(fptr + 11),
			*(fptr + 12), *(fptr + 13), *(fptr + 14), *(fptr + 15));
	} else {
		flow_field_dump_bytes(str, flength, desc, fptr);
	}
}

void
flow_debug_add_field(struct xe_debug *debug, int flength, int ftype,
	uint8_t *fptr, char *debug_flow_str)
{
	char flow_str[128];

	if (!debug->dump_flows) {
		return;
	}

	if (debug_flow_str[0]) {
		strcat(debug_flow_str, "; ");
	}

	if (0) {
#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)                   \
} else if (ftype == FLDID) {                                                  \
	flow_field_dump(flow_str, FLDTYPE, flength, DESC, fptr);
#include "netflow.def"
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
flow_dump_str(struct xe_debug *debug, const char *flow_str)
{
	if (!debug->dump_flows) {
		return;
	}

	if (debug->dump_to_syslog) {
		LOG("%s", flow_str);
	} else {
		fprintf(debug->dump_out, "%s\n", flow_str);
	}
}

