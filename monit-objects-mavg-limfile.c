/*
 * xenoeye
 *
 * Copyright (c) 2024-2026, Vladimir Misyurov
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
#include <stdlib.h>
#include <arpa/inet.h>
#include "monit-objects.h"

static int
mavg_limits_parse_line(struct mo_mavg *window, char *line, uint8_t *key,
	MAVG_TYPE *val)
{
	char token[TOKEN_MAX_SIZE];
	size_t i;
	size_t validx = 0;

	for (i=0; i<window->fieldset.n; i++) {
		struct field *fld = &window->fieldset.fields[i];

		/* get token */
		csv_next(&line, token);

		if (fld->aggr) {
			val[validx] = strtod(token, NULL);
			validx++;
		} else {
			/* append to key */
			int res;
			uint8_t d8;
			uint16_t d16;
			uint32_t d32;
			uint64_t d64;

			if (fld->type == FILTER_BASIC_ADDR4) {
				res = inet_pton(AF_INET, token, key);
				if (res != 1) {
					LOG("Can't convert '%s' to "
						"IPv4 address", token);
					return 0;
				}
			} else if (fld->type == FILTER_BASIC_ADDR6) {
				res = inet_pton(AF_INET6, token, key);
				if (res != 1) {
					LOG("Can't convert '%s' to "
						"IPv6 address", token);
					return 0;
				}
			} else if (fld->type == FILTER_BASIC_MAC) {
				res = mac_addr_read(token,
					(struct mac_addr *)key);
				if (!res) {
					LOG("Can't convert '%s' to "
						"MAC address", token);
					return 0;
				}
			} else if (fld->type == FILTER_BASIC_STRING) {
				memset(key, 0, fld->size);
				strcpy((char *)key, token);
			} else {
				/* FIXME: check? */
				long long int v = atoll(token);
				switch (fld->size) {
					case 1:
						d8 = v;
						memcpy(key, &d8, 1);
						break;
					case 2:
						d16 = htons(v);
						memcpy(key, &d16, 2);
						break;
					case 4:
						d32 = htonl(v);
						memcpy(key, &d32, 4);
						break;
					case 8:
						d64 = htobe64(v);
						memcpy(key, &d64, 8);
						break;
				}
			}

			key += fld->size;
		}
	}

	return 1;
}


/* load CSV file with limits */
int
mavg_limits_file_load(struct mo_mavg *window, struct mavg_limit *l)
{
	tkvdb_datum dtk, dtv;
	TKVDB_RES rc;
	uint8_t *key;
	MAVG_TYPE *val;

	FILE *f = fopen(l->file, "r");
	if (!f) {
		LOG("Can't open file '%s': %s", l->file, strerror(errno));
		l->db->free(l->db);
		return 0;
	}

	key = window->thr_data[0].key;
	val = alloca(sizeof(MAVG_TYPE) * window->fieldset.n_aggr);

	dtk.data = key;
	dtk.size = window->thr_data[0].keysize;

	dtv.data = val;
	dtv.size = sizeof(MAVG_TYPE) * window->fieldset.n_aggr;

	for (;;) {
		char line[2048], *trline;

		if (!fgets(line, sizeof(line) - 1, f)) {
			break;
		}

		trline = string_trim(line);
		if (strlen(trline) == 0) {
			/* skip empty line */
			continue;
		}
		if (trline[0] == '#') {
			/* skip comment */
			continue;
		}

		if (!mavg_limits_parse_line(window, trline, key, val)) {
			continue;
		}

		/* append to limits database */
		rc = l->db->put(l->db, &dtk, &dtv);
		if (rc != TKVDB_OK) {
			LOG("Can't add item from '%s' to limits db, code %d",
				l->file, rc);
		}
	}
	fclose(f);

	return 1;
}

