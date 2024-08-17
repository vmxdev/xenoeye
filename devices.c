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
#include <arpa/inet.h>
#include <stdlib.h>

#include "filter.h"
#include "devices.h"
#include "aajson/aajson.h"

struct devices_info
{
	struct device *devices;
	size_t n_devices;
};

static struct devices_info devices = {NULL, 0};

static int
config_adjust_devs_size(struct devices_info *devs, size_t idx)
{
	struct device *tmp;

	if (devs->n_devices >= (idx + 1)) {
		return 1;
	}

	tmp = realloc(devs->devices, (idx + 1) * sizeof(struct device));
	if (!tmp) {
		LOG("realloc() failed");
		return 0;
	}

	devs->devices = tmp;
	devs->n_devices = idx + 1;

	/* init new device */
	memset(&devs->devices[devs->n_devices - 1], 0, sizeof(struct device));

	return 1;
}

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

static int
config_callback(struct aajson *a, aajson_val *value, void *user)
{
	struct devices_info *devs = user;
	size_t idx;

	if (a->path_stack_pos < 2) {
		return 1;
	}

	if (a->path_stack[1].type != AAJSON_PATH_ITEM_ARRAY) {
		return 1;
	}

	idx = a->path_stack[1].data.array_idx;

	if (!config_adjust_devs_size(devs, idx)) {
		return 0;
	}

	if (STRCMP(a, 2, "ip") == 0) {
		unsigned char buf[sizeof(struct in6_addr)];
		int rc;

		devs->devices[devs->n_devices - 1].use_ip = 1;

		/* FIXME: add IPv6 */
		rc = inet_pton(AF_INET, value->str, buf);
		if (rc <= 0) {
			LOG("Can't parse IP '%s'", value->str);
			return 0;
		}

		devs->devices[devs->n_devices - 1].ip_ver = 4;
		devs->devices[devs->n_devices - 1].ip = 0;
		memcpy(&devs->devices[devs->n_devices - 1].ip, buf, 4);
	}

	if (STRCMP(a, 2, "id") == 0) {
		devs->devices[devs->n_devices - 1].use_id = 1;
		devs->devices[devs->n_devices - 1].id
			= htonl(atoi(value->str));
	}

	if (STRCMP(a, 2, "sampling-rate") == 0) {
		devs->devices[devs->n_devices - 1].sampling_rate
			= atoi(value->str);
	}

	if (STRCMP(a, 2, "mark") == 0) {
		struct filter_input input;
		struct device *d = &devs->devices[devs->n_devices - 1];
		struct filter_expr **tmp = realloc(d->exprs, sizeof(struct filter_expr *) * (d->n_exprs + 1));
		if (!tmp) {
			LOG("realloc() failed");
			return 0;
		}
		d->exprs = tmp;

		memset(&input, 0, sizeof(input));
		input.s = value->str;

		d->exprs[d->n_exprs] = parse_filter(&input);
		if (input.error) {
			LOG("Can't parse filter '%s'. Parse error: %s",
				value->str, input.errmsg);
			return 0;
		}

		d->n_exprs++;
	}

	if (STRCMP(a, 2, "skip-unmarked") == 0) {
		if (value->type == AAJSON_VALUE_TRUE) {
			devs->devices[devs->n_devices - 1].skip_unmarked = 1;
		}
	}

	return 1;
}
#undef STRCMP

int
devices_load(const char *filename)
{
	FILE *f;
	long len;
	struct aajson conf_json;
	int ret = 0;
	char *file;

	f = fopen(filename, "rb");
	if (!f) {
		LOG("Can't open config file '%s'", filename);
		goto fail_open;
	}

	fseek(f, 0, SEEK_END);
	len = ftell(f);

	fseek(f, 0, SEEK_SET);
	file = malloc(len);
	if (!file) {
		LOG("Can't allocate %ld bytes", len);
		goto fail_alloc;
	}

	if (fread(file, 1, len, f) != (size_t)len) {
		LOG("Can't read config file '%s'", filename);
		goto fail_read;
	}

	aajson_init(&conf_json, file);
	aajson_parse(&conf_json, &config_callback, &devices);

	if (conf_json.error) {
		LOG("Can't parse config file '%s': line %lu, col %lu: %s",
			filename, conf_json.line, conf_json.col,
			conf_json.errmsg);

		free(devices.devices);
		devices.devices = NULL;
		devices.n_devices = 0;

		goto fail_parse;
	}

	ret = 1;

fail_parse:
fail_read:
	free(file);
fail_alloc:
	fclose(f);
fail_open:
	return ret;
}


int
device_get_sampling_rate(struct device *d)
{
	size_t i;
	int found = 0;

	for (i=0; i<devices.n_devices; i++) {
		struct device *db = &devices.devices[i];

		if (db->use_ip && db->use_id) {
			/* check all fields */
			if ((d->ip_ver == db->ip_ver)
				&& (d->ip == db->ip) && (d->id == db->id)) {

				found = 1;
				d->sampling_rate = db->sampling_rate;
				break;
			}
		} else  if (db->use_ip) {
			/* only IP */
			if ((d->ip_ver == db->ip_ver) && (d->ip == db->ip)) {
				found = 1;
				d->sampling_rate = db->sampling_rate;
				break;
			}
		} if (db->use_id) {
			/* only ID */
			if (d->id == db->id) {
				found = 1;
				d->sampling_rate = db->sampling_rate;
				break;
			}
		}
	}

	return found;
}

int
device_get_mark(struct device *d, struct flow_info *fi)
{
	size_t i;
	int found = 0;
	struct device *db;

	for (i=0; i<devices.n_devices; i++) {
		db = &devices.devices[i];

		if (db->use_ip && db->use_id) {
			/* check all fields */
			if ((d->ip_ver == db->ip_ver)
				&& (d->ip == db->ip) && (d->id == db->id)) {

				found = 1;
				break;
			}
		} else  if (db->use_ip) {
			/* only IP */
			if ((d->ip_ver == db->ip_ver) && (d->ip == db->ip)) {
				found = 1;
				break;
			}
		} if (db->use_id) {
			/* only ID */
			if (d->id == db->id) {
				found = 1;
				break;
			}
		}
	}

	if (!found) {
		return 0;
	}

	d->skip_unmarked = db->skip_unmarked;
	d->mark = 0;
	for (i=0; i<db->n_exprs; i++) {
		if (filter_match(db->exprs[i], fi)) {
			d->mark++;
		}
	}

	return 1;
}

