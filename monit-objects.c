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
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "utils.h"
#include "xenoeye.h"
#include "filter.h"
#include "flow_debug.h"
#include "netflow.h"

#include "tkvdb.h"

#include "monit-objects.h"

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

static int
monit_object_json_callback(struct aajson *a, aajson_val *value, void *user)
{
	struct monit_object *mo;
	char *key = a->path_stack[a->path_stack_pos].data.path_item;

	mo = (struct monit_object *)user;

	if (a->path_stack_pos == 1) {
		if (strcmp(key, "filter") == 0) {
			struct filter_input input;

			memset(&input, 0, sizeof(input));
			input.s = value->str;
			mo->expr = parse_filter(&input);
			if (input.error) {
				LOG("Can't parse filter. Parse error: %s",
					input.errmsg);
				return 0;
			}
		}
	}

	if (STRCMP(a, 1, "debug") == 0) {
		return flow_debug_config(a, value, &mo->debug);
	}

	if (STRCMP(a, 1, "fwm") == 0) {
		/* fixed window in memory */
		return fwm_config(a, value, mo);
	}

	if (STRCMP(a, 1, "mavg") == 0) {
		/* moving averages */
		return mavg_config(a, value, mo);
	}

	return 1;
}

#undef STRCMP

static int
monit_object_info_parse(struct xe_data *data, const char *moname,
	const char *fn)
{
	FILE *f;
	struct stat st;
	size_t s;
	char *json;
	int ret = 0;
	struct monit_object mo, *motmp;

	struct aajson a;

	/* read entire file in memory */
	f = fopen(fn, "r");
	if (!f) {
		LOG("Can't open info file '%s': %s", fn, strerror(errno));
		goto fail_open;
	}

	if (fstat(fileno(f), &st) < 0) {
		LOG("Can't make fstat() on info file '%s': %s",
			fn, strerror(errno));
		goto fail_fstat;
	}

	json = (char *)malloc(st.st_size + 1);
	if (!json) {
		LOG("malloc(%lu) failed", (unsigned long int)(st.st_size + 1));
		goto fail_malloc;
	}

	s = fread(json, st.st_size, 1, f);
	if (s != 1) {
		LOG("Can't read file '%s'", fn);
		goto fail_fread;
	}

	memset(&mo, 0, sizeof(struct monit_object));

	/* parse */
	aajson_init(&a, json);
	aajson_parse(&a, &monit_object_json_callback, &mo);
	if (a.error) {
		LOG("Can't parse config file '%s' (line: %lu, col: %lu): %s",
			fn, a.line, a.col, a.errmsg);
		goto fail_parse;
	}

	motmp = realloc(data->monit_objects, (data->nmonit_objects + 1)
		* sizeof(struct monit_object));
	if (!motmp) {
		LOG("realloc() failed");
		goto fail_realloc;
	}

	/*filter_dump(mo.expr, stdout);*/

	/* copy name of monitoring object */
	strcpy(mo.name, moname);

	data->monit_objects = motmp;
	data->monit_objects[data->nmonit_objects] = mo;
	data->nmonit_objects++;

	ret = 1;

fail_realloc:
fail_parse:
fail_fread:
	free(json);
fail_malloc:
fail_fstat:
	fclose(f);
fail_open:

	return ret;
}

int
monit_objects_init(struct xe_data *data)
{
	DIR *d;
	struct dirent *dir;
	int ret = 0;
	int thread_err;

	free(data->monit_objects);
	data->monit_objects = NULL;
	data->nmonit_objects = 0;

	d = opendir(data->mo_dir);
	if (!d) {
		LOG("Can't open directory with monitoring objects '%s': %s",
			data->mo_dir, strerror(errno));
		goto fail_opendir;
	}

	while ((dir = readdir(d)) != NULL) {
		size_t i;
		struct monit_object *mo;
		char mofile[PATH_MAX + 512];

		if (dir->d_name[0] == '.') {
			/* skip hidden files */
			continue;
		}

		if (dir->d_type != DT_DIR) {
			continue;
		}

		sprintf(mofile, "%s/%s/mo.conf", data->mo_dir, dir->d_name);
		LOG("Adding monitoring object '%s'", dir->d_name);

		if (!monit_object_info_parse(data, dir->d_name, mofile)) {
			continue;
		}

		mo = &data->monit_objects[data->nmonit_objects - 1];
		for (i=0; i<mo->nfwm; i++) {
			struct mo_fwm *fwm = &mo->fwms[i];
			if (!fwm_fields_init(data->nthreads, fwm)) {
				return 0;
			}
			if (fwm->time == 0) {
				LOG("warning: timeout for '%s:%s' is not set"
					", using default %d",
					mo->name, fwm->name,
					FWM_DEFAULT_TIMEOUT);
				fwm->time = FWM_DEFAULT_TIMEOUT;
			}
		}
		/* moving averages */
		for (i=0; i<mo->nmavg; i++) {
			struct mo_mavg *mavg = &mo->mavgs[i];
			if (!mavg_fields_init(data->nthreads, mavg)) {
				return 0;
			}
			if (mavg->size_secs == 0) {
				LOG("warning: time for '%s:%s' is not set"
					", using default %d",
					mo->name, mavg->name,
					MAVG_DEFAULT_SIZE);
				mavg->size_secs = MAVG_DEFAULT_SIZE;
			}

			if (mavg->merge_secs == 0) {
				LOG("warning: merge time for '%s:%s' is not set"
					", using default %d",
					mo->name, mavg->name,
					MAVG_MERGE_DEFAULT_TIMEOUT);
				mavg->merge_secs = MAVG_MERGE_DEFAULT_TIMEOUT;
			}
		}
	}

	closedir(d);

	/* create thread for background processing fixed windows in memory */
	thread_err = pthread_create(&data->fwm_tid, NULL,
		&fwm_bg_thread, data);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_fwmthread;
	}

	/* moving averages */
	thread_err = pthread_create(&data->mavg_tid, NULL,
		&mavg_bg_thread, data);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_mavgthread;
	}

	ret = 1;

fail_mavgthread:
fail_fwmthread:
	/* FIXME: free monitoring objects */
fail_opendir:
	return ret;
}

static uint64_t
monit_object_nf_val(struct nf_flow_info *flow, struct field *fld)
{
	uint64_t val;
	uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;

	switch (fld->size) {
		case sizeof(uint64_t):
			val = be64toh(*(uint64_t *)flow_fld);
			break;
		case sizeof(uint32_t):
			val = be32toh(*(uint32_t *)flow_fld);
			break;
		default:
			val = 0;
			break;
	}

	return val;
}

void
monit_object_field_print(struct field *fld, FILE *f, uint8_t *data)
{
	uint16_t d16;
	uint32_t d32;
	uint64_t d64;
	char s[INET6_ADDRSTRLEN + 1];

	switch (fld->type) {
		case FILTER_BASIC_ADDR4:
			inet_ntop(AF_INET, data, s, INET_ADDRSTRLEN);
			fprintf(f, " '%s' ", s);
			break;

		case FILTER_BASIC_ADDR6:
			inet_ntop(AF_INET6, data, s, INET6_ADDRSTRLEN);
			fprintf(f, " '%s' ", s);
			break;

		case FILTER_BASIC_RANGE:
			switch (fld->size) {
				case sizeof(uint8_t):
					fprintf(f, " %u ", data[0]);
					break;
				case sizeof(uint16_t):
					d16 = *((uint16_t *)data);
					fprintf(f, " %u ", ntohs(d16));
					break;
				case sizeof(uint32_t):
					d32 = *((uint32_t *)data);
					fprintf(f, " %u ", ntohl(d32));
					break;
				case sizeof(uint64_t):
					d64 = *((uint64_t *)data);
					fprintf(f, " %lu ", be64toh(d64));
					break;
				default:
					break;
			}
			break;

		default:
			break;
	}
}

static int
monit_object_mavg_process_nf(struct monit_object *mo, size_t thread_id,
	struct nf_flow_info *flow)
{
	size_t i, j, f;

	for (i=0; i<mo->nmavg; i++) {
		tkvdb_tr *tr;
		TKVDB_RES rc;
		tkvdb_datum dtkey, dtval;

		/* FIXME: move it to netflow parser */
		struct timespec tmsp;
		uint64_t time_ns;

		struct mo_mavg *mavg = &mo->mavgs[i];
		struct mavg_data *adata = &mavg->data[thread_id];

		uint8_t *key = adata->key;

		/* don't want high accuracy, using CLOCK_REALTIME_COARSE */
		if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
			LOG("clock_gettime() failed: %s", strerror(errno));
			continue;
		}
		time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

		/* make key */
		for (f=0; f<mavg->fieldset.n_naggr; f++) {
			struct field *fld = &mavg->fieldset.naggr[f];

			uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;
			memcpy(key, (void *)flow_fld, fld->size);
			key += fld->size;
		}

		/* get current database bank */
		tr = atomic_load_explicit(&adata->tr, memory_order_relaxed);

		dtkey.data = adata->key;
		dtkey.size = adata->keysize;

		/* search for key */
		rc = tr->get(tr, &dtkey, &dtval);
		if (rc == TKVDB_OK) {
			/* update existing values */
			struct mavg_val *vals = dtval.data;

			for (j=0; j<mavg->fieldset.n_aggr; j++) {
				struct field *fld = &mavg->fieldset.aggr[j];
				__float128 val = monit_object_nf_val(flow, fld)
					* fld->scale * flow->sampling_rate;

				__float128 tmdiff = time_ns
					- adata->val[j].time_prev;
				__float128 window = mavg->size_secs * 1e9;

				 vals[j].val = vals[j].val
					- tmdiff / window * vals[j].val + val;
				adata->val[j].time_prev = time_ns;
			}

		} else if ((rc == TKVDB_EMPTY) || (rc == TKVDB_NOT_FOUND)) {
			/* try to add new key-value pair */
			for (j=0; j<mavg->fieldset.n_aggr; j++) {
				struct field *fld = &mavg->fieldset.aggr[j];
				__float128 val = monit_object_nf_val(flow, fld)
					* fld->scale * flow->sampling_rate;

				adata->val[j].val = val;
				adata->val[j].time_prev = time_ns;
			}

			dtval.data = adata->val;
			dtval.size = adata->valsize
				* sizeof(struct mavg_val);

			rc = tr->put(tr, &dtkey, &dtval);
			if (rc == TKVDB_OK) {
			} else if (rc == TKVDB_ENOMEM) {
				LOG("Can't append key, not enough memory");
			} else {
				LOG("Can't append key, error code %d", rc);
			}
		} else {
			LOG("Can't find key, error code %d", rc);
		}
	}

	return 1;
}

int
monit_object_process_nf(struct monit_object *mo, size_t thread_id,
	struct nf_flow_info *flow)
{
	size_t i, j, f;

	for (i=0; i<mo->nfwm; i++) {
		tkvdb_tr *tr;
		TKVDB_RES rc;
		tkvdb_datum dtkey, dtval;

		struct mo_fwm *fwm = &mo->fwms[i];
		struct fwm_data *fdata = &fwm->data[thread_id];
		uint8_t *key = fdata->key;

		/* make key */
		for (f=0; f<fwm->fieldset.n_naggr; f++) {
			struct field *fld = &fwm->fieldset.naggr[f];

			uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;
			memcpy(key, (void *)flow_fld, fld->size);
			key += fld->size;
		}

		/* get current database bank */
		tr = atomic_load_explicit(&fdata->tr, memory_order_relaxed);

		dtkey.data = fdata->key;
		dtkey.size = fdata->keysize;

		/* search for key */
		rc = tr->get(tr, &dtkey, &dtval);
		if (rc == TKVDB_OK) {
			/* update existing values */
			uint64_t *vals = dtval.data;
			for (j=0; j<fwm->fieldset.n_aggr; j++) {
				struct field *fld = &fwm->fieldset.aggr[j];
				uint64_t val = monit_object_nf_val(flow, fld);

				vals[j] += val * fld->scale
					* flow->sampling_rate;
			}
		} else if ((rc == TKVDB_EMPTY) || (rc == TKVDB_NOT_FOUND)) {
			/* try to add new key-value pair */

			/* init new aggregatable values */
			for (j=0; j<fwm->fieldset.n_aggr; j++) {
				struct field *fld = &fwm->fieldset.aggr[j];
				uint64_t val = monit_object_nf_val(flow, fld);

				fdata->val[j] = val * fld->scale
					* flow->sampling_rate;
			}

			dtval.data = fdata->val;
			dtval.size = fdata->valsize;

			rc = tr->put(tr, &dtkey, &dtval);
			if (rc == TKVDB_OK) {
			} else if (rc == TKVDB_ENOMEM) {
				/* not enough memory */
			} else {
				LOG("Can't append key, error code %d", rc);
			}
		} else {
			LOG("Can't find key, error code %d", rc);
		}
	}

	/* moving average */
	if (!monit_object_mavg_process_nf(mo, thread_id, flow)) {
		return 0;
	}

	return 1;
}

