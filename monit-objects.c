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
				LOG("Parse error: %s", input.errmsg);
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
	char modir[PATH_MAX] = "monit_objects";
	int thread_err;

	free(data->monit_objects);
	data->monit_objects = NULL;
	data->nmonit_objects = 0;

	d = opendir(modir);
	if (!d) {
		LOG("Can't open directory with monitoring objects '%s': %s",
			modir, strerror(errno));
		goto fail_opendir;
	}

	while ((dir = readdir(d)) != NULL) {
		size_t i;
		struct monit_object *mo;
		char mofile[PATH_MAX];

		if (dir->d_name[0] == '.') {
			/* skip hidden files */
			continue;
		}

		if (dir->d_type != DT_DIR) {
			continue;
		}

		sprintf(mofile, "%s/%s/mo.conf", modir, dir->d_name);
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
	}

	closedir(d);

	/* create thread for background processing fixed windows in memory */
	thread_err = pthread_create(&data->fwm_tid, NULL,
		&fwm_bg_thread, data);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_fwmthread;
	}

	ret = 1;

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

	return 1;
}

