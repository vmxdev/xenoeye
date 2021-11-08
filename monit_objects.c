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

#include "aajson/aajson.h"

#include "utils.h"
#include "xenoeye.h"
#include "filter.h"
#include "flow_debug.h"

#include "tkvdb.h"

struct fwm_data
{
	/* using two banks */
	tkvdb_tr *trs[2];

	/* current bank */
	tkvdb_tr *_Atomic tr;

	uint8_t *key;
	uint64_t *val;

	size_t keysize, valsize;
};

struct mo_fieldset
{
	/* all fields */
	size_t n;
	struct field *fields;

	/* key fields (without packets/octets) */
	size_t n_naggr;
	struct field *naggr;

	/* aggregable fields */
	size_t n_aggr;
	struct field *aggr;
};

struct mo_fwm
{
	char name[TOKEN_MAX_SIZE];
	struct mo_fieldset fieldset;
	int time;

	/* each thread has it's own data */
	struct fwm_data *data;
};

static void *fwm_bg_thread(void *);

static int
fwm_fields_init(size_t nthreads, struct mo_fwm *window)
{
	size_t i, keysize, valsize;

	keysize = 0;
	for (i=0; i<window->fieldset.n_naggr; i++) {
		keysize += window->fieldset.naggr[i].size;
	}

	valsize = window->fieldset.n_aggr * sizeof(uint64_t);

	window->data = calloc(nthreads, sizeof(struct fwm_data));
	if (!window->data) {
		LOG("calloc() failed");
		return 0;
	}

	for (i=0; i<nthreads; i++) {
		window->data[i].keysize = keysize;
		window->data[i].key = malloc(keysize);
		if (!window->data[i].key) {
			LOG("malloc() failed");
			return 0;
		}

		window->data[i].valsize = valsize;
		window->data[i].val = malloc(valsize);
		if (!window->data[i].val) {
			LOG("malloc() failed");
			return 0;
		}

		window->data[i].trs[0] = tkvdb_tr_create(NULL, NULL);
		if (!window->data[i].trs[0]) {
			LOG("tkvdb_tr_create() failed");
			return 0;
		}
		window->data[i].trs[1] = tkvdb_tr_create(NULL, NULL);
		if (!window->data[i].trs[1]) {
			LOG("tkvdb_tr_create() failed");
			return 0;
		}

		window->data[i].trs[0]->begin(window->data[i].trs[0]);
		window->data[i].trs[1]->begin(window->data[i].trs[1]);

		atomic_store_explicit(&window->data[i].tr,
			window->data[i].trs[0], memory_order_relaxed);

	}

	return 1;
}

static int
do_field_append(struct field **fields, size_t *n, struct field *fld)
{
	struct field *tmp_fields;

	tmp_fields = realloc(*fields, (*n + 1) * sizeof(struct field));
	if (!tmp_fields) {
		LOG("realloc() failed");
		return 0;
	}
	*fields = tmp_fields;
	(*fields)[*n] = *fld;
	(*n)++;

	return 1;
}

static int
config_field_append(char *s, struct mo_fwm *window)
{
	struct field fld;
	char err[ERR_MSG_LEN];

	if (!parse_field(s, &fld, err)) {
		LOG("Can't parse field '%s': %s", s, err);
		return 0;
	}

	if (!do_field_append(&window->fieldset.fields, &window->fieldset.n,
		&fld)) {

		return 0;
	}

	/* separate aggregatable and non-aggregatable fields */
	if (fld.aggr) {
		if (!do_field_append(&window->fieldset.aggr,
			&window->fieldset.n_aggr, &fld)) {

			return 0;
		}
	} else {
		if (!do_field_append(&window->fieldset.naggr,
			&window->fieldset.n_naggr, &fld)) {

			return 0;
		}
	}

	return 1;
}

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

static int
fixed_window_mem_config(struct aajson *a, aajson_val *value,
	struct monit_object *mo)
{
	size_t i;
	struct mo_fwm *window;

	if (a->path_stack[2].type != AAJSON_PATH_ITEM_ARRAY) {
		LOG("'fwm' must be array");
		return 0;
	}

	i = a->path_stack[2].data.array_idx;
	if (i >= mo->nfwm) {
		struct mo_fwm *tmp;

		/* append new window */
		tmp = realloc(mo->fwms, (i + 1) * sizeof(struct mo_fwm));
		if (!tmp) {
			LOG("realloc() failed");
			return 0;
		}
		memset(&tmp[i], 0, sizeof(struct mo_fwm));

		mo->fwms = tmp;
		mo->nfwm = i + 1;
	}

	window = &mo->fwms[i];

	if (STRCMP(a, 3, "name") == 0) {
		strcpy(window->name, value->str);
	} else if (STRCMP(a, 3, "fields") == 0) {
		if (!config_field_append(value->str, window)) {
			return 0;
		}
	} else if (STRCMP(a, 3, "time") == 0) {
		window->time = atoi(value->str);
		if (window->time < 0) {
			LOG("Incorrect time '%s'", value->str);
			return 0;
		}
	}

	return 1;
}

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
		return fixed_window_mem_config(a, value, mo);
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
			if (!fwm_fields_init(data->nthreads, &mo->fwms[i])) {
				return 0;
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

				vals[j] += val * fld->scale;
			}
		} else if ((rc == TKVDB_EMPTY) || (rc == TKVDB_NOT_FOUND)) {
			/* try to add new key-value pair */

			/* init new aggregatable values */
			for (j=0; j<fwm->fieldset.n_aggr; j++) {
				struct field *fld = &fwm->fieldset.aggr[j];
				uint64_t val = monit_object_nf_val(flow, fld);

				fdata->val[j] = val * fld->scale;
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

static void
fwm_field_print(struct field *fld, char *s, uint8_t *data)
{
	uint16_t d16;
	uint32_t d32;
	uint64_t d64;

	switch (fld->type) {
		case FILTER_BASIC_ADDR4:
			inet_ntop(AF_INET, data, s, INET_ADDRSTRLEN);
			break;

		case FILTER_BASIC_ADDR6:
			inet_ntop(AF_INET6, data, s, INET6_ADDRSTRLEN);
			break;

		case FILTER_BASIC_RANGE:
			switch (fld->size) {
				case sizeof(uint8_t):
					sprintf(s, "%u", data[0]);
					break;
				case sizeof(uint16_t):
					d16 = *((uint16_t *)data);
					sprintf(s, "%u", ntohs(d16));
					break;
				case sizeof(uint32_t):
					d32 = *((uint32_t *)data);
					sprintf(s, "%u", ntohl(d32));
					break;
				case sizeof(uint64_t):
					d64 = *((uint64_t *)data);
					sprintf(s, "%lu", be64toh(d64));
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
fwm_sort_tr(struct mo_fwm *fwm, tkvdb_tr *tr)
{
	tkvdb_cursor *c;

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		return 0;
	}

	if (c->first(c) != TKVDB_OK) {
		goto empty;
	}

	do {
		size_t i;
		char line[4096];
		char strval[128];

		uint8_t *naggr = c->key(c);
		uint64_t *aggr = c->val(c);

		line[0] = '\0';
		for (i=0; i<fwm->fieldset.n; i++) {
			struct field *fld = &fwm->fieldset.fields[i];

			if (fld->aggr) {
				sprintf(strval, "%lu ", *aggr);
				strcat(line, strval);
				aggr++;
			} else {
				fwm_field_print(fld, strval, naggr);
				strcat(line, strval);
				strcat(line, " ");
				naggr += fld->size;
			}
		}

		LOG("> %s", line);
	} while (c->next(c) == TKVDB_OK);

empty:
	c->free(c);

	return 1;
}

static int
fwm_merge_tr(struct mo_fwm *fwm, tkvdb_tr *tr_merge, tkvdb_tr *tr)
{
	tkvdb_cursor *c;

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		return 0;
	}

	if (c->first(c) != TKVDB_OK) {
		/* empty set */
		goto empty;
	}

	do {
		TKVDB_RES rc;
		tkvdb_datum dtk, dtv;

		dtk.data = c->key(c);
		dtk.size = c->keysize(c);

		rc = tr_merge->get(tr_merge, &dtk, &dtv);
		if (rc == TKVDB_OK) {
			size_t i;
			uint64_t *vals = dtv.data;
			uint64_t *vals_add = c->val(c);

			/* update data */
			for (i=0; i<fwm->fieldset.n_aggr; i++) {
				vals[i] += vals_add[i];
			}
		} else {
			/* not found */
			dtv.data = c->val(c);
			dtv.size = c->valsize(c);

			rc = tr_merge->put(tr_merge, &dtk, &dtv);
			if (rc != TKVDB_OK) {
				LOG("put() failed");
				break;
			}
		}
	} while (c->next(c) == TKVDB_OK);

empty:
	c->free(c);

	/* reset transaction */
	tr->rollback(tr);
	tr->begin(tr);

	return 1;
}

static int
fwm_merge(struct mo_fwm *fwm, size_t nthreads)
{
	size_t i;
	tkvdb_tr *tr_merge;

	tr_merge = tkvdb_tr_create(NULL, NULL);
	if (!tr_merge) {
		LOG("Can't create transaction");
		return 0;
	}

	tr_merge->begin(tr_merge);

	/* merge data from all threads */
	for (i=0; i<nthreads; i++) {
		tkvdb_tr *tr;

		tr = atomic_load_explicit(&fwm->data[i].tr,
			memory_order_relaxed);

		/* swap banks */
		if (tr == fwm->data[i].trs[0]) {
			atomic_store_explicit(&fwm->data[i].tr,
				fwm->data[i].trs[1], memory_order_relaxed);
		} else {
			atomic_store_explicit(&fwm->data[i].tr,
				fwm->data[i].trs[0], memory_order_relaxed);
		}
		usleep(10);
		fwm_merge_tr(fwm, tr_merge, tr);
	}

	fwm_sort_tr(fwm, tr_merge);

	tr_merge->free(tr_merge);

	return 1;
}

static void *
fwm_bg_thread(void *arg)
{
	struct xe_data *data = (struct xe_data *)arg;

	for (;;) {
		size_t i, j;

		if (atomic_load_explicit(&data->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}

		for (i=0; i<data->nmonit_objects; i++) {
			struct monit_object *mo = &data->monit_objects[i];

			for (j=0; j<mo->nfwm; j++) {
				struct mo_fwm *fwm = &mo->fwms[j];

				LOG("mo: %lu, fwm: %lu", i, j);
				if (!fwm_merge(fwm, data->nthreads)) {
					break;
				}
			}
		}

		sleep(10);
	}

	return NULL;
}

