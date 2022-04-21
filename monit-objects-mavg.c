/*
 * xenoeye
 *
 * Copyright (c) 2022, Vladimir Misyurov, Michael Kogan
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

#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "utils.h"
#include "monit-objects.h"

int
mavg_fields_init(size_t nthreads, struct mo_mavg *window)
{
	size_t i, keysize, valsize;
	tkvdb_params *params;

	params = tkvdb_params_create();
	tkvdb_param_set(params, TKVDB_PARAM_ALIGNVAL, 16);

	keysize = 0;
	for (i=0; i<window->fieldset.n_naggr; i++) {
		keysize += window->fieldset.naggr[i].size;
	}

	valsize = window->fieldset.n_aggr;

	window->data = calloc(nthreads, sizeof(struct mavg_data));
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
		window->data[i].val = malloc(valsize
			* sizeof(struct mavg_val));
		if (!window->data[i].val) {
			LOG("malloc() failed");
			return 0;
		}

		/* init database */
		window->data[i].trs[0] = tkvdb_tr_create(NULL, params);
		if (!window->data[i].trs[0]) {
			LOG("tkvdb_tr_create() failed");
			return 0;
		}
		window->data[i].trs[1] = tkvdb_tr_create(NULL, params);
		if (!window->data[i].trs[1]) {
			LOG("tkvdb_tr_create() failed");
			return 0;
		}

		window->data[i].trs[0]->begin(window->data[i].trs[0]);
		window->data[i].trs[1]->begin(window->data[i].trs[1]);

		atomic_store_explicit(&window->data[i].tr,
			window->data[i].trs[0], memory_order_relaxed);
	}

	tkvdb_params_free(params);
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
config_field_append(char *s, struct mo_mavg *window)
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

int
mavg_config(struct aajson *a, aajson_val *value,
	struct monit_object *mo)
{
	size_t i;
	struct mo_mavg *window;

	if (a->path_stack[2].type != AAJSON_PATH_ITEM_ARRAY) {
		LOG("'mavg' must be array");
		return 0;
	}

	i = a->path_stack[2].data.array_idx;
	if (i >= mo->nmavg) {
		struct mo_mavg *tmp;

		/* append new window */
		tmp = realloc(mo->mavgs, (i + 1) * sizeof(struct mo_mavg));
		if (!tmp) {
			LOG("realloc() failed");
			return 0;
		}
		memset(&tmp[i], 0, sizeof(struct mo_mavg));

		mo->mavgs = tmp;
		mo->nmavg = i + 1;
	}

	window = &mo->mavgs[i];

	if (STRCMP(a, 3, "name") == 0) {
		strcpy(window->name, value->str);
	} else if (STRCMP(a, 3, "fields") == 0) {
		if (!config_field_append(value->str, window)) {
			return 0;
		}
	} else if (STRCMP(a, 3, "time") == 0) {
		int tmp_time = atoi(value->str);
		if (tmp_time < 0) {
			LOG("Incorrect time '%s'", value->str);
			return 0;
		}

		window->size_secs = tmp_time;
	} else if (STRCMP(a, 3, "merge") == 0) {
		int tmp_time = atoi(value->str);
		if (tmp_time <= 0) {
			LOG("Incorrect merge time '%s'", value->str);
			return 0;
		}

		window->merge_secs = tmp_time;
	} else if (STRCMP(a, 3, "overflow") == 0) {
		/* */
	}

	return 1;
}

static int
mavg_dump_tr(struct mo_mavg *mavg, tkvdb_tr *tr, const char *mo_name,
	const char *exp_dir)
{
	size_t i;
	int ret = 0;
	tkvdb_cursor *c;

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		ret = 1;
		goto empty;
	}

	/* iterate over all set */
	printf("dump:\n");
	do {
		uint8_t *data = c->key(c);
		struct mavg_val *val = c->val(c);

		for (i=0; i<mavg->fieldset.n_naggr; i++) {
			struct field *fld = &mavg->fieldset.naggr[i];
			monit_object_field_print(fld, stdout, data);
			printf(":");

			data += fld->size;
		}

		printf(" :: ");
		for (i=0; i<mavg->fieldset.n_aggr; i++) {
			printf("%g ", (double)val[i].val);
		}
		printf("\n");
	} while (c->next(c) == TKVDB_OK);

	printf("\n");
	ret = 1;
empty:
	c->free(c);

cursor_fail:
	return ret;
}


static int
mavg_merge_tr(struct mo_mavg *mavg, tkvdb_tr *tr_merge, tkvdb_tr *tr)
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
			struct mavg_val *vals = dtv.data;
			struct mavg_val *vals_add = c->val(c);

			/* update data */
			for (i=0; i<mavg->fieldset.n_aggr; i++) {
				vals[i].val += vals_add[i].val;
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
mavg_merge(struct mo_mavg *fwm, size_t nthreads, const char *mo_name,
	const char *exp_dir)
{
	size_t i;
	tkvdb_tr *tr_merge;
	tkvdb_params *params;

	params = tkvdb_params_create();
	tkvdb_param_set(params, TKVDB_PARAM_ALIGNVAL, 16);

	tr_merge = tkvdb_tr_create(NULL, params);
	if (!tr_merge) {
		LOG("Can't create transaction");
		return 0;
	}

	tkvdb_params_free(params);

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
		mavg_merge_tr(fwm, tr_merge, tr);
	}

	mavg_dump_tr(fwm, tr_merge, mo_name, exp_dir);

	tr_merge->free(tr_merge);

	return 1;
}


void *
mavg_bg_thread(void *arg)
{
	struct xe_data *data = (struct xe_data *)arg;

	for (;;) {
		time_t t;
		size_t i, j;
		int need_sleep = 1;

		if (atomic_load_explicit(&data->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}

		t = time(NULL);
		if (t == ((time_t)-1)) {
			LOG("time() failed: %s", strerror(errno));
			return NULL;
		}

		for (i=0; i<data->nmonit_objects; i++) {
			struct monit_object *mo = &data->monit_objects[i];

			for (j=0; j<mo->nmavg; j++) {
				struct mo_mavg *mavg = &mo->mavgs[j];

				if ((mavg->last_merge + mavg->merge_secs)
					<= t) {

					/* time to merge */
					if (mavg_merge(mavg, data->nthreads,
						mo->name, data->exp_dir)) {

						mavg->last_merge = t;
						need_sleep = 0;
					} else {
						continue;
					}
				}
			}
		}

		if (need_sleep) {
			sleep(1);
		}
	}

	return NULL;
}

