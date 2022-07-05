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
#include "netflow.h"
#include "monit-objects.h"
#include "monit-objects-common.h"

int
mavg_fields_init(size_t nthreads, struct mo_mavg *window)
{
	size_t i, j, keysize, valsize, val_itemsize;
	tkvdb_params *params;

	params = tkvdb_params_create();
	tkvdb_param_set(params, TKVDB_PARAM_ALIGNVAL, 16);
	tkvdb_param_set(params, TKVDB_PARAM_TR_DYNALLOC, 0);
	tkvdb_param_set(params, TKVDB_PARAM_TR_LIMIT, MAVG_DEFAULT_TR_SIZE);

	keysize = 0;
	for (i=0; i<window->fieldset.n_naggr; i++) {
		keysize += window->fieldset.naggr[i].size;
	}

	if (window->noverflow > 1) {
		val_itemsize = sizeof(struct mavg_val)
			+ sizeof(__float128) * (window->noverflow - 1);
	} else {
		val_itemsize = sizeof(struct mavg_val);
	}

	valsize = window->fieldset.n_aggr * val_itemsize;

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
		window->data[i].val_itemsize = val_itemsize;
		window->data[i].val = malloc(valsize);
		if (!window->data[i].val) {
			LOG("malloc() failed");
			return 0;
		}

		/* init database */
		for (j=0; j<MAVG_NBANKS; j++) {
			window->data[i].trs[j] = tkvdb_tr_create(NULL, params);
			if (!window->data[i].trs[j]) {
				LOG("tkvdb_tr_create() failed");
				return 0;
			}

			window->data[i].trs[0]->begin(window->data[i].trs[0]);
		}

		atomic_init(&window->data[i].tr_idx, 0);
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

/* parse config section 'overflow' */
static int
mavg_config_limit(struct aajson *a, aajson_val *value,
	struct mo_mavg *window, size_t n_aggr)
{
	size_t i;
	struct mavg_limit *l;

	if (a->path_stack[4].type != AAJSON_PATH_ITEM_ARRAY) {
		LOG("'overflow' must be array");
		return 0;
	}

	i = a->path_stack[4].data.array_idx;
	if (i >= window->noverflow) {
		struct mavg_limit *tmp;

		/* append new overflow item */
		tmp = realloc(window->overflow,
			(i + 1) * sizeof(struct mavg_limit));
		if (!tmp) {
			LOG("realloc() failed");
			return 0;
		}
		memset(&tmp[i], 0, sizeof(struct mavg_limit));

		tmp[i].def = malloc(n_aggr * sizeof(__float128));
		if (!tmp[i].def) {
			free(tmp);
			LOG("malloc() failed");
			return 0;
		}

		window->overflow = tmp;
		window->noverflow = i + 1;
	}

	l = &window->overflow[i];

	if (STRCMP(a, 5, "name") == 0) {
		strcpy(l->name, value->str);
	} else if (STRCMP(a, 5, "limits") == 0) {
		strcpy(l->file, value->str);
	} else if (STRCMP(a, 5, "default") == 0) {
		/* FIXME: check ? */
		size_t idx = a->path_stack[6].data.array_idx;
		l->def[idx] = strtod(value->str, NULL);
	}

	return 1;
}

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
		if (!mavg_config_limit(a, value, window,
			window->fieldset.n_aggr)) {

			return 0;
		}
	}

	return 1;
}

static int
mavg_limits_parse_line(struct mo_mavg *window, char *line, uint8_t *key,
	__float128 *val)
{
	char* token;
	const char separators[] = ",";
	size_t i = 0;
	size_t validx = 0;

	token = strtok(line, separators);
	while (token != NULL) {
		struct field *fld = &window->fieldset.fields[i];

		if (i >= window->fieldset.n) {
			break;
		}

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

		token = strtok(NULL, separators);
		i++;
	}

	return 1;
}

/* load CSV file with limits */
static int
mavg_limits_file_load(struct mo_mavg *window, struct mavg_limit *l)
{
	tkvdb_datum dtk, dtv;
	TKVDB_RES rc;
	uint8_t *key;
	__float128 *val;

	FILE *f = fopen(l->file, "r");
	if (!f) {
		LOG("Can't open file '%s': %s", l->file, strerror(errno));
		l->db->free(l->db);
		return 0;
	}

	key = window->data[0].key;
	val = alloca(sizeof(__float128) * window->fieldset.n_aggr);

	dtk.data = key;
	dtk.size = window->data[0].keysize;

	dtv.data = val;
	dtv.size = sizeof(__float128) * window->fieldset.n_aggr;

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

int
mavg_limits_init(struct mo_mavg *window)
{
	size_t i;
	tkvdb_params *params;
	params = tkvdb_params_create();
	tkvdb_param_set(params, TKVDB_PARAM_ALIGNVAL, 16);

	for (i=0; i<window->noverflow; i++) {
		struct mavg_limit *l = &window->overflow[i];

		if (l->name[0] == '\0') {
			sprintf(l->name, "%lu", i);
			LOG("mavg 'name' is not set, will use '%s'", l->name);
		}

		l->db = tkvdb_tr_create(NULL, params);
		if (!l->db) {
			LOG("Can't create limits database");
			return 0;
		}

		l->db->begin(l->db);
		if (l->file[0]) {
			/* try to read file */
			mavg_limits_file_load(window, l);
		}
	}

	tkvdb_params_free(params);
	return 1;
}

#define MAVG_VAL(DATUM, I, SIZE) ((struct mavg_val *)&DATUM[SIZE * I])

static void
mavg_limits_check(struct mo_mavg *mavg, uint8_t *vptr, struct mavg_data *data)
{
	size_t i, j;

	for (i=0; i<mavg->fieldset.n_aggr; i++) {
		__float128 val;
		struct mavg_val *pval;

		pval = MAVG_VAL(vptr, i, data->valsize);
		val = pval->val;

		for (j=0; j<mavg->noverflow; j++) {
			if (val >= pval->limits_max[j]) {
				LOG("overflow! (%f < %f)",
					(double)pval->limits_max[j], (double)val);
			}
		}
	}
}

static void
mavg_val_update(struct mo_mavg *mavg, struct nf_flow_info *flow,
	uint8_t *valptr, uint64_t time_ns, struct mavg_data *data)
{
	size_t i;

	for (i=0; i<mavg->fieldset.n_aggr; i++) {
		struct field *fld = &mavg->fieldset.aggr[i];
		__float128 val, oldval, tmdiff, window;
		uint64_t time_prev_ns;
		struct mavg_val *pval;

		val = monit_object_nf_val(flow, fld)
			* fld->scale * flow->sampling_rate;

		pval = MAVG_VAL(valptr, i, data->valsize);

		/* load previous values */
		oldval = atomic_load_explicit(&pval->val,
			memory_order_relaxed);

		time_prev_ns = atomic_load_explicit(&pval->time_prev,
			memory_order_relaxed);

		tmdiff = time_ns - time_prev_ns;
		window = mavg->size_secs * 1e9;

		if (tmdiff < window) {
			/* calculate and store new value */
			atomic_store_explicit(&pval->val,
				oldval - tmdiff / window * oldval + val,
				memory_order_relaxed);
		} else {
			atomic_store_explicit(&pval->val,
				0.0f,
				memory_order_relaxed);
		}

		atomic_store_explicit(&pval->time_prev, time_ns,
			memory_order_relaxed);

	}
}

static void
mavg_val_init(struct mo_mavg *mavg, struct nf_flow_info *flow,
	uint64_t time_ns, struct mavg_data *data)
{
	size_t i, j;

	memset(data->val, 0, data->valsize);

	for (i=0; i<mavg->fieldset.n_aggr; i++) {
		struct field *fld = &mavg->fieldset.aggr[i];
		__float128 val;
		struct mavg_val *pval;

		val = monit_object_nf_val(flow, fld)
			* fld->scale * flow->sampling_rate;

		pval = MAVG_VAL(data->val, i, data->valsize);

		/* setup limits */
		for (j=0; j<mavg->noverflow; j++) {
			TKVDB_RES rc;
			tkvdb_datum dtkey, dtval;
			tkvdb_tr *tr = mavg->overflow[j].db;

			dtkey.data = data->key;
			dtkey.size = data->keysize;

			rc = tr->get(tr, &dtkey, &dtval);
			if (rc == TKVDB_OK) {
				/* found, using value as limit */
				__float128 *limptr = (__float128 *)dtval.data;
				pval->limits_max[j] = *limptr;
			} else {
				/* not found, using default */
				pval->limits_max[j] = mavg->overflow[j].def[i];
			}
		}

		atomic_store_explicit(&pval->val, val, memory_order_relaxed);

		atomic_store_explicit(&pval->time_prev, time_ns,
			memory_order_relaxed);
	}
}


int
monit_object_mavg_process_nf(struct monit_object *mo, size_t thread_id,
	uint64_t time_ns, struct nf_flow_info *flow)
{
	size_t i, f;

	for (i=0; i<mo->nmavg; i++) {
		tkvdb_tr *tr, *tr_prev;
		size_t tr_idx, tr_prev_idx;
		TKVDB_RES rc;
		tkvdb_datum dtkey, dtval;

		struct mo_mavg *mavg = &mo->mavgs[i];
		struct mavg_data *data = &mavg->data[thread_id];

		uint8_t *key = data->key;

		/* make key */
		for (f=0; f<mavg->fieldset.n_naggr; f++) {
			struct field *fld = &mavg->fieldset.naggr[f];

			uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;
			memcpy(key, (void *)flow_fld, fld->size);
			key += fld->size;
		}

		/* get current database bank */
		tr_idx = atomic_load_explicit(&data->tr_idx,
			memory_order_relaxed);
		tr_prev_idx = tr_idx - 1;

		tr_idx %= MAVG_NBANKS;
		tr_prev_idx %= MAVG_NBANKS;

		tr = data->trs[tr_idx];
		tr_prev = data->trs[tr_prev_idx];

		dtkey.data = data->key;
		dtkey.size = data->keysize;

		/* search for key */
		rc = tr->get(tr, &dtkey, &dtval);
		if (rc == TKVDB_OK) {
			/* update existing values */
			mavg_val_update(mavg, flow, dtval.data, time_ns, data);
			mavg_limits_check(mavg, dtval.data, data);
		} else if ((rc == TKVDB_EMPTY) || (rc == TKVDB_NOT_FOUND)) {
			/* search in "prev" bank */
			rc = tr->get(tr_prev, &dtkey, &dtval);
			if (rc == TKVDB_OK) {
				/* found */
				/* copy old values */
				memcpy(data->val, dtval.data, data->valsize);
				/* update */
				mavg_val_update(mavg, flow, data->val,
					time_ns, data);
				mavg_limits_check(mavg, data->val, data);
			} else {
				/* try to add new key-value pair */
				mavg_val_init(mavg, flow, time_ns, data);
				mavg_limits_check(mavg, data->val, data);
			}

			dtval.data = data->val;
			dtval.size = data->valsize;

			rc = tr->put(tr, &dtkey, &dtval);
			if (rc == TKVDB_OK) {
			} else if (rc == TKVDB_ENOMEM) {
				if (!data->need_more_mem) {
					LOG("Can't insert data, "\
						"not enough memory");
					data->need_more_mem = 1;
				}
			} else {
				LOG("Can't insert data, error code %d", rc);
			}
		} else {
			LOG("Can't find key, error code %d", rc);
		}
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
				vals[i].val +=
					atomic_load_explicit(&vals_add[i].val,
					memory_order_relaxed);
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
		size_t tr_idx;

		tr_idx = atomic_load_explicit(&fwm->data[i].tr_idx,
			memory_order_relaxed);

		tr = fwm->data[i].trs[tr_idx];

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
					}
				}

				/* swap database banks */
				if ((mavg->last_bankswap
					+ mavg->size_secs * 2 + 1) <= t) {

					/* time to swap banks */
/*
					if (mavg_swap(mavg, data->nthreads)) {
						mavg->last_bankswap = t;
						need_sleep = 0;
					}
*/
				}
			}
		}

		if (need_sleep) {
			sleep(1);
		}
	}

	return NULL;
}

