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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>

#include "utils.h"
#include "netflow.h"
#include "monit-objects.h"
#include "monit-objects-common.h"

#define MAVG_VAL(DATUM, I, SIZE) ((struct mavg_val *)&DATUM[SIZE * I])

int
mavg_fields_init(size_t nthreads, struct mo_mavg *window)
{
	size_t i, keysize, valsize, val_itemsize;
	tkvdb_params *params, *params_ovr;

	params = tkvdb_params_create();
	tkvdb_param_set(params, TKVDB_PARAM_ALIGNVAL, 16);
	tkvdb_param_set(params, TKVDB_PARAM_TR_DYNALLOC, 0);
	tkvdb_param_set(params, TKVDB_PARAM_TR_LIMIT, window->db_mem);

	params_ovr = tkvdb_params_create();
	tkvdb_param_set(params_ovr, TKVDB_PARAM_ALIGNVAL, 16);

	keysize = 0;
	for (i=0; i<window->fieldset.n_naggr; i++) {
		keysize += window->fieldset.naggr[i].size;
	}

	if (window->noverlimit > 1) {
		val_itemsize = sizeof(struct mavg_val)
			+ sizeof(MAVG_TYPE) * (window->noverlimit - 1);
	} else {
		val_itemsize = sizeof(struct mavg_val);
	}

	valsize = window->fieldset.n_aggr * val_itemsize;


	/* per-thread data */
	window->data = calloc(nthreads, sizeof(struct mavg_data));
	if (!window->data) {
		LOG("calloc() failed");
		return 0;
	}

	for (i=0; i<nthreads; i++) {
		struct mavg_data *data = &window->data[i];
		tkvdb_tr *tmp_db;

		data->keysize = keysize;
		/* allocate memory for key plus level number */
		data->key_fullsize = keysize + sizeof(size_t);
		data->key = malloc(data->key_fullsize);
		if (!data->key) {
			LOG("malloc() failed");
			return 0;
		}

		data->valsize = valsize;
		data->val_itemsize = val_itemsize;
		data->val = malloc(valsize);
		if (!data->val) {
			LOG("malloc() failed");
			return 0;
		}

		/* init database */
		tmp_db = tkvdb_tr_create(NULL, params);
		if (!tmp_db) {
			LOG("tkvdb_tr_create() failed");
			return 0;
		}

		tmp_db->begin(tmp_db);
		atomic_store_explicit(&data->db, tmp_db, memory_order_relaxed);


		/* init databases with limits */
		data->ovr_db[0] = tkvdb_tr_create(NULL, params_ovr);
		if (!data->ovr_db[0]) {
			LOG("Can't create database for overlimited items");
			return 0;
		}
		data->ovr_db[0]->begin(data->ovr_db[0]);

		data->ovr_db[1] = tkvdb_tr_create(NULL, params_ovr);
		if (!data->ovr_db[1]) {
			LOG("Can't create database for overlimited items");
			return 0;
		}
		data->ovr_db[1]->begin(data->ovr_db[1]);
	}

	window->glb_ovr_db = tkvdb_tr_create(NULL, params_ovr);
	if (!window->glb_ovr_db) {
		LOG("Can't create database for overlimited items");
		return 0;
	}
	window->glb_ovr_db->begin(window->glb_ovr_db);

	window->nthreads = nthreads;

	tkvdb_params_free(params);
	tkvdb_params_free(params_ovr);
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

/* parse config section 'overlimit' */
static int
mavg_config_limit(struct aajson *a, aajson_val *value,
	struct mo_mavg *window, size_t n_aggr)
{
	size_t i;
	struct mavg_limit *l;

	if (a->path_stack[4].type != AAJSON_PATH_ITEM_ARRAY) {
		LOG("'overlimit' must be array");
		return 0;
	}

	i = a->path_stack[4].data.array_idx;
	if (i >= window->noverlimit) {
		struct mavg_limit *tmp;

		/* append new overlimit item */
		tmp = realloc(window->overlimit,
			(i + 1) * sizeof(struct mavg_limit));
		if (!tmp) {
			LOG("realloc() failed");
			return 0;
		}
		memset(&tmp[i], 0, sizeof(struct mavg_limit));

		tmp[i].back2norm_time_ns = MAVG_DEFAULT_BACK2NORM * 1e9;

		tmp[i].def = malloc(n_aggr * sizeof(MAVG_TYPE));
		if (!tmp[i].def) {
			free(tmp);
			LOG("malloc() failed");
			return 0;
		}

		window->overlimit = tmp;
		window->noverlimit = i + 1;
	}

	l = &window->overlimit[i];

	if (STRCMP(a, 5, "name") == 0) {
		strcpy(l->name, value->str);
	} else if (STRCMP(a, 5, "limits") == 0) {
		strcpy(l->file, value->str);
	} else if (STRCMP(a, 5, "default") == 0) {
		/* FIXME: check ? */
		size_t idx = a->path_stack[6].data.array_idx;
		l->def[idx] = strtod(value->str, NULL);
	} else if (STRCMP(a, 5, "action-script") == 0) {
		strcpy(l->action_script, value->str);
	} else if (STRCMP(a, 5, "back2norm-script") == 0) {
		strcpy(l->back2norm_script, value->str);
	} else if (STRCMP(a, 5, "back2norm-time") == 0) {
		int back2norm_time = atoi(value->str);

		if (back2norm_time <= 0) {
			LOG("Incorrect 'back2norm-time' value '%s', using %d",
				value->str, MAVG_DEFAULT_BACK2NORM);
			back2norm_time= MAVG_DEFAULT_BACK2NORM;
		}

		l->back2norm_time_ns = back2norm_time * 1e9;
	} else if (STRCMP(a, 5, "ext") == 0) {
		/* extended statistics */
		if (a->path_stack[6].type != AAJSON_PATH_ITEM_ARRAY) {
			LOG("'ext' must be array");
			return 0;
		}

		i = a->path_stack[6].data.array_idx;
		if (i >= l->n_ext_stat) {
			struct mavg_limit_ext_stat *tmp;
			char *delim;

			/* append new extended table (fwm) */
			tmp = realloc(l->ext_stat,
				(i + 1) * sizeof(struct mavg_limit_ext_stat));
			if (!tmp) {
				LOG("realloc() failed");
				return 0;
			}

			/* parse name and optional monitoring object */
			delim = strchr(value->str, '/');
			if (delim) {
				*delim = '\0';
				strcpy(tmp[i].mo_name, value->str);
				strcpy(tmp[i].name, delim + 1);
			} else {
				tmp[i].mo_name[0] = '\0';
				strcpy(tmp[i].name, value->str);
			}

			/* init pointer */
			tmp[i].ptr = NULL;

			l->ext_stat = tmp;
			l->n_ext_stat = i + 1;
		}
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

		/* default db size */
		tmp[i].db_mem = MAVG_DEFAULT_DB_SIZE;

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
	} else if (STRCMP(a, 3, "dump") == 0) {
		int tmp_time = atoi(value->str);
		if (tmp_time < 0) {
			LOG("Incorrect dump time '%s'", value->str);
			return 0;
		}

		window->dump_secs = tmp_time;
	} else if (STRCMP(a, 3, "mem-m") == 0) {
		int tmp_mem = atoi(value->str);
		if (tmp_mem < 0) {
			LOG("Incorrect db size '%s', using default %dM",
				value->str,
				MAVG_DEFAULT_DB_SIZE / (1024 * 1024));
			window->db_mem = MAVG_DEFAULT_DB_SIZE;
		} else {
			window->db_mem = tmp_mem * 1024 * 1024;
		}
	} else if (STRCMP(a, 3, "overlimit") == 0) {
		if (!mavg_config_limit(a, value, window,
			window->fieldset.n_aggr)) {

			return 0;
		}
	}

	return 1;
}

static int
mavg_limits_parse_line(struct mo_mavg *window, char *line, uint8_t *key,
	MAVG_TYPE *val)
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
	MAVG_TYPE *val;

	FILE *f = fopen(l->file, "r");
	if (!f) {
		LOG("Can't open file '%s': %s", l->file, strerror(errno));
		l->db->free(l->db);
		return 0;
	}

	key = window->data[0].key;
	val = alloca(sizeof(MAVG_TYPE) * window->fieldset.n_aggr);

	dtk.data = key;
	dtk.size = window->data[0].keysize;

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

int
mavg_limits_init(struct mo_mavg *window)
{
	size_t i;
	tkvdb_params *params;
	params = tkvdb_params_create();
	tkvdb_param_set(params, TKVDB_PARAM_ALIGNVAL, 16);

	for (i=0; i<window->noverlimit; i++) {
		struct mavg_limit *l = &window->overlimit[i];

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

/* react on overlimit */
static void
mavg_on_overlimit(struct xe_data *globl, struct mavg_data *data,
	size_t limit_id, struct mavg_ovrlm_data *od)
{
	TKVDB_RES rc;
	tkvdb_datum dtk, dtv;
	tkvdb_tr *db;

	size_t ovr_idx;

	/* select bank */
	ovr_idx = atomic_load_explicit(&globl->mavg_db_bank_idx,
		memory_order_relaxed) % 2;

	db = data->ovr_db[ovr_idx];

	/* append level id to key */
	memcpy(data->key + data->keysize, &limit_id, sizeof(size_t));

	dtk.data = data->key;
	dtk.size = data->key_fullsize;

	dtv.data = od;
	dtv.size = sizeof(struct mavg_ovrlm_data);

	/* put without checks if this item exists */
	rc = db->put(db, &dtk, &dtv);
	if (rc != TKVDB_OK) {
		LOG("Can't append item to db with "\
			"overlimited records, error code %d", rc);
		return;
	}

}

static void
mavg_limits_check(struct xe_data *globl, struct mo_mavg *mavg,
	struct mavg_data *data,	uint8_t *vptr, MAVG_TYPE *vals,
	uint64_t time_ns)
{
	size_t i, j;

	for (i=0; i<mavg->fieldset.n_aggr; i++) {
		MAVG_TYPE val;
		struct mavg_val *pval;

		pval = MAVG_VAL(vptr, i, data->valsize);
		val = vals[i] / (MAVG_TYPE)mavg->size_secs;

		for (j=0; j<mavg->noverlimit; j++) {
			if (val >= pval->limits_max[j]) {
				struct mavg_ovrlm_data od;

				od.time_last = time_ns;
				od.val = val;
				od.limit = pval->limits_max[j];
				od.back2norm_time_ns
					= mavg->overlimit[j].back2norm_time_ns;

				mavg_on_overlimit(globl, data, j, &od);
			}
		}
	}
}

static void
mavg_recalc(_Atomic MAVG_TYPE *oldval_p, _Atomic uint64_t *old_time_ns_p,
	MAVG_TYPE val, uint64_t time_ns, MAVG_TYPE wndsize,
	_Atomic MAVG_TYPE *res)
{
	MAVG_TYPE oldval, tmdiff;
	uint64_t old_time_ns;

	oldval = atomic_load_explicit(oldval_p, memory_order_relaxed);
	old_time_ns = atomic_load_explicit(old_time_ns_p,
		memory_order_relaxed);

	tmdiff = time_ns - old_time_ns;

	if (tmdiff < wndsize) {
		/* calculate and store new value */
		atomic_store_explicit(res,
			oldval - tmdiff / wndsize * oldval + val,
			memory_order_relaxed);
	} else {
		atomic_store_explicit(res, val, memory_order_relaxed);
	}
}


static void
mavg_val_init(struct mo_mavg *mavg, struct nf_flow_info *flow,
	uint64_t time_ns, struct mavg_data *data, MAVG_TYPE *vals)
{
	size_t i, j;

	memset(data->val, 0, data->valsize);

	for (i=0; i<mavg->fieldset.n_aggr; i++) {
		struct field *fld = &mavg->fieldset.aggr[i];
		MAVG_TYPE val;
		struct mavg_val *pval;

		val = monit_object_nf_val(flow, fld)
			* fld->scale * flow->sampling_rate;

		pval = MAVG_VAL(data->val, i, data->valsize);

		/* setup limits */
		for (j=0; j<mavg->noverlimit; j++) {
			TKVDB_RES rc;
			tkvdb_datum dtkey, dtval;
			tkvdb_tr *tr = mavg->overlimit[j].db;

			dtkey.data = data->key;
			dtkey.size = data->keysize;

			rc = tr->get(tr, &dtkey, &dtval);
			if (rc == TKVDB_OK) {
				/* found, using value as limit */
				MAVG_TYPE *limptr = (MAVG_TYPE *)dtval.data;
				pval->limits_max[j] = *limptr;
			} else {
				/* not found, using default */
				pval->limits_max[j] = mavg->overlimit[j].def[i];
			}
		}

		atomic_store_explicit(&pval->val, val, memory_order_relaxed);

		atomic_store_explicit(&pval->time_prev, time_ns,
			memory_order_relaxed);

		atomic_store_explicit(&vals[i], val, memory_order_relaxed);
	}
}

/* try to reset MA database when there is not enough memory in it */
static int
try_reset_db(struct mo_mavg *mavg, struct mavg_data *thr_data)
{
	tkvdb_cursor *c;
	int ret = 0;

	struct timespec tmsp;
	uint64_t time_ns;

	MAVG_TYPE wndsize;

	tkvdb_params *params;
	tkvdb_tr *newdb, *olddb;

	/* create new database with the same params as old */
	params = tkvdb_params_create();
	tkvdb_param_set(params, TKVDB_PARAM_ALIGNVAL, 16);
	tkvdb_param_set(params, TKVDB_PARAM_TR_DYNALLOC, 0);
	tkvdb_param_set(params, TKVDB_PARAM_TR_LIMIT, mavg->db_mem);

	/* create new database */
	newdb = tkvdb_tr_create(NULL, params);
	if (!newdb) {
		LOG("tkvdb_tr_create() failed");
		goto newdb_fail;
	}

	tkvdb_params_free(params);

	newdb->begin(newdb);

	if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
		LOG("clock_gettime() failed: %s", strerror(errno));
		goto clock_fail;
	}
	time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

	/* window size in nanoseconds */
	wndsize = mavg->size_secs * 1e9;

	olddb = atomic_load_explicit(&thr_data->db, memory_order_relaxed);

	c = tkvdb_cursor_create(olddb);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		LOG("c->first() failed");
		goto first_failed;
	}

	/* iterate over all set */
	do {
		size_t i;
		int keep = 0;

		tkvdb_datum dtk = c->key_datum(c);
		tkvdb_datum dtv = c->val_datum(c);

		for (i=0; i<mavg->fieldset.n_aggr; i++) {
			struct mavg_val *pval;

			pval = MAVG_VAL(((uint8_t *)dtv.data), i,
				thr_data->valsize);

			/* check when this item was last used */
			if ((pval->time_prev + wndsize) > time_ns) {
				/* if no later than window size,
				   save in new database */
				keep = 1;
			}
		}

		if (keep) {
			TKVDB_RES rc = newdb->put(newdb, &dtk, &dtv);
			if (rc != TKVDB_OK) {
				LOG("put() failed with code %d", rc);
				goto put_failed;
			}
		}

	} while (c->next(c) == TKVDB_OK);

	/* replace old database with new one */
	atomic_store_explicit(&thr_data->db, newdb, memory_order_relaxed);

	/* sleep a bit to wait for other threads to finish working with the
	   old database*/
	usleep(10);

	/* destroy old database */
	olddb->free(olddb);

	ret = 1;

put_failed:
first_failed:
	c->free(c);

cursor_fail:
clock_fail:
	newdb->free(newdb);

newdb_fail:

	return ret;
}

int
monit_object_mavg_process_nf(struct xe_data *globl, struct monit_object *mo,
	size_t thread_id, uint64_t time_ns, struct nf_flow_info *flow)
{
	size_t i, f, t;

	for (i=0; i<mo->nmavg; i++) {
		tkvdb_tr *db;
		TKVDB_RES rc;
		tkvdb_datum dtkey, dtval, nval;
		MAVG_TYPE wndsize;

		struct mo_mavg *mavg = &mo->mavgs[i];
		struct mavg_data *data = &mavg->data[thread_id];

		uint8_t *key = data->key;

		/* reserve space for merged values */
		MAVG_TYPE *mvals = alloca(mavg->fieldset.n_aggr
			* sizeof(MAVG_TYPE));

		/* window size in nanoseconds */
		wndsize = mavg->size_secs * 1e9;

		/* make key */
		for (f=0; f<mavg->fieldset.n_naggr; f++) {
			struct field *fld = &mavg->fieldset.naggr[f];

			uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;
			memcpy(key, (void *)flow_fld, fld->size);
			key += fld->size;
		}

		db = atomic_load_explicit(&data->db, memory_order_relaxed);

		dtkey.data = data->key;
		dtkey.size = data->keysize;

		/* search for key */
		rc = db->get(db, &dtkey, &dtval);
		if (rc == TKVDB_OK) {
			/* update existing values */
			for (i=0; i<mavg->fieldset.n_aggr; i++) {
				struct field *fld = &mavg->fieldset.aggr[i];
				MAVG_TYPE val;
				struct mavg_val *pval;

				val = monit_object_nf_val(flow, fld)
					* fld->scale * flow->sampling_rate;

				pval = MAVG_VAL(((uint8_t *)dtval.data), i,
					data->valsize);
				mavg_recalc(&pval->val, &pval->time_prev, val,
					time_ns, wndsize, &pval->val);

				/* update time */
				atomic_store_explicit(&pval->time_prev, time_ns,
					memory_order_relaxed);

				mvals[i] = pval->val;
			}

			/* values from another threads */
			for (t=0; t<mavg->nthreads; t++) {
				struct mavg_data *ndata;
				tkvdb_tr *ndb;

				if (t == thread_id) {
					/* skip self thread */
					continue;
				}

				ndata = &mavg->data[t];
				ndb = atomic_load_explicit(&ndata->db,
					memory_order_relaxed);
				rc = ndb->get(ndb, &dtkey, &nval);
				if (rc == TKVDB_OK) {
					for (i=0; i<mavg->fieldset.n_aggr; i++) {
						struct mavg_val *pval;
						pval =
						MAVG_VAL(((uint8_t *)nval.data),
							i, data->valsize);

						mavg_recalc(&pval->val,
							&pval->time_prev,
							mvals[i], time_ns,
							wndsize,
							(_Atomic MAVG_TYPE *)&mvals[i]);

						/* update time */
						atomic_store_explicit(
							&pval->time_prev,
							time_ns,
							memory_order_relaxed);
					}
				}
			}

			mavg_limits_check(globl, mavg, data, dtval.data, mvals,
				time_ns);
		} else if ((rc == TKVDB_EMPTY) || (rc == TKVDB_NOT_FOUND)) {
			size_t j;
			/* try to add new key-value pair */

			if (data->db_is_full) {
				/* skip */
				continue;
			}

			/*
			 * FIXME: it's not really needed, trying to suppress
			 * valgring warning
			*/
			for (j=0; j<mavg->fieldset.n_aggr; j++) {
				mvals[j] = 0.0f;
			}

			mavg_val_init(mavg, flow, time_ns, data, mvals);

			mavg_limits_check(globl, mavg, data, data->val, mvals,
				time_ns);

			dtval.data = data->val;
			dtval.size = data->valsize;

			rc = db->put(db, &dtkey, &dtval);

			if (rc == TKVDB_ENOMEM) {
				/* FIXME: out of memory */
				LOG("Not enough memory for MA database, "
					"please increase value of 'mem-m'");
				if (!try_reset_db(mavg, data)) {
					LOG("Can't cleanup MA database, all "
						"new items will be discarded");

					data->db_is_full = 1;
				}
			} else if (rc != TKVDB_OK) {
				LOG("Can't insert data, error code %d", rc);
			}
		} else {
			LOG("Can't find key, error code %d", rc);
		}
	}

	return 1;
}


static void
monit_objects_mavg_link(struct monit_object *mo, struct mavg_limit_ext_stat *e)
{
	size_t i;

	/* for each fwm in monitoring object */
	for (i=0; i<mo->nfwm; i++) {
		struct mo_fwm *fwm = &mo->fwms[i];

		if (strcmp(fwm->name, e->name) == 0) {
			e->ptr = &fwm->active_cnt;
			break;
		}
	}
}


static void
monit_objects_mavg_link_d(struct xe_data *globl, struct mavg_limit_ext_stat *e)
{
	size_t i;

	/* for each monitoring object */
	for (i=0; i<globl->nmonit_objects; i++) {
		struct monit_object *mo = &globl->monit_objects[i];

		if (strcmp(e->mo_name, mo->name) == 0) {
			/* found */
			monit_objects_mavg_link(mo, e);
			break;
		}
	}
}


static void
monit_objects_mavg_link_mo(struct xe_data *globl, struct monit_object *mo)
{
	size_t i, j, k;

	/* for each moving average */
	for (i=0; i<mo->nmavg; i++) {
		struct mo_mavg *mw = &mo->mavgs[i];

		/* for each overlimit set */
		for (j=0; j<mw->noverlimit; j++) {
			struct mavg_limit *lm = &mw->overlimit[j];

			/* for each ext table */
			for (k=0; k<lm->n_ext_stat; k++) {
				struct mavg_limit_ext_stat *e
					= &lm->ext_stat[k];

				if (!*e->mo_name) {
					/* same monitoring object */
					monit_objects_mavg_link(mo, e);
				} else {
					/* different monitoring object */
					monit_objects_mavg_link_d(globl, e);
				}
			}
		}
	}
}


void
monit_objects_mavg_link_ext_stat(struct xe_data *globl)
{
	size_t i;

	/* for each monitoring object */
	for (i=0; i<globl->nmonit_objects; i++) {
		struct monit_object *mo = &globl->monit_objects[i];

		monit_objects_mavg_link_mo(globl, mo);
	}
}

