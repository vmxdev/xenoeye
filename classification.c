/*
 * xenoeye
 *
 * Copyright (c) 2023, Vladimir Misyurov, Michael Kogan
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
#include "monit-objects-common.h"
#include "netflow.h"

int
classification_fields_init(size_t nthreads, struct mo_classification *clsf)
{
	size_t i, keysize;

	if (!clsf->on) {
		return 1;
	}

	keysize = 0;
	for (i=0; i<clsf->nfields; i++) {
		keysize += clsf->fields[i].size;
	}

	clsf->thread_data =
		calloc(nthreads, sizeof(struct classification_thread_data));
	if (!clsf->thread_data) {
		LOG("calloc() failed");
		return 0;
	}

	for (i=0; i<nthreads; i++) {
		clsf->thread_data[i].keysize = keysize;
		clsf->thread_data[i].key = malloc(keysize);
		if (!clsf->thread_data[i].key) {
			LOG("malloc() failed");
			return 0;
		}

		clsf->thread_data[i].trs[0] = tkvdb_tr_create(NULL, NULL);
		if (!clsf->thread_data[i].trs[0]) {
			LOG("tkvdb_tr_create() failed");
			return 0;
		}
		clsf->thread_data[i].trs[1] = tkvdb_tr_create(NULL, NULL);
		if (!clsf->thread_data[i].trs[1]) {
			LOG("tkvdb_tr_create() failed");
			return 0;
		}

		clsf->thread_data[i].trs[0]
			->begin(clsf->thread_data[i].trs[0]);

		clsf->thread_data[i].trs[1]
			->begin(clsf->thread_data[i].trs[1]);

		atomic_store_explicit(&clsf->thread_data[i].tr_idx,
			0, memory_order_relaxed);
	}

	return 1;
}


static int
config_field_append(char *s, struct mo_classification *clsf)
{
	struct field fld;
	char err[ERR_MSG_LEN];
	struct field *tmp_fields;

	if (!parse_field(s, &fld, err)) {
		LOG("Can't parse field '%s': %s", s, err);
		return 0;
	}

	if (fld.aggr) {
		LOG("Aggregable field ('%s') is not allowed", s);
		return 0;
	}

	tmp_fields = realloc(clsf->fields,
		(clsf->nfields + 1) * sizeof(struct field));
	if (!tmp_fields) {
		LOG("realloc() failed");
		return 0;
	}
	clsf->fields = tmp_fields;
	clsf->fields[clsf->nfields] = fld;
	clsf->nfields++;

	return 1;
}

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

int
classification_config(struct aajson *a, aajson_val *value,
	struct monit_object *mo)
{
	struct mo_classification *clsf = &mo->classification;

	clsf->on = 1;

	if (STRCMP(a, 2, "top-percents") == 0) {
		clsf->top_percents = atoi(value->str);
		if (clsf->top_percents > 100) {
			LOG("Incorrect 'top-percents': '%s'", value->str);
			return 0;
		}
	} else if (STRCMP(a, 2, "fields") == 0) {
		if (!config_field_append(value->str, clsf)) {
			return 0;
		}
	} else if (STRCMP(a, 2, "time") == 0) {
		clsf->time = atoi(value->str);
		if (clsf->time <= 0) {
			LOG("Incorrect time '%s'", value->str);
			return 0;
		}
	} else if (STRCMP(a, 2, "val") == 0) {
		char err[ERR_MSG_LEN];

		clsf->val = calloc(1, sizeof(struct field));
		if (!clsf->val) {
			LOG("calloc() failed");
			return 0;
		}

		if (!parse_field(value->str, clsf->val, err)) {
			LOG("Can't parse field '%s': %s", value->str, err);
			return 0;
		}

		if (!clsf->val->aggr) {
			LOG("Non-aggregable field ('%s') is not allowed",
				value->str);
			return 0;
		}
	}

	return 1;
}

static void
classification_field_to_string(struct field *fld, char *str, uint8_t *data)
{
	/*if (fld->id == )*/
	monit_object_field_print_str(fld, str, data, 0);
}

static int
classification_dump(struct mo_classification *clsf, tkvdb_tr *tr,
	const char *mo_name, const char *clsf_dir)
{
	int ret = 0;
	tkvdb_cursor *c;
	uint64_t sum = 0, sumtmp = 0;
	char class_name[CLASS_NAME_MAX + 1];

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		ret = 1;
		goto empty;
	}

	/* first pass, calculate sum */
	do {
		uint64_t *s = c->key(c);
		sum += *s;
	} while (c->next(c) == TKVDB_OK);

	/* second pass, get top % */
	c->first(c);
	do {
		FILE *f;
		char path[PATH_MAX];
		uint8_t ktmp[64];
		char str[64];
		size_t i;

		uint64_t *s = c->key(c);
		uint8_t *naggr = c->key(c);

		sumtmp += *s;

		naggr += sizeof(uint64_t);
 
		class_name[0] = '\0';
		for (i=0; i<clsf->nfields; i++) {
			struct field *fld = &clsf->fields[i];

			if (fld->descending) {
				int j;

				for (j=0; j<fld->size; j++) {
					/* invert value */
					ktmp[j] = ~*naggr;
					naggr++;
				}
			} else {
				memcpy(ktmp, naggr, fld->size);
				naggr += fld->size;
			}

			classification_field_to_string(fld, str, ktmp);
			strcat(class_name, str);
			strcat(class_name, ".");
		}
		sprintf(path, "%s/%s-%s", clsf_dir, mo_name, class_name);

		f = fopen(path, "w");
		fprintf(f, "stats: %lu\n", *s * 100 / sum);
		fclose(f);

		if ((sumtmp * 100 / sum) >= clsf->top_percents) {
			break;
		}
	} while (c->next(c) == TKVDB_OK);

	/* rest */
	sumtmp = 0;
	while (c->next(c) == TKVDB_OK) {
		uint64_t *s = c->key(c);
		sumtmp += *s;
	}

	ret = 1;

empty:
	c->free(c);

cursor_fail:

	return ret;
}


static int
classification_sort_tr(struct mo_classification *clsf, tkvdb_tr *tr,
	const char *mo_name, const char *clsf_dir)
{
	int ret = 0;
	tkvdb_cursor *c;
	tkvdb_tr *tr_merge;

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		ret = 1;
		goto empty;
	}

	tr_merge = tkvdb_tr_create(NULL, NULL);
	if (!tr_merge) {
		LOG("Can't create transaction");
		goto tr_fail;
	}

	tr_merge->begin(tr_merge);

	/* iterate over all set */
	do {
		size_t i;
		uint8_t key[4096];
		uint8_t *kptr = key;
		tkvdb_datum dtk, dtv;
		TKVDB_RES rc;
		uint64_t tmpv;

		uint8_t *naggr = c->key(c);
		uint64_t *v = c->val(c);

		/* make key for correct sorting */
		if (clsf->val->descending) {
			tmpv = ~*v;
		} else {
			tmpv = *v;
		}
		memcpy(kptr, &tmpv, sizeof(uint64_t));
		kptr += sizeof(uint64_t);

		for (i=0; i<clsf->nfields; i++) {
			struct field *fld = &clsf->fields[i];

			if (fld->descending) {
				int j;

				for (j=0; j<fld->size; j++) {
					/* invert value */
					*kptr = ~*naggr;
					kptr++;
					naggr++;
				}
			} else {
				memcpy(kptr, naggr, fld->size);
				kptr += fld->size;
				naggr += fld->size;
			}
		}

		dtk.data = key;
		dtk.size = kptr - key;

		dtv.size = 0;
		dtv.data = NULL;
		rc = tr_merge->put(tr_merge, &dtk, &dtv);
		if (rc != TKVDB_OK) {
			LOG("put() failed");
		}
	} while (c->next(c) == TKVDB_OK);

	classification_dump(clsf, tr_merge, mo_name, clsf_dir);
	tr_merge->free(tr_merge);

	ret = 1;
empty:
tr_fail:
	c->free(c);

cursor_fail:
	return ret;
}


static int
classification_merge_tr(tkvdb_tr *tr_merge, tkvdb_tr *tr)
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
			uint64_t *v = dtv.data;
			uint64_t *v_add = c->val(c);

			/* update data */
			*v += *v_add;
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
classification_merge(struct mo_classification *clsf, size_t nthreads,
	const char *mo_name, const char *clsf_dir)
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
		int tr_idx;
		tkvdb_tr *tr;

		/* get current bank and swap banks atomically */
		tr_idx = atomic_fetch_add_explicit(
			&clsf->thread_data[i].tr_idx, 1, memory_order_relaxed)
			% 2;

		tr = clsf->thread_data[i].trs[tr_idx];

		/* wait for stalled updates in inactive bank */
		usleep(10);

		classification_merge_tr(tr_merge, tr);
	}

	classification_sort_tr(clsf, tr_merge, mo_name, clsf_dir);

	tr_merge->free(tr_merge);

	return 1;
}

void *
classification_bg_thread(void *arg)
{
	struct xe_data *data = (struct xe_data *)arg;

	for (;;) {
		time_t t;
		size_t i;
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
			struct mo_classification *clsf = &mo->classification;

			if (!clsf->on) {
				continue;
			}

			if ((clsf->last_export + clsf->time) <= t) {
				/* time to export */
				if (classification_merge(clsf, data->nthreads,
					mo->name, data->clsf_dir)) {

					clsf->last_export = t;
					need_sleep = 0;
				} else {
					continue;
				}
			}
		}

		if (need_sleep) {
			sleep(1);
		}
	}

	return NULL;
}

int classification_process_nf(struct xe_data *globl,
	struct monit_object *mo, size_t thread_id, struct nf_flow_info *flow)
{
	size_t i;
	struct mo_classification *clsf = &mo->classification;
	struct classification_thread_data *cdata =
		&clsf->thread_data[thread_id];

	uint8_t *key;

	size_t tr_idx;
	tkvdb_tr *tr;
	tkvdb_datum dtkey, dtval;
	TKVDB_RES rc;

	key = cdata->key;

	for (i=0; i<clsf->nfields; i++) {
		struct field *fld = &clsf->fields[i];

		monit_object_key_add_fld(fld, key, flow);
		key += fld->size;
	}

	tr_idx = atomic_load_explicit(&cdata->tr_idx, memory_order_relaxed)
		% 2;

	tr = cdata->trs[tr_idx];

	dtkey.data = cdata->key;
	dtkey.size = cdata->keysize;

	/* search for key */
	rc = tr->get(tr, &dtkey, &dtval);
	if (rc == TKVDB_OK) {
		/* update existing value */
		uint64_t *dbval_ptr = dtval.data;
		struct field *fld = clsf->val;
		uint64_t val = monit_object_nf_val(flow, fld);

		*dbval_ptr += val * fld->scale * flow->sampling_rate;
	} else if ((rc == TKVDB_EMPTY) || (rc == TKVDB_NOT_FOUND)) {
		/* try to add new key-value pair */
		struct field *fld = clsf->val;
		uint64_t val = monit_object_nf_val(flow, fld);

		val = val * fld->scale * flow->sampling_rate;

		dtval.data = &val;
		dtval.size = sizeof(val);

		rc = tr->put(tr, &dtkey, &dtval);
		if (rc == TKVDB_OK) {
		} else if (rc == TKVDB_ENOMEM) {
			/* not enough memory */
		} else {
			LOG("Can't append key, error code %d", rc);
			return 0;
		}
	} else {
		LOG("Can't find key, error code %d", rc);
		return 0;
	}

	return 1;
}

