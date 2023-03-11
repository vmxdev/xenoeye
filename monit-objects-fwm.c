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

#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "utils.h"
#include "monit-objects.h"

int
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

int
fwm_config(struct aajson *a, aajson_val *value,
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

		/* by default fw is enabled */
		atomic_init(&tmp[i].active_cnt, 1);

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
	} else if (STRCMP(a, 3, "limit") == 0) {
		window->limit = atoi(value->str);
		if (window->limit < 0) {
			LOG("Incorrect limit '%s'", value->str);
			return 0;
		}
	} else if (STRCMP(a, 3, "create-index") == 0) {
		if ((value->type == AAJSON_VALUE_FALSE)
			|| (strcmp(value->str, "off") == 0)) {

			window->dont_create_index = 1;
		}
	} else if (STRCMP(a, 3, "extended") == 0) {
		if (value->type == AAJSON_VALUE_TRUE) {
			atomic_init(&window->active_cnt, 0);
		}
		/* other values for 'disabled' ignored */
	}

	return 1;
}


static int
fwm_dump(struct mo_fwm *fwm, tkvdb_tr *tr, const char *mo_name,
	const char *exp_dir)
{
	int ret = 0;
	tkvdb_cursor *c;
	FILE *f;
	time_t t;
	char path[PATH_MAX * 2];
	size_t i;
	int first_field;
	int n;
	int hit_limit = 0;
	char table_name[PATH_MAX + 512];

	t = time(NULL);
	if (t == ((time_t) -1)) {
		LOG("time() failed: %s", strerror(errno));
		goto time_fail;
	}

	sprintf(table_name, "%s_%s", mo_name, fwm->name);

	sprintf(path, "%s/%s_%llu.sql", exp_dir, table_name,
		(long long unsigned)t);
	f = fopen(path, "w");
	if (!f) {
		LOG("fopen('%s') failed: %s", path, strerror(errno));
		goto fopen_fail;
	}

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		ret = 1;
		goto empty;
	}

	/* generate CREATE TABLE statement */
	fprintf(f, "create table if not exists \"%s\" (\n", table_name);
	fprintf(f, "  time TIMESTAMPTZ,\n");

	first_field = 1;
	for (i=0; i<fwm->fieldset.n; i++) {
		struct field *fld = &fwm->fieldset.fields[i];

		if (!first_field) {
			fprintf(f, ",\n");
		} else {
			first_field = 0;
		}

		if ((fld->type == FILTER_BASIC_ADDR4)
			|| (fld->type == FILTER_BASIC_ADDR6)) {

			fprintf(f, "  %s INET", fld->sql_name);
		} else {
			fprintf(f, "  %s BIGINT", fld->sql_name);
		}
	}
	fprintf(f, ");\n\n");

	/* index */
	if (!fwm->dont_create_index) {
		fprintf(f, "create index concurrently if not exists "
			"\"%s_idx\" on \"%s\"(time);\n\n",
			table_name, table_name);
	}

	n = 0;

	fprintf(f, "BEGIN;\n");
	do {
		uint8_t *data = c->key(c);

		fprintf(f, "insert into \"%s\" ", table_name);
		fprintf(f, "values ( to_timestamp(%llu), ",
			(long long unsigned)t);

		first_field = 1;
		/* parse key */
		for (i=0; i<fwm->fieldset.n; i++) {
			struct field *fld = &fwm->fieldset.fields[i];

			if (!first_field) {
				fprintf(f, ", ");
			} else {
				first_field = 0;
			}

			if (fld->aggr) {
				uint64_t v, *vptr;
				vptr = (uint64_t *)data;

				v = be64toh(*vptr);
				if (fld->descending) {
					/* invert value */
					v = ~v;
				}
				fprintf(f, " %lu ", v);

				data += sizeof(uint64_t);
			} else {
				if (fld->descending) {
					int j;

					for (j=0; j<fld->size; j++) {
						/* invert value */
						data[j] = ~data[j];
					}
				}

				monit_object_field_print(fld, f, data, 1);

				data += fld->size;
			}
		}

		fprintf(f, ");\n");

		/* check limit */
		n++;
		if (fwm->limit) {
			if (n >= fwm->limit) {
				hit_limit = 1;
				break;
			}
		}
	} while (c->next(c) == TKVDB_OK);

	/* calculate others */
	if (hit_limit) {
		size_t j = 0;

		uint64_t others[fwm->fieldset.n_aggr];
		for (i=0; i<fwm->fieldset.n_aggr; i++) {
			others[i] = 0;
		}

		while (c->next(c) == TKVDB_OK) {
			uint8_t *data = c->key(c);

			j = 0;
			for (i=0; i<fwm->fieldset.n; i++) {
				struct field *fld = &fwm->fieldset.fields[i];

				if (fld->aggr) {
					uint64_t v, *vptr;
					vptr = (uint64_t *)data;

					v = be64toh(*vptr);
					if (fld->descending) {
						/* invert value */
						v = ~v;
					}
					others[j] += v;
					j++;

					data += sizeof(uint64_t);
				} else {
					data += fld->size;
				}
			}
		}
		/* print others */
		fprintf(f, "insert into \"%s\" ", table_name);
		fprintf(f, "values ( to_timestamp(%llu), ",
			(long long unsigned)t);

		first_field = 1;
		j = 0;
		for (i=0; i<fwm->fieldset.n; i++) {
			struct field *fld = &fwm->fieldset.fields[i];

			if (!first_field) {
				fprintf(f, ", ");
			} else {
				first_field = 0;
			}

			if (fld->aggr) {
				fprintf(f, " %lu ", others[j]);
				j++;
			} else {
				fprintf(f, " NULL ");
			}
		}

		fprintf(f, ");\n");
	}
	fprintf(f, "COMMIT;\n");

	ret = 1;
empty:
	fclose(f);
	c->free(c);

fopen_fail:
time_fail:
cursor_fail:

	return ret;
}

static int
fwm_sort_tr(struct mo_fwm *fwm, tkvdb_tr *tr, const char *mo_name,
	const char *exp_dir)
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

		uint8_t *naggr = c->key(c);
		uint64_t *aggr = c->val(c);

		/* make key for correct sorting */
		for (i=0; i<fwm->fieldset.n; i++) {
			struct field *fld = &fwm->fieldset.fields[i];
			if (fld->aggr) {
				uint64_t v;
				v = htobe64(*aggr);
				if (fld->descending) {
					/* invert value */
					v = ~v;
				}
				memcpy(kptr, &v, sizeof(uint64_t));
				kptr += sizeof(uint64_t);
				aggr++;
			} else {
				if (fld->descending) {
					int j;

					for (j=0; j<fld->size; j++) {
						/* invert value */
						naggr[j] = ~naggr[j];
					}
				}
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

	fwm_dump(fwm, tr_merge, mo_name, exp_dir);
	tr_merge->free(tr_merge);

	ret = 1;
empty:
tr_fail:
	c->free(c);

cursor_fail:
	return ret;
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
fwm_merge(struct mo_fwm *fwm, size_t nthreads, const char *mo_name,
	const char *exp_dir)
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

	fwm_sort_tr(fwm, tr_merge, mo_name, exp_dir);

	tr_merge->free(tr_merge);

	return 1;
}

void *
fwm_bg_thread(void *arg)
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

			for (j=0; j<mo->nfwm; j++) {
				struct mo_fwm *fwm = &mo->fwms[j];

				if ((fwm->last_export + fwm->time) <= t) {
					/* time to export */
					if (fwm_merge(fwm, data->nthreads,
						mo->name, data->exp_dir)) {

						fwm->last_export = t;
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

