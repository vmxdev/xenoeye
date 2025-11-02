/*
 * xenoeye
 *
 * Copyright (c) 2023-2024, Vladimir Misyurov, Michael Kogan
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
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <dirent.h>

#include "config.h"

#include "utils.h"
#include "monit-objects.h"
#include "monit-objects-common.h"
#include "netflow.h"
#include "flow-info.h"

#define TMP_STR_LEN 1024

#ifndef HAVE_GETPROTOBYNUMBER_R
/* musl don't have a getprotobynumber_r */
static pthread_mutex_t getprotobynumber_lock = PTHREAD_MUTEX_INITIALIZER;

static int getprotobynumber_r(int proto, struct protoent *result_buf,
	char buf[], size_t buflen,
	struct protoent **result)
{
	(void)result_buf;
	(void)buflen;
	(void)result;
	struct protoent *pe;

	pthread_mutex_lock(&getprotobynumber_lock);
	pe = getprotobynumber(proto);
	strcpy(buf, pe->p_name);
	pthread_mutex_unlock(&getprotobynumber_lock);

	return 1;
}

#endif

int
classification_fields_init(size_t nthreads, struct mo_classification *clsf)
{
	size_t i, keysize;

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

	/* init classifier db */
	clsf->db.bank[0] = tkvdb_tr_create(NULL, NULL);
	if (!clsf->db.bank[0]) {
		LOG("tkvdb_tr_create() failed");
		return 0;
	}
	clsf->db.bank[1] = tkvdb_tr_create(NULL, NULL);
	if (!clsf->db.bank[1]) {
		LOG("tkvdb_tr_create() failed");
		return 0;
	}
	clsf->db.bank[0]->begin(clsf->db.bank[0]);
	clsf->db.bank[1]->begin(clsf->db.bank[1]);

	atomic_store_explicit(&clsf->db.idx, 0, memory_order_relaxed);

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
	size_t i;
	struct mo_classification *clsf;

	if (a->path_stack[2].type != AAJSON_PATH_ITEM_ARRAY) {
		LOG("'classification' must be an array");
		return 0;
	}

	i = a->path_stack[2].data.array_idx;
	if (i >= mo->nclassifications) {
		struct mo_classification *tmp;

		/* append */
		tmp = realloc(mo->classifications,
			(i + 1) * sizeof(struct mo_classification));

		if (!tmp) {
			LOG("realloc() failed");
			return 0;
		}

		memset(&tmp[i], 0, sizeof(struct mo_classification));

		/* set id */
		tmp[i].id = i;

		mo->classifications = tmp;
		mo->nclassifications = i + 1;
	}

	clsf = &mo->classifications[i];

#define LEVEL 3
	if (STRCMP(a, LEVEL, "top-percents") == 0) {
		clsf->top_percents = atoi(value->str);
		if (clsf->top_percents > 100) {
			LOG("Incorrect 'top-percents': '%s'", value->str);
			return 0;
		}
	} else if (STRCMP(a, LEVEL, "fields") == 0) {
		if (!config_field_append(value->str, clsf)) {
			return 0;
		}
	} else if (STRCMP(a, LEVEL, "time") == 0) {
		clsf->time = atoi(value->str);
		if (clsf->time <= 0) {
			LOG("Incorrect time '%s'", value->str);
			return 0;
		}
	} else if (STRCMP(a, LEVEL, "id") == 0) {
		clsf->id = atoi(value->str);
		if ((clsf->id < 0) || (clsf->id >= CLASSES_MAX)) {
			LOG("Incorrect id '%s', must be in range[0..%d]",
				value->str, CLASSES_MAX - 1);
			return 0;
		}

	} else if (STRCMP(a, LEVEL, "val") == 0) {
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
#undef LEVEL

	return 1;
}


static void
load_db(struct mo_classification *clsf, const char *clsf_dir,
	const char *mo_name)
{
	DIR *d;
	struct dirent *dir;
	tkvdb_tr *db;
	TKVDB_RES rc;
	size_t b_idx, i;
	int j;
	char clsf_path[PATH_MAX*2 + 10];

	/* get unused bank */
	b_idx = (atomic_load_explicit(&clsf->db.idx, memory_order_relaxed) + 1)
		% 2;

	db = clsf->db.bank[b_idx];
	/* reset data */
	db->rollback(db);
	db->begin(db);

	sprintf(clsf_path, "%s/%s/%d", clsf_dir, mo_name, clsf->id);
	d = opendir(clsf_path);
	if (!d) {
		LOG("Can't open directory '%s': %s", clsf_path,
			strerror(errno));
		return;
	}

	while ((dir = readdir(d)) != NULL) {
		tkvdb_datum dtk, dtv;
		char nmfile[PATH_MAX*2 + 271];
		FILE *f;
		char cdir[PATH_MAX + 1];
		char *cptr;

		char class_name[CLASS_NAME_MAX + 1];
		size_t class_name_len;
		char *nl;

		uint8_t key[4096];
		uint8_t *kptr = key;

		if (dir->d_name[0] == '.') {
			continue;
		}

		if (dir->d_type != DT_DIR) {
			continue;
		}

		/* build a key from dir name */
		strcpy(cdir, dir->d_name);
		cptr = cdir;
		for (i=0; i<clsf->nfields; i++) {
			long long int data;
			char *end;
			struct field *fld = &clsf->fields[i];

			if (!cptr) {
				data = 0;
			} else {
				/* search for separator in dir name */
				end = strchr(cptr, '-');
				if (end) {
					*end = '\0';
					data = atoll(cptr);
					cptr = end + 1;
				} else {
					data = atoll(cptr);
					cptr = NULL;
				}
			}

			switch (fld->size) {
				case sizeof(uint8_t):
					*kptr = data;
					break;
				case sizeof(uint16_t):
					*(uint16_t *)kptr = fld->descending ?
						~htobe16(data) : htobe16(data);
					break;
				case sizeof(uint32_t):
					*(uint32_t *)kptr = fld->descending ?
						~htobe32(data) : htobe32(data);
					break;
				case sizeof(uint64_t):
					*(uint64_t *)kptr = fld->descending ?
						~htobe64(data) : htobe64(data);
					break;

				default:
					/* ??? */
					for (j=0; j<fld->size; j++) {
						kptr[j] = 0;
					}
					break;
			}

			kptr += fld->size;
		}

		/* get name */
		sprintf(nmfile, "%s/%s/name", clsf_path, dir->d_name);
		f = fopen(nmfile, "r");
		if (!f) {
			LOG("Can't open '%s': %s", nmfile, strerror(errno));
			continue;
		}
		class_name_len = fread(class_name, 1, CLASS_NAME_MAX, f);
		class_name[class_name_len] = '\0';
		/* search for \n */
		nl = strchr(class_name, '\n');
		if (nl) {
			*nl = '\0';
			class_name_len = strlen(class_name);
		}
		fclose(f);

		dtk.data = key;
		dtk.size = kptr - key;

		dtv.data = class_name;
		dtv.size = class_name_len;

		rc = db->put(db, &dtk, &dtv);
		if (rc != TKVDB_OK) {
			LOG("put() failed with code %d", rc);
		}
	}
	closedir(d);

	/* swap db banks */
	atomic_fetch_add_explicit(&clsf->db.idx, 1, memory_order_relaxed);
}


static void
field_to_string(struct field *fld, char *str, uint8_t *data)
{
	/* functions mfreq/min with ports */
	if ((strstr(fld->name, "mfreq") != NULL)
		|| (strstr(fld->name, "min") != NULL)) {

		if (strstr(fld->name, "port") != NULL) {
			uint64_t port64 = be64toh(*((uint64_t *)data));
			int port = htobe16(port64);
			struct servent se, *se_res;

			if (getservbyport_r(port, NULL, &se, str,
				TMP_STR_LEN, &se_res) == 0) {

				if (se_res != NULL) {
					return;
				}
			}
		}
	}

	if (fld->id == PROTO) {
		int proto = *data;
		struct protoent pe, *pe_res;

		if (getprotobynumber_r(proto, &pe, str,
			TMP_STR_LEN, &pe_res) == 0) {

			return;
		}
	} else if (fld->id == PORT) {
		int port = *((uint16_t *)data);
		struct servent se, *se_res;

		if (getservbyport_r(port, NULL, &se, str,
			TMP_STR_LEN, &se_res) == 0) {

			if (se_res != NULL) {
				return;
			}
		}
	} else if (fld->id == TCPFLAGS) {
		uint8_t flags = *data;
		int has_flag = 0;

		str[0] = '\0';

#define PRINT_FLAG(N, STR)                \
do {                                      \
	if (flags & N) {                  \
		if (has_flag) {           \
			strcat(str, "+"); \
		}                         \
		strcat(str, STR);         \
		has_flag = 1;             \
	}                                 \
} while (0)

		PRINT_FLAG(0x80, "CWR");
		PRINT_FLAG(0x40, "ECE");
		PRINT_FLAG(0x20, "URG");
		PRINT_FLAG(0x10, "ACK");
		PRINT_FLAG(0x08, "PSH");
		PRINT_FLAG(0x04, "RST");
		PRINT_FLAG(0x02, "SYN");
		PRINT_FLAG(0x01, "FIN");
#undef PRINT_FLAG

		if (has_flag) {
			return;
		}
	}

	monit_object_field_print_str(fld, str, data, 0);
}

static void
update_clsf_dir(const char *clsf_dir, int class_id, const char *mo_name,
	const char *class_dir, const char *class_name,
	uint64_t s, uint64_t sum)
{
	char path[PATH_MAX*2 + 17];
	struct stat st;
	FILE *f;

	sprintf(path, "%s/%s", clsf_dir, mo_name);
	if (stat(path, &st) != 0) {
		/* try to create directory */
		if (mkdir(path, 0755) != 0) {
			LOG("Can't create dir '%s': %s", path,
				strerror(errno));
			return;
		}
	}

	sprintf(path, "%s/%s/%d", clsf_dir, mo_name, class_id);
	if (stat(path, &st) != 0) {
		/* try to create directory */
		if (mkdir(path, 0755) != 0) {
			LOG("Can't create dir '%s': %s", path,
				strerror(errno));
			return;
		}
	}

	sprintf(path, "%s/%s/%d/%s", clsf_dir, mo_name, class_id, class_dir);
	if (stat(path, &st) != 0) {
		/* try to create directory */
		if (mkdir(path, 0755) != 0) {
			LOG("Can't create dir '%s': %s", path,
				strerror(errno));
			return;
		}
	}

	sprintf(path, "%s/%s/%d/%s/name", clsf_dir, mo_name, class_id,
		class_dir);
	if (stat(path, &st) != 0) {
		/* no file */
		f = fopen(path, "w");
		if (f) {
			fprintf(f, "%s", class_name);
			fclose(f);
		} else {
			LOG("Can't open file '%s': %s", path,
				strerror(errno));
		}
	}

	sprintf(path, "%s/%s/%d/%s/stats", clsf_dir, mo_name, class_id,
		class_dir);
	f = fopen(path, "w");
	if (!f) {
		LOG("Can't create file '%s': %s", path,
			strerror(errno));
		return;
	}
	fprintf(f, "%lu of %lu, %f%%\n", s, sum, (double)s * 100.0 / sum);
	fclose(f);
}

static int
classification_dump(struct mo_classification *clsf, tkvdb_tr *tr,
	const char *mo_name, const char *clsf_dir)
{
	int ret = 0;
	tkvdb_cursor *c;
	uint64_t sum = 0, sumtmp = 0;
	char class_dir[CLASS_NAME_MAX + 1];
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
		uint64_t *s_ptr = c->key(c);

		uint64_t s = clsf->val->descending ? be64toh(~(*s_ptr))
			: be64toh(*s_ptr);

		sum += s;
	} while (c->next(c) == TKVDB_OK);

	/* second pass, get top % */
	c->first(c);
	do {
		uint8_t ktmp[64];
		char str[TMP_STR_LEN];
		size_t i;

		uint64_t *s_ptr = c->key(c);

		uint8_t *naggr = c->key(c);

		uint64_t s = clsf->val->descending ? be64toh(~(*s_ptr))
			: be64toh(*s_ptr);

		sumtmp += s;

		naggr += sizeof(uint64_t);
 
		class_name[0] = '\0';
		class_dir[0] = '\0';
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

			monit_object_field_print_str(fld, str, ktmp, 0);
			strcat(class_dir, str);

			field_to_string(fld, str, ktmp);
			strcat(class_name, str);

			if ((i + 1) < clsf->nfields) {
				strcat(class_name, ",");
				strcat(class_dir, "-");
			}
		}

		update_clsf_dir(clsf_dir, clsf->id, mo_name, class_dir,
			class_name, s, sum);

		if ((sumtmp * 100 / sum) >= clsf->top_percents) {
			break;
		}
	} while (c->next(c) == TKVDB_OK);

	ret = 1;

empty:
	c->free(c);

cursor_fail:

	return ret;
}


static int
classification_sort_dump(struct mo_classification *clsf, tkvdb_tr *tr,
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
			tmpv = ~htobe64(*v);
		} else {
			tmpv = htobe64(*v);
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

	classification_sort_dump(clsf, tr_merge, mo_name, clsf_dir);

	tr_merge->free(tr_merge);

	return 1;
}

static void
classification_merge_rec(struct xe_data *globl, struct monit_object *mos,
	size_t n_mo, time_t t)
{
	size_t i;
	int need_sleep = 1;

	for (i=0; i<n_mo; i++) {
		size_t j;
		struct monit_object *mo = &mos[i];

		for (j=0; j<mo->nclassifications; j++) {
			struct mo_classification *clsf
				= &mo->classifications[j];

			if ((clsf->last_export + clsf->time) <= t) {
				/* time to export */
				if (classification_merge(clsf,
					globl->nthreads,
					mo->name, globl->clsf_dir)) {

					clsf->last_export = t;
					need_sleep = 0;
				} else {
					continue;
				}

				load_db(clsf, globl->clsf_dir, mo->name);
			}
		}

		if (mo->n_mo) {
			classification_merge_rec(globl, mo->mos, mo->n_mo, t);
		}
	}

	if (need_sleep) {
		sleep(1);
	}
}

void *
classification_bg_thread(void *arg)
{
	struct xe_data *globl = (struct xe_data *)arg;

	for (;;) {
		time_t t;

		if (atomic_load_explicit(&globl->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}

		t = time(NULL);
		if (t == ((time_t)-1)) {
			LOG("time() failed: %s", strerror(errno));
			return NULL;
		}

		classification_merge_rec(globl, globl->monit_objects,
			globl->nmonit_objects, t);
	}

	return NULL;
}

static int
classification_process_nf_class(struct monit_object *mo, size_t thread_id,
	struct flow_info *flow, uint8_t *flow_class, int class_id)
{
	size_t i;
	struct mo_classification *clsf = &mo->classifications[class_id];
	struct classification_thread_data *cdata =
		&clsf->thread_data[thread_id];

	uint8_t *key;

	size_t tr_idx;
	tkvdb_tr *tr;

	size_t clsf_b_idx;
	tkvdb_tr *clsf_db;
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

	/* get classifier db */
	clsf_b_idx = atomic_load_explicit(&clsf->db.idx, memory_order_relaxed)
		% 2;

	clsf_db = clsf->db.bank[clsf_b_idx];

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

	/* search for class in db */
	rc = clsf_db->get(clsf_db, &dtkey, &dtval);
	if (rc == TKVDB_OK) {
		/* copy class name to flow */
		char *class_name = dtval.data;
		memcpy((char *)flow_class, class_name, dtval.size);
		flow_class[dtval.size] = '\0';
	} else {
		flow_class[0] = '\0';
	}

	return 1;
}

int
classification_process_nf(struct monit_object *mo, size_t thread_id,
	struct flow_info *flow)
{
	int i;

#define DO(ID, CLASS) flow->has_##CLASS = 0;
FOR_LIST_OF_CLASSES
#undef DO

	for (i=0; (unsigned int)i<mo->nclassifications; i++) {

		if (0) {

#define DO(ID, CLASS)                                                       \
		} else if (mo->classifications[i].id == ID) {               \
			memset(flow->CLASS, 0, CLASS_NAME_MAX);             \
			flow->has_##CLASS = 1;                              \
			classification_process_nf_class(mo, thread_id, flow,\
				flow->CLASS, i);
FOR_LIST_OF_CLASSES
#undef DO
		}
	}

	return 1;
}

