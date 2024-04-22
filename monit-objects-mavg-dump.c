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

static int
mavg_dump_tr(FILE *out, struct mo_mavg *mavg, tkvdb_tr *tr,
	size_t val_itemsize)
{
	size_t i;
	int ret = 0;
	tkvdb_cursor *c;
	size_t mem_used;

	MAVG_TYPE wnd_size_ns;

	struct timespec tmsp;
	uint64_t time_ns;

	if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
		LOG("clock_gettime() failed: %s", strerror(errno));
	}
	time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

	/* time window in nanoseconds */
	wnd_size_ns = (MAVG_TYPE)mavg->size_secs * 1e9;

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		ret = 1;
		goto empty;
	}

	/* print memory used by database */
	mem_used = tr->mem(tr);
	fprintf(out, "mem used/avail: %luM/%luM (%lu/%lu bytes)\n",
		1 + mem_used / (1024 * 1024), mavg->db_mem / (1024 * 1024),
		mem_used, mavg->db_mem);

	/* iterate over all set */
	do {
		uint8_t *data = c->key(c);
		uint8_t *pval = c->val(c);


		for (i=0; i<mavg->fieldset.n_naggr; i++) {
			struct field *fld = &mavg->fieldset.naggr[i];
			monit_object_field_print(fld, out, data, 1);

			data += fld->size;
		}

		fprintf(out, " :: ");

		for (i=0; i<mavg->fieldset.n_aggr; i++) {
			size_t j;
			struct mavg_val *val;
			MAVG_TYPE v;

			val = MAVG_VAL(pval, i, val_itemsize);
			v = val->val;

			/* correct value */
			if (time_ns > (val->time_prev + wnd_size_ns)) {
				v = 0.0;
			} else {
				v = v - (time_ns - val->time_prev)
					/ wnd_size_ns * v;
				v /= (MAVG_TYPE)mavg->size_secs;
			}

			fprintf(out, "%lu ", (uint64_t)v);

			/* limits */
			fprintf(out, "(");
			for (j=0; j<mavg->noverlimit; j++) {
				/* */
				MAVG_TYPE limit;
				limit = atomic_load_explicit(&val->limits_max[j],
					memory_order_relaxed);
				fprintf(out, "%lu ", (uint64_t)limit);
			}

			fprintf(out, ")");
		}

		fprintf(out, "\n");
	} while (c->next(c) == TKVDB_OK);

	fprintf(out, "\n");
	ret = 1;
empty:
	c->free(c);

cursor_fail:
	return ret;
}

static int
mavg_dump_do(struct mo_mavg *mavg, size_t nthreads, struct monit_object *mo,
	int append)
{
	FILE *f;
	char dump_path[PATH_MAX * 2];
	size_t i;
	char timebuf[100];
	time_t t;

	t = time(NULL);
	if (t == (time_t)-1) {
		LOG("time() failed: %s", strerror(errno));
		return 0;
	}

	sprintf(dump_path, append? "%s/%s.adump" : "%s/%s.dump",
		mo->dir, mavg->name);

	if (strlen(dump_path) >= PATH_MAX) {
		LOG("Filename too big: %s/%s", mo->dir, mavg->name);
		return 0;
	}

	f = fopen(dump_path, append? "a": "w");
	if (!f) {
		LOG("Can't open '%s': %s", dump_path, strerror(errno));
		return 0;
	}

	fprintf(f, "%s", ctime_r(&t, timebuf));

	for (i=0; i<nthreads; i++) {
		tkvdb_tr *db;

		db = atomic_load_explicit(&mavg->data[i].db,
			memory_order_relaxed);

		mavg_dump_tr(f, mavg, db, mavg->data[i].val_itemsize);
	}

	if (append) {
		/* extra empty line */
		fprintf(f, "\n");
	}

	fclose(f);

	return 1;
}

static int
mavg_dump(struct mo_mavg *mavg, size_t nthreads, struct monit_object *mo)
{
	char enabled[PATH_MAX * 2];
	struct stat statbuf;
	int dump = 0, append = 0;

	sprintf(enabled, "%s/%s.d", mo->dir, mavg->name);
	if (strlen(enabled) >= PATH_MAX) {
		LOG("Filename too big: %s/%s", mo->dir, mavg->name);
		return 0;
	}

	if (stat(enabled, &statbuf) == 0) {
		dump = 1;
	}

	sprintf(enabled, "%s/%s.a", mo->dir, mavg->name);
	if (stat(enabled, &statbuf) == 0) {
		append = 1;
	}

	if (!dump && !append) {
		/* skip */
		return 0;
	}

	if (dump) {
		mavg_dump_do(mavg, nthreads, mo, 0);
	}

	if (append) {
		mavg_dump_do(mavg, nthreads, mo, 1);
	}

	return 1;
}

void *
mavg_dump_thread(void *arg)
{
	struct xe_data *data = (struct xe_data *)arg;

	for (;;) {
		time_t t;
		size_t i, j;

		if (atomic_load_explicit(&data->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}

		t = time(NULL);
		if (t == ((time_t)-1)) {
			LOG("time() failed: %s", strerror(errno));
			return NULL;
		}

		/* for each monitoring object */
		for (i=0; i<data->nmonit_objects; i++) {
			struct monit_object *mo = &data->monit_objects[i];

			/* for each moving average */
			for (j=0; j<mo->nmavg; j++) {
				struct mo_mavg *mavg = &mo->mavgs[j];

				if (mavg->dump_secs == 0) {
					/* skip */
					continue;
				}

				if ((mavg->last_dump_check + mavg->dump_secs)
					<= t) {

					/* time to dump */
					mavg_dump(mavg, data->nthreads, mo);

					mavg->last_dump_check = t;
				}
			}
		}

		sleep(1);
	}

	return NULL;
}

