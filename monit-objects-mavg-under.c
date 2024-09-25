/*
 * xenoeye
 *
 * Copyright (c) 2024, Vladimir Misyurov
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
underlimit_check(struct mo_mavg *mavg, tkvdb_tr *db)
{
	tkvdb_cursor *c;

	c = tkvdb_cursor_create(db);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		return 0;
	}

	if (c->first(c) != TKVDB_OK) {
		/* empty set */
		goto empty;
	}

	do {
		size_t i;
		uint8_t *key = c->key(c);
		for (i=0; i<mavg->fieldset.n_naggr; i++) {
			struct field *fld = &mavg->fieldset.naggr[i];
			monit_object_field_print(fld, stderr, key, 1);
			fprintf(stderr, "\n");
		}
/*
		dtk.data = c->key(c);
		dtk.size = c->keysize(c);
*/
	} while (c->next(c) == TKVDB_OK);

empty:
	c->free(c);

	return 1;
}


static int
mavg_merge(struct mo_mavg *mavg, tkvdb_tr *db, tkvdb_tr *thread_db,
	uint64_t time_ns, int skip_zeros)
{
	MAVG_TYPE wndsize = mavg->size_secs * 1e9;
	tkvdb_cursor *c;

	c = tkvdb_cursor_create(thread_db);
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
		size_t i;
		int has_non_zero = 0;

		size_t val_itemsize = c->valsize(c);
		uint8_t *vals_db = c->val(c);

		/* array of vals */
		uint8_t vals_local[val_itemsize];

		/* recalculate moving avg values for the current time */
		for (i=0; i<mavg->fieldset.n_aggr; i++) {
			struct mavg_val *val, *val_db;
			MAVG_TYPE v, new_v;
			uint64_t tmdiff;
			size_t j;

			val = MAVG_VAL(vals_local, i, val_itemsize);
			val_db = MAVG_VAL(vals_db, i, val_itemsize);

			v = atomic_load_explicit(&val_db->val,
				memory_order_relaxed);
			tmdiff = time_ns
				- atomic_load_explicit(&val_db->time_prev,
					memory_order_relaxed);

			if (tmdiff < wndsize) {
				new_v = v - tmdiff / wndsize * v;
				val->val = new_v;
				if ((__int128_t)new_v != 0) {
					has_non_zero = 1;
				}
			} else {
				val->val = 0.0f;
			}

			/* rest of structure */
			val->time_prev = time_ns;
			for (j=0; j<mavg->noverlimit + mavg->nunderlimit; j++) {
				v = atomic_load_explicit(&val_db->limits[j],
					memory_order_relaxed);
				val->limits[j] = v;
			}
		}

		/* skip zeros if needed */
		if (skip_zeros && !has_non_zero) {
			continue;
		}

		dtk.data = c->key(c);
		dtk.size = c->keysize(c);

		/* check if item is in db */
		rc = db->get(db, &dtk, &dtv);
		if (rc == TKVDB_OK) {
			uint8_t *vals = dtv.data;

			/* update data */
			for (i=0; i<mavg->fieldset.n_aggr; i++) {
				struct mavg_val *val_db, *val_local;

				val_db = MAVG_VAL(vals, i, val_itemsize);
				val_local = MAVG_VAL(vals_local, i,
					val_itemsize);
				val_db->val += val_local->val;
			}
		} else {
			/* not found, create new */
			dtv.data = vals_local;
			dtv.size = val_itemsize;

			rc = db->put(db, &dtk, &dtv);
			if (rc != TKVDB_OK) {
				LOG("put() failed, code %d", rc);
				break;
			}
		}
	} while (c->next(c) == TKVDB_OK);

empty:
	c->free(c);

	return 1;
}


static int
mavg_check_underlimit(struct mo_mavg *mavg, size_t nthreads,
	struct monit_object *mo, uint64_t time_ns)
{
	tkvdb_tr *db;
	size_t i;

	db = tkvdb_tr_create(NULL, NULL);
	if (!db) {
		LOG("Can't create transaction");
		return 0;
	}

	db->begin(db);

	for (i=0; i<nthreads; i++) {
		tkvdb_tr *thread_db;

		thread_db = atomic_load_explicit(&mavg->thr_data[i].db,
			memory_order_relaxed);

		mavg_merge(mavg, db, thread_db, time_ns, 1);
	}

	underlimit_check(mavg, db);

	db->free(db);

	return 1;
}

static void
underlimit_check_rec(struct xe_data *globl,
	struct monit_object *mos, size_t n_mo, uint64_t time_ns)
{
	size_t i, j;

	for (i=0; i<n_mo; i++) {
		struct monit_object *mo = &(mos[i]);

		/* for each moving average */
		for (j=0; j<mo->nmavg; j++) {
			struct mo_mavg *mavg = &mo->mavgs[j];
			uint64_t check_at;

			if (mavg->nunderlimit == 0) {
				continue;
			}
			LOG("Has underlimit!");

			check_at = atomic_load_explicit(
				&mavg->underlimit_check_at,
				memory_order_relaxed);

			if ((check_at == 0) || (time_ns < check_at)) {
				continue;
			}

			mavg_check_underlimit(mavg, globl->nthreads, mo,
				time_ns);
		}

		if (mo->n_mo) {
			underlimit_check_rec(globl, mo->mos, mo->n_mo, time_ns);
		}
	}
}

void *
mavg_check_underlimit_thread(void *arg)
{
	struct xe_data *globl = (struct xe_data *)arg;

	for (;;) {
		struct timespec tmsp;
		uint64_t time_ns;

		if (atomic_load_explicit(&globl->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}


		if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
			LOG("clock_gettime() failed: %s", strerror(errno));
		}
		time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

		underlimit_check_rec(globl, globl->monit_objects,
			globl->nmonit_objects, time_ns);

		sleep(2);
	}

	return NULL;
}

