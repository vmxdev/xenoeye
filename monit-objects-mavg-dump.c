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
mavg_dump_tr(struct mo_mavg *mavg, tkvdb_tr *tr, size_t val_itemsize,
	const char *mo_name)
{
	size_t i;
	int ret = 0;
	tkvdb_cursor *c;

	__float128 wnd_size_ns;

	struct timespec tmsp;
	uint64_t time_ns;

	if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
		LOG("clock_gettime() failed: %s", strerror(errno));
	}
	time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

	/* time window in nanoseconds */
	wnd_size_ns = (__float128)mavg->size_secs * 1e9;

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
	printf("dump %s:%s\n", mo_name, mavg->name);
	do {
		uint8_t *data = c->key(c);
		uint8_t *pval = c->val(c);


		for (i=0; i<mavg->fieldset.n_naggr; i++) {
			struct field *fld = &mavg->fieldset.naggr[i];
			monit_object_field_print(fld, stdout, data, 1);

			data += fld->size;
		}

		printf(" :: ");
		for (i=0; i<mavg->fieldset.n_aggr; i++) {
			size_t j;
			struct mavg_val *val;
			__float128 v;

			val = MAVG_VAL(pval, i, val_itemsize);
			v = val->val;

			/* correct value */
			if (time_ns > (val->time_prev + wnd_size_ns)) {
				v = 0.0;
			} else {
				v = v - (time_ns - val->time_prev)
					/ wnd_size_ns * v;
				v /= (__float128)mavg->size_secs;
			}

			printf("%g ", (double)v);

			/* limits */
			printf("(");
			for (j=0; j<mavg->noverlimit; j++) {
				/* */
				printf("%g ", (double)val->limits_max[j]);
			}

			printf(")");
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
mavg_dump(struct mo_mavg *mavg, size_t nthreads, const char *mo_name)
{
	size_t i;

	/* dump data from all threads */
	for (i=0; i<nthreads; i++) {
		mavg_dump_tr(mavg, mavg->data[i].tr,
			mavg->data[i].val_itemsize, mo_name);
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

				if ((mavg->last_dump + mavg->dump_secs)
					<= t) {

					/* time to dump */
					if (mavg_dump(mavg, data->nthreads,
						mo->name)) {

						mavg->last_dump = t;
						need_sleep = 0;
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

