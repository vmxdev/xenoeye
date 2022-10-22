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

static int
build_file_name(char *path, struct mo_mavg *mw, uint8_t *key, size_t keysize)
{
	size_t i;
	FILE *fname;

	uint8_t *flddata;

	size_t namesize;
	char *nameptr;

	size_t limit_id;
	struct mavg_limit *l;

	/* get limit id */
	memcpy(&limit_id, key + keysize - sizeof(size_t), sizeof(size_t));

	l = &mw->overlimit[limit_id];

	/* build file name */
	fname = open_memstream(&nameptr, &namesize);
	if (!fname) {
		LOG("Can't open memstream: %s", strerror(errno));
		return 0;
	}

	fprintf(fname, "%s-%s-", mw->notif_pfx, l->name);
	flddata = key;
	for (i=0; i<mw->fieldset.n_naggr; i++) {
		struct field *fld = &mw->fieldset.naggr[i];

		monit_object_field_print(fld, fname, flddata, 0);
		if ((i + 1) < mw->fieldset.n_naggr) {
			fprintf(fname, "-");
		}

		flddata += fld->size;
	}
	fclose(fname);

	strcpy(path, nameptr);

	free(nameptr);

	return 1;
}

static void
on_overlimit(struct mo_mavg *mw, uint8_t *key, size_t keysize,
	struct mavg_ovrlm_data *ovr)
{
	size_t i;
	uint8_t *flddata;

	FILE *fcont, *f;
	size_t csize;
	char *cptr;
	char filename[PATH_MAX];

	if (!build_file_name(filename, mw, key, keysize)) {
		return;
	}

	/* build file content */
	fcont = open_memstream(&cptr, &csize);
	if (!fcont) {
		LOG("Can't open memstream: %s", strerror(errno));
		return;
	}

	flddata = key;
	for (i=0; i<mw->fieldset.n_naggr; i++) {
		struct field *fld = &mw->fieldset.naggr[i];

		monit_object_field_print(fld, fcont, flddata, 1);

		flddata += fld->size;
	}
	fprintf(fcont, " %lu %lu", (uint64_t)ovr->val, (uint64_t)ovr->limit);
	/*fprintf(fcont, " %f %f", (double)ovr->limit, (double)ovr->val);*/
	fclose(fcont);

	/* write file */
	f = fopen(filename, "w");
	if (!f) {
		LOG("Can't create file '%s': %s", filename, strerror(errno));
		return;
	}
	fputs(cptr, f);
	fclose(f);

	free(cptr);
}

static void
on_update(struct mo_mavg *mw, uint8_t *key, size_t keysize,
	struct mavg_ovrlm_data *ovr)
{
}

static void
on_ret_to_norm(struct mo_mavg *mw, uint8_t *key, size_t keysize)
{
	char filename[PATH_MAX];

	build_file_name(filename, mw, key, keysize);
	if (unlink(filename) < 0) {
		LOG("Can't remove file '%s': %s", filename, strerror(errno));
	}
}

static int
act(struct mo_mavg *mw, tkvdb_tr *db)
{
	int ret = 0;
	tkvdb_cursor *c;

	struct timespec tmsp;
	uint64_t time_ns;

	if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
		LOG("clock_gettime() failed: %s", strerror(errno));
		return 0;
	}
	time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

	c = tkvdb_cursor_create(db);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		ret = 1;
		goto empty;
	}

	do {
		struct mavg_ovrlm_data *val = c->val(c);

		if (val->type == MAVG_OVRLM_GONE) {
			goto skip;
		}

		/* FIXME: move timeout to config */
		if ((val->time_last + 20*1e9) < time_ns) {
			/* return to normal */
			on_ret_to_norm(mw, c->key(c), c->keysize(c));

			val->type = MAVG_OVRLM_GONE;
			goto skip;
		}

		if (val->type == MAVG_OVRLM_UPDATE) {
			if ((val->time_dump + 3e9) > val->time_last) {
				/* update */
				on_update(mw, c->key(c), c->keysize(c),
					c->val(c));
				val->time_dump = val->time_last;
			}
		} else if (val->type == MAVG_OVRLM_NEW) {
			/* actions */
			on_overlimit(mw, c->key(c), c->keysize(c),
				c->val(c));

			/* change type */
			val->type = MAVG_OVRLM_UPDATE;
		}
skip: ;
	} while (c->next(c) == TKVDB_OK);

	ret = 1;
empty:
	c->free(c);

cursor_fail:
	return ret;
}

static int
check_items(tkvdb_tr *db, tkvdb_tr *db_thread)
{
	int ret = 0;
	tkvdb_cursor *c;

	c = tkvdb_cursor_create(db_thread);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		ret = 1;
		goto empty;
	}

	do {
		TKVDB_RES rc;
		tkvdb_datum dtk, dtv;

		struct mavg_ovrlm_data *val_thr = c->val(c);

		dtk.data = c->key(c);
		dtk.size = c->keysize(c);

		rc = db->get(db, &dtk, &dtv);
		if (rc == TKVDB_OK) {
			/* item is in database */
			struct mavg_ovrlm_data *val_glb = dtv.data;

			if (val_glb->type == MAVG_OVRLM_UPDATE) {
				/* update time */
				val_glb->time_last = val_thr->time_last;

				/* check time */
				/* FIXME: move timeout to config? */
				if ((val_glb->time_dump + 3e9)
					< val_thr->time_last) {

					goto skip;
				}
				val_glb->val = val_thr->val;
			} else if (val_glb->type == MAVG_OVRLM_GONE) {
				/* restart actions */
				val_glb->type = MAVG_OVRLM_NEW;
				val_glb->time_start = val_thr->time_last;
				val_glb->time_last = val_thr->time_last;
				val_glb->time_dump = 0;
				val_glb->val = val_thr->val;
				val_glb->limit = val_thr->limit;
			}
			/* don't touch items with type MAVG_OVRLM_NEW */
		} else {
			/* new item */
			struct mavg_ovrlm_data val;

			val.type = MAVG_OVRLM_NEW;
			val.time_start = val_thr->time_last;
			val.time_last = val_thr->time_last;
			val.time_dump = 0;
			val.val = val_thr->val;
			val.limit = val_thr->limit;

			dtv.data = &val;
			dtv.size = c->valsize(c);

			rc = db->put(db, &dtk, &dtv);
			if (rc != TKVDB_OK) {
				LOG("Can't insert data, error code %d", rc);
			}
		}

skip: ;
	} while (c->next(c) == TKVDB_OK);

	ret = 1;
empty:
	c->free(c);

cursor_fail:
	return ret;
}

void *
mavg_act_thread(void *arg)
{
	struct xe_data *globl = (struct xe_data *)arg;

	for (;;) {
		size_t moidx;
		size_t bank;

		if (atomic_load_explicit(&globl->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}

		/* switch bank and get previous */
		bank = atomic_fetch_add_explicit(&globl->mavg_db_bank_idx, 1,
			memory_order_relaxed) % 2;

		usleep(10000);

		/* for each monitoring object */
		for (moidx=0; moidx<globl->nmonit_objects; moidx++) {
			size_t mwidx;
			struct monit_object *mo = &globl->monit_objects[moidx];

			/* for each moving average in this object */
			for (mwidx=0; mwidx<mo->nmavg; mwidx++) {
				size_t tidx;
				struct mo_mavg *mw = &mo->mavgs[mwidx];
				tkvdb_tr *db_glb = mw->glb_ovr_db;

				/* for each thread data */
				for (tidx=0; tidx<globl->nthreads; tidx++) {
					tkvdb_tr *db_thr
						= mw->data[tidx].ovr_db[bank];

					check_items(db_glb, db_thr);

					/* reset per-thread databases */
					db_thr->rollback(db_thr);
					db_thr->begin(db_thr);
				}

				act(mw, db_glb);
			}
		}
	}

	return NULL;
}

