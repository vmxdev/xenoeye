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
build_file_name(char *path, struct mo_mavg *mw, uint8_t *key, size_t keysize,
	size_t *limit_id)
{
	size_t i;
	FILE *fname;

	uint8_t *flddata;

	size_t namesize;
	char *nameptr;

	struct mavg_limit *l;

	/* get limit id */
	memcpy(limit_id, key + keysize - sizeof(size_t), sizeof(size_t));

	l = &mw->overlimit[*limit_id];

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

static int
build_file_content(char *text, struct mo_mavg *mw, uint8_t *key,
	MAVG_TYPE val, MAVG_TYPE limit)
{
	size_t i;
	FILE *fcont;
	size_t csize;
	char *cptr;
	uint8_t *flddata;

	fcont = open_memstream(&cptr, &csize);
	if (!fcont) {
		LOG("Can't open memstream: %s", strerror(errno));
		return 0;
	}

	flddata = key;
	for (i=0; i<mw->fieldset.n_naggr; i++) {
		struct field *fld = &mw->fieldset.naggr[i];

		monit_object_field_print(fld, fcont, flddata, 1);

		flddata += fld->size;
	}
	fprintf(fcont, " %lu %lu", (uint64_t)val, (uint64_t)limit);
	/*fprintf(fcont, " %f %f", (double)val, (double)limit);*/
	fclose(fcont);

	strcpy(text, cptr);

	free(cptr);

	return 1;
}

static void
exec_script(struct mo_mavg *mw, uint8_t *key, size_t limit_id, char *mo_name,
	char *script, char *filename, MAVG_TYPE val, MAVG_TYPE limit)
{
	int pid;
	char **args;
	size_t i, argidx = 0;
	uint8_t *flddata;
	char *arg;

	if (!*script) {
		return;
	}

	/* build script args */
	args = alloca((mw->fieldset.n_naggr + 8) * sizeof(char *));
	args[argidx++] = script;
	args[argidx++] = mo_name;
	args[argidx++] = mw->name;
	args[argidx++] = mw->overlimit[limit_id].name;
	args[argidx++] = filename;

	flddata = key;
	for (i=0; i<mw->fieldset.n_naggr; i++) {
		struct field *fld = &mw->fieldset.naggr[i];
		arg = alloca(INET6_ADDRSTRLEN + 10);

		monit_object_field_print_str(fld, arg, flddata, 0);
		args[argidx++] = arg;

		flddata += fld->size;
	}

	arg = alloca(30);
	sprintf(arg, "%lu", (uint64_t)val);
	args[argidx++] = arg;

	arg = alloca(30);
	sprintf(arg, "%lu", (uint64_t)limit);
	args[argidx++] = arg;

	args[argidx++] = NULL;


	pid = fork();
	if (pid == 0) {
		/* child */

		pid = fork();
		if (pid == 0) {
			/* double fork */
			if (execve(args[0], args, NULL) == -1) {
				LOG("Can't start script '%s': %s",
					args[0], strerror(errno));
			}
		} else if (pid == -1) {
			LOG("Can't fork(): %s", strerror(errno));
		}
		exit(EXIT_FAILURE);
	} else if (pid == -1) {
		LOG("Can't fork(): %s", strerror(errno));
	}
}


static void
ext_stats_toggle(struct mo_mavg *mw, int on)
{
	size_t i, j;

	for (i=0; i<mw->noverlimit; i++) {
		struct mavg_limit *ml = &mw->overlimit[i];

		for (j=0; j<ml->n_ext_stat; j++) {
			struct mavg_limit_ext_stat *e = &ml->ext_stat[j];

			if (e->ptr) {
				if (on) {
					atomic_fetch_add_explicit(e->ptr, 1,
						memory_order_relaxed);
				} else {
					atomic_fetch_sub_explicit(e->ptr, 1,
						memory_order_relaxed);
				}
			}
		}
	}
}


static void
on_overlimit(struct mo_mavg *mw, uint8_t *key, size_t keysize,
	struct mavg_ovrlm_data *ovr, char *mo_name)
{
	FILE *f;
	char filename[PATH_MAX];
	char filecont[1024];
	size_t limit_id;
	char *script;

	/* turn on extended statistics */
	ext_stats_toggle(mw, 1);

	if (!build_file_name(filename, mw, key, keysize, &limit_id)) {
		LOG("Can't create file");
		return;
	}

	if (!build_file_content(filecont, mw, key, ovr->val, ovr->limit)) {
		return;
	}

	/* write file */
	f = fopen(filename, "w");
	if (!f) {
		LOG("Can't create file '%s': %s", filename, strerror(errno));
		return;
	}
	fputs(filecont, f);
	fclose(f);

	/* start script */
	script = mw->overlimit[limit_id].action_script;
	exec_script(mw, key, limit_id, mo_name, script, filename, ovr->val,
		ovr->limit);
}

static void
on_update(struct mo_mavg *mw, uint8_t *key, size_t keysize,
	struct mavg_ovrlm_data *ovr, uint64_t time_ns, MAVG_TYPE wnd_size_ns)
{
	FILE *f;
	char filename[PATH_MAX];
	char filecont[1024];
	size_t limit_id;

	MAVG_TYPE val;

	if (!build_file_name(filename, mw, key, keysize, &limit_id)) {
		LOG("Update failed");
		return;
	}


	if (time_ns > (ovr->time_last + wnd_size_ns)) {
		val = 0.0;
	} else {
		val = ovr->val
			- (time_ns - ovr->time_last) / wnd_size_ns * ovr->val;
	}


	if (!build_file_content(filecont, mw, key, val, ovr->limit)) {
		return;
	}

	/* write file */
	f = fopen(filename, "w");
	if (!f) {
		LOG("Can't create file '%s': %s", filename, strerror(errno));
		return;
	}
	fputs(filecont, f);
	fclose(f);
}

static void
on_back_to_norm(struct mo_mavg *mw, uint8_t *key, size_t keysize,
	struct mavg_ovrlm_data *ovr, char *mo_name)
{
	char filename[PATH_MAX];
	char filecont[1024];
	size_t limit_id;
	char *script;

	/* turn off extended statistics */
	ext_stats_toggle(mw, 0);

	if (!build_file_name(filename, mw, key, keysize, &limit_id)) {
		return;
	}

	if (unlink(filename) < 0) {
		LOG("Can't remove file '%s': %s", filename, strerror(errno));
	}

	if (!build_file_content(filecont, mw, key, 0, ovr->limit)) {
		return;
	}

	/* start script */
	script = mw->overlimit[limit_id].back2norm_script;
	exec_script(mw, key, limit_id, mo_name, script, filename, 0,
		ovr->limit);
}

static int
act(struct mo_mavg *mw, tkvdb_tr *db, MAVG_TYPE wnd_size_ns, char *mo_name)
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
			/* traffic is back to normal */
			on_back_to_norm(mw, c->key(c), c->keysize(c), val,
				mo_name);

			val->type = MAVG_OVRLM_GONE;
			goto skip;
		}

		if (val->type == MAVG_OVRLM_UPDATE) {
			if ((val->time_dump + 3*1e9) > time_ns) {
				goto skip;
			}

			on_update(mw, c->key(c), c->keysize(c), val, time_ns,
				wnd_size_ns);

			val->time_dump = time_ns;
		} else if (val->type == MAVG_OVRLM_NEW) {
			on_overlimit(mw, c->key(c), c->keysize(c), val,
				mo_name);

			/* update dump time */
			val->time_dump = time_ns;

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

				act(mw, db_glb, mw->size_secs * 1e9, mo->name);
			}
		}
	}

	return NULL;
}

