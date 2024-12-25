/*
 * xenoeye
 *
 * Copyright (c) 2022-2024, Vladimir Misyurov, Michael Kogan
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
build_file_name(char *path, struct mo_mavg *mavg, uint8_t *key, size_t keysize,
	size_t *limit_id, int is_overlim)
{
	size_t i;
	FILE *fname;

	uint8_t *flddata;

	size_t namesize;
	char *nameptr;

	struct mavg_limit *l;

	/* get limit id */
	memcpy(limit_id, key + keysize - sizeof(size_t), sizeof(size_t));

	if (is_overlim) {
		l = &mavg->overlimit[*limit_id];
	} else {
		l = &mavg->underlimit[*limit_id];
	}

	/* build file name */
	fname = open_memstream(&nameptr, &namesize);
	if (!fname) {
		LOG("Can't open memstream: %s", strerror(errno));
		return 0;
	}

	fprintf(fname, "%s-%s-", mavg->notif_pfx, l->name);
	flddata = key;
	for (i=0; i<mavg->fieldset.n_naggr; i++) {
		struct field *fld = &mavg->fieldset.naggr[i];

		monit_object_field_print(fld, fname, flddata, 0);
		if ((i + 1) < mavg->fieldset.n_naggr) {
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
	char *script, char *filename, MAVG_TYPE val, MAVG_TYPE limit,
	int is_overlim)
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
	if (is_overlim) {
		args[argidx++] = mw->overlimit[limit_id].name;
	} else {
		args[argidx++] = mw->underlimit[limit_id].name;
	}
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
			setsid();
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
ext_stats_toggle(struct mo_mavg *mw, int on, int is_overlim)
{
	size_t i, j, n;

	if (is_overlim) {
		n = mw->noverlimit;
	} else {
		n = mw->nunderlimit;
	}

	for (i=0; i<n; i++) {
		struct mavg_limit *ml;
		if (is_overlim) {
			ml = &mw->overlimit[i];
		} else {
			ml = &mw->underlimit[i];
		}

		for (j=0; j<ml->n_ext_stat; j++) {
			struct mavg_limit_ext_stat *e = &ml->ext_stat[j];

			if (e->ptr) {
				if (on) {
					atomic_store_explicit(e->ptr, 1,
						memory_order_relaxed);
				} else {
					atomic_store_explicit(e->ptr, 0,
						memory_order_relaxed);
				}
			}
		}
	}
}


static void
on_limit(struct mo_mavg *mw, uint8_t *key, size_t keysize,
	struct mavg_lim_data *ovr, char *mo_name, int is_overlim)
{
	FILE *f;
	char filename[PATH_MAX];
	char filecont[1024];
	size_t limit_id;
	char *script;

	/* turn on extended statistics */
	ext_stats_toggle(mw, 1, is_overlim);

	if (!build_file_name(filename, mw, key, keysize, &limit_id,
		is_overlim)) {

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
	if (is_overlim) {
		script = mw->overlimit[limit_id].action_script;
	} else {
		script = mw->underlimit[limit_id].action_script;
	}

	exec_script(mw, key, limit_id, mo_name, script, filename, ovr->val,
		ovr->limit, is_overlim);
}

static void
on_update(struct mo_mavg *mw, uint8_t *key, size_t keysize,
	struct mavg_lim_data *ovr, MAVG_TYPE val)
{
	FILE *f;
	char filename[PATH_MAX];
	char filecont[1024];
	size_t limit_id;

	if (!build_file_name(filename, mw, key, keysize, &limit_id, 1)) {
		LOG("Update failed");
		return;
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
	struct mavg_lim_data *ld, char *mo_name, MAVG_TYPE val, int is_overlim)
{
	char filename[PATH_MAX];
	char filecont[1024];
	size_t limit_id;
	char *script;

	/* turn off extended statistics */
	ext_stats_toggle(mw, 0, is_overlim);

	if (!build_file_name(filename, mw, key, keysize, &limit_id,
		is_overlim)) {

		return;
	}

	if (unlink(filename) < 0) {
		LOG("Can't remove file '%s': %s", filename, strerror(errno));
	}

	if (!build_file_content(filecont, mw, key, val, ld->limit)) {
		return;
	}

	/* start script */
	if (is_overlim) {
		script = mw->overlimit[limit_id].back2norm_script;
	} else {
		script = mw->underlimit[limit_id].back2norm_script;
	}
	exec_script(mw, key, limit_id, mo_name, script, filename, val,
		ld->limit, is_overlim);
}

int
act(struct mo_mavg *mw, tkvdb_tr *db, MAVG_TYPE wnd_size_ns, char *mo_name,
	int is_overlim)
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
		struct mavg_lim_data *ld = c->val(c);
		MAVG_TYPE val;
		int cmp_res;

		if (ld->state == MAVG_LIM_GONE) {
			goto skip;
		}

		if (ld->state == MAVG_LIM_NEW) {
			on_limit(mw, c->key(c), c->keysize(c), ld,
				mo_name, is_overlim);

			/* update dump time */
			ld->time_dump = time_ns;

			/* change type */
			ld->state = MAVG_LIM_UPDATE;
			goto skip;
		}

		/* calculate val */
		if (time_ns > (ld->time_last + wnd_size_ns)) {
			val = 0.0;
		} else {
			val = ld->val
				- (time_ns - ld->time_last)
				  / wnd_size_ns * ld->val;
		}


		/* UPDATE or ALMOST_GONE */
		if (is_overlim) {
			cmp_res = val > ld->limit;
		} else {
			cmp_res = val < ld->limit;
		}
		if (cmp_res) {
			ld->state = MAVG_LIM_UPDATE;
			ld->time_back2norm = 0;
		} else {
			if (ld->state == MAVG_LIM_UPDATE) {
				ld->state = MAVG_LIM_ALMOST_GONE;
				ld->time_back2norm = time_ns;
			}
		}

		if (ld->state == MAVG_LIM_ALMOST_GONE) {
			if (time_ns > (ld->time_back2norm + ld->back2norm_time_ns)) {
				/* traffic is back to normal */
				on_back_to_norm(mw, c->key(c), c->keysize(c),
					ld, mo_name, val, is_overlim);

				ld->state = MAVG_LIM_GONE;
				goto skip;
			}
		}

		if ((ld->time_dump + 3*1e9) > time_ns) {
			goto skip;
		}

		/* update notification file */
		on_update(mw, c->key(c), c->keysize(c), ld, val);
		ld->time_dump = time_ns;

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

		struct mavg_lim_data *val_thr = c->val(c);

		dtk.data = c->key(c);
		dtk.size = c->keysize(c);

		rc = db->get(db, &dtk, &dtv);
		if (rc == TKVDB_OK) {
			/* item is in database */
			struct mavg_lim_data *val_glb = dtv.data;

			if (val_glb->state == MAVG_LIM_UPDATE) {
				/* update time */
				val_glb->time_last = val_thr->time_last;

				/* check time */
				/* FIXME: move timeout to config? */
				if ((val_glb->time_dump + 3e9)
					< val_thr->time_last) {

					goto skip;
				}
				val_glb->val = val_thr->val;
			} else if (val_glb->state == MAVG_LIM_GONE) {
				/* restart actions */
				val_glb->state = MAVG_LIM_NEW;

				val_glb->time_last = val_thr->time_last;
				val_glb->time_dump = 0;
				val_glb->val = val_thr->val;
				val_glb->limit = val_thr->limit;
				val_glb->back2norm_time_ns
					= val_thr->back2norm_time_ns;
			}
			/* don't touch items with type MAVG_LIM_NEW */
		} else {
			/* new item */
			struct mavg_lim_data val;

			val.state = MAVG_LIM_NEW;
			val.time_last = val_thr->time_last;
			val.time_dump = 0;
			val.val = val_thr->val;
			val.limit = val_thr->limit;
			val.back2norm_time_ns = val_thr->back2norm_time_ns;

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

static void
check_rec(struct xe_data *globl, size_t bank,
	struct monit_object *mos, size_t n_mo)
{
	size_t i;
	for (i=0; i<n_mo; i++) {
		size_t mwidx;
		struct monit_object *mo = &mos[i];

		/* for each moving average in this object */
		for (mwidx=0; mwidx<mo->nmavg; mwidx++) {
			size_t tidx;
			struct mo_mavg *mw = &mo->mavgs[mwidx];
			tkvdb_tr *db_glb = mw->ovrerlm_db;

			/* for each thread data */
			for (tidx=0; tidx<globl->nthreads; tidx++) {
				tkvdb_tr *db_thr
					= mw->thr_data[tidx].ovr_db[bank];

				check_items(db_glb, db_thr);

				/* reset per-thread databases */
				db_thr->rollback(db_thr);
				db_thr->begin(db_thr);
			}

			act(mw, db_glb, mw->size_secs * 1e9, mo->name, 1);
		}

		if (mo->n_mo) {
			check_rec(globl, bank, mo->mos, mo->n_mo);
		}
	}
}

void *
mavg_act_thread(void *arg)
{
	struct xe_data *globl = (struct xe_data *)arg;

	for (;;) {
		size_t bank;

		if (atomic_load_explicit(&globl->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}

		/* switch bank and get previous */
		bank = atomic_fetch_add_explicit(&globl->mavg_db_bank_idx, 1,
			memory_order_relaxed) % 2;

		usleep(100000);
		check_rec(globl, bank,
			globl->monit_objects, globl->nmonit_objects);
	}

	return NULL;
}

