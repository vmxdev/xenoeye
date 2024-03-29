/*
 * xenoeye
 *
 * Copyright (c) 2019-2022, Vladimir Misyurov, Michael Kogan
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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <alloca.h>
#include <errno.h>

#include "utils.h"
#include "netflow-templates.h"
#include "tkvdb/tkvdb.h"

static const char *templates_db;             /* path to templates db file */
static tkvdb_tr *mem_dbs[2] = {NULL, NULL};  /* database in memory */
static _Atomic size_t db_idx = 0;            /* index of current mem_db */

/* load templates from disk to mem db */
static int
templates_load(size_t idx)
{
	tkvdb *db;

	tkvdb_cursor *c;
	TKVDB_RES rc;
	tkvdb_tr *tr;
	tkvdb_tr *dst;
	int ret = 0;

	dst = mem_dbs[idx];

	db = tkvdb_open(templates_db, NULL);
	if (!db) {
		LOG("Can't open database '%s': %s", templates_db,
			strerror(errno));
		goto fail_db;
	}

	tr = tkvdb_tr_create(db, NULL);
	if (!tr) {
		LOG("Can't create transaction");
		goto fail_tr;
	}

	tr->begin(tr);

	c = tkvdb_cursor_create(tr);
	if (!c) {
		LOG("tkvdb_cursor_create() failed");
		goto cursor_fail;
	}

	if (c->first(c) != TKVDB_OK) {
		/* empty on-disk database */
		goto empty;
	}

	do {
		tkvdb_datum dtk, dtv;

		dtk = c->key_datum(c);
		dtv = c->val_datum(c);

		rc = dst->put(dst, &dtk, &dtv);
		if (rc != TKVDB_OK) {
			LOG("Can't load template item, skipping");
		}
	} while (c->next(c) == TKVDB_OK);

	c->free(c);

empty:
	tr->rollback(tr);
	tr->free(tr);
	ret = 1;

cursor_fail:
fail_tr:
	tkvdb_close(db);
fail_db:

	return ret;
}

int
netflow_templates_init(struct xe_data *globl)
{
	size_t i;

	templates_db = globl->templates_db;

	for (i=0; i<2; i++) {
		mem_dbs[i] = tkvdb_tr_create(NULL, NULL);
		if (!mem_dbs[i]) {
			LOG("Can't create mem db");
			goto fail_tr;
		}

		mem_dbs[i]->begin(mem_dbs[i]);
	}

	templates_load(0);

	return 1;

fail_tr:
	netflow_templates_shutdown();

	return 0;
}

void
netflow_templates_shutdown(void)
{
	size_t i;

	for (i=0; i<2; i++) {
		if (mem_dbs[i]) {
			mem_dbs[i]->free(mem_dbs[i]);
			mem_dbs[i] = NULL;
		}
	}
}

void *
netflow_template_find(struct template_key *tkey, int allow_templates_in_future)
{
	tkvdb_cursor *c;
	tkvdb_datum dtk;
	TKVDB_RES rc;
	void *ret = NULL;
	struct template_key *key;
	tkvdb_tr *tr;

	if (allow_templates_in_future) {
		key = alloca(sizeof(struct template_key));
		*key = *tkey;
		key->epoch = 0xffffff;
	} else {
		key = tkey;
	}

	/* select current db bank */
	tr = mem_dbs[atomic_load_explicit(&db_idx, memory_order_relaxed) % 2];

	/* search for the most recent template */
	c = tkvdb_cursor_create(tr);
	dtk.data = key;
	dtk.size = sizeof(struct template_key);

	rc = c->seek(c, &dtk, TKVDB_SEEK_LE);
	if ((rc == TKVDB_OK)
		&& (c->keysize(c) == sizeof(struct template_key))) {

		/* size of key without time */
		size_t sk = sizeof(struct template_key) - sizeof(uint32_t);

		/* compare keys without time */
		if (memcmp(c->key(c), key, sk) == 0) {
			ret = c->val(c);
		}
	}
	c->free(c);

	return ret;
}

int
netflow_template_add(struct template_key *tkey, void *t, size_t size)
{
	tkvdb *db;
	tkvdb_datum dtk, dtv;

	tkvdb_tr *tr;
	size_t idx;

	LOG("Adding template");

	/* add template to on-disk database */
	db = tkvdb_open(templates_db, NULL);
	if (!db) {
		LOG("Can't open database '%s': %s", templates_db,
			strerror(errno));
		goto fail_db;
	}

	tr = tkvdb_tr_create(db, NULL);
	if (!tr) {
		LOG("Can't create transaction");
		goto fail_tr;
	}

	tr->begin(tr);

	dtk.data = tkey;
	dtk.size = sizeof(struct template_key);

	dtv.data = t;
	dtv.size = size;

	if (tr->put(tr, &dtk, &dtv) != TKVDB_OK) {
		LOG("Can't put template in storage");
		return 0;
	}
	if (tr->commit(tr) != TKVDB_OK) {
		LOG("Can't commit transaction");
		return 0;
	}
	tkvdb_close(db);

	/* get index of inactive mem db */
	idx = (atomic_load_explicit(&db_idx, memory_order_relaxed) + 1) % 2;

	/* reset inactive mem db */
	tr = mem_dbs[idx];
	tr->rollback(tr);
	tr->begin(tr);

	/* load new db from disk to the inactive mem db */
	if (!templates_load(idx)) {
		goto fail_load;
	}

	/* swap banks atomically, inactive db becomes active */
	atomic_fetch_add_explicit(&db_idx, 1, memory_order_relaxed);

	LOG("Template added");

	return 1;

fail_tr:
	tkvdb_close(db);
fail_load:
fail_db:
	return 0;
}

