/*
 * xenoeye
 *
 * Copyright (c) 2019, Vladimir Misyurov
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

#include "utils.h"
#include "netflow_templates.h"
#include "tkvdb/tkvdb.h"

#define TEMPLATES_DBFILE "templates.tkv"

static tkvdb *db;     /* templates database */
static tkvdb_tr *tr;  /* transaction */

int
netflow_templates_init(void)
{
	db = tkvdb_open(TEMPLATES_DBFILE, NULL);
	if (!db) {
		LOG("Can't create transaction");
		goto fail_db;
	}

	tr = tkvdb_tr_create(db, NULL);
	if (!tr) {
		LOG("Can't create transaction");
		goto fail_tr;
	}

	tr->begin(tr);
	return 1;

fail_tr:
	tkvdb_close(db);
fail_db:
	return 0;
}

void
netflow_templates_shutdown(void)
{
	tr->free(tr);
	tkvdb_close(db);
}

struct nf9_template_item *
netflow_template_find(struct template_key *tkey)
{
	tkvdb_cursor *c;
	tkvdb_datum dtk;
	TKVDB_RES rc;
	struct nf9_template_item *ret = NULL;

	/* search for the most recent template */
	c = tkvdb_cursor_create(tr);
	dtk.data = tkey->data;
	dtk.size = tkey->size;
	rc = c->seek(c, &dtk, TKVDB_SEEK_LE);
	if ((rc == TKVDB_OK) && (c->keysize(c) == tkey->size)) {
		/* size of key without epoch */
		size_t sk = tkey->size - sizeof(uint32_t);
		if (memcmp(c->key(c), tkey->data, sk) == 0) {
			ret = c->val(c);
			c->free(c);
		}
	}

	return ret;
}

int
netflow_template_add(struct template_key *tkey, struct nf9_template_item *t)
{
	tkvdb_datum dtk, dtv;

	LOG("adding template");
	dtk.data = tkey->data;
	dtk.size = tkey->size;

	dtv.data = t;
	dtv.size = 4 + ntohs(t->field_count) * 4;

	if (tr->put(tr, &dtk, &dtv) != TKVDB_OK) {
		return 0;
	}
	if (tr->commit(tr) != TKVDB_OK) {
		return 0;
	}
	tr->begin(tr);
	LOG("template added");

	return 1;
}

