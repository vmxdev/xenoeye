/*
 * xenoeye
 *
 * Copyright (c) 2019-2020, Vladimir Misyurov, Michael Kogan
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

#include "utils.h"
#include "netflow_templates.h"
#include "tkvdb/tkvdb.h"


static tkvdb *db;     /* templates database */
static tkvdb_tr *tr;  /* transaction */

static void
dump(char *pfx, char *data, size_t len)
{
	size_t i;
	char buf[512];

	buf[0] = '\0';
	for (i=0; i<len; i++) {
		char sym[10];

		sprintf(sym, "%02x ", (unsigned char)data[i]);
		strcat(buf, sym);
	}
	LOG("%s: %s", pfx, buf);
}


int
netflow_templates_init(struct xe_data *data)
{
	db = tkvdb_open(data->templates_db, NULL);
	if (!db) {
		LOG("Can't open database '%s'", data->templates_db);
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

void *
netflow_template_find(struct template_key *tkey, int allow_templates_in_future)
{
	tkvdb_cursor *c;
	tkvdb_datum dtk;
	TKVDB_RES rc;
	void *ret = NULL;
	struct template_key *key;

	if (allow_templates_in_future) {
		key = alloca(sizeof(struct template_key));
		*key = *tkey;
		key->epoch = 0xffffff;
	} else {
		key = tkey;
	}

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
	tkvdb_datum dtk, dtv;

	LOG("Adding template");

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
	tr->begin(tr);
	LOG("Template added");

	return 1;
}

