#include "query.h"

static int
accept(struct query_input *i, enum TOKEN_ID token)
{
	if (i->current_token.id != token) {
		return 0;
	}

	read_token(i);

	if (i->error) {
		return 0;
	}

	return 1;
}

static int
expect(struct query_input *i, enum TOKEN_ID token)
{
	if (!accept(i, token)) {
		/* unexpected token */ 
		return 0;
	}

	return 1;
}

static void
saddr(struct query_input *i)
{
	/* saddr in 192.168.0.0/24
	 * daddr = 192.168.0.0/24
	 **/

	if (accept(i, IN)) {
	} else if (accept(i, ASSIGN)) {
	} else {
		mkerror(i, "Expected '=' or 'in' after ADDR");
		return;
	}

	if (!expect(i, CIDR)) {
		mkerror(i, "Expected CIDR (address or address with mask)");
		return;
	}
}

void
parse_query(struct query_input *i)
{
	read_token(i);
	if (accept(i, SADDR)) {
		saddr(i);
	} else if (accept(i, DADDR)) {
		saddr(i);
	} else {
		mkerror(i, "Unexpected token");
	}
}

