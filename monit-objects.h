#ifndef monit_objects_h_included
#define monit_objects_h_included

#include "xe-debug.h"
#include "aajson/aajson.h"
#include "filter.h"

#include "tkvdb.h"

#define FWM_DEFAULT_TIMEOUT 30

#define MAVG_DEFAULT_SIZE 5
#define MAVG_MERGE_DEFAULT_TIMEOUT 2

#define MAVG_NBANKS 3
#define MAVG_DEFAULT_TR_SIZE (1024*1024*256)

#define MAVG_DEFAULT_LIMDB_SIZE (1024*1024)

struct xe_data;
struct nf_flow_info;

struct mo_fieldset
{
	/* all fields */
	size_t n;
	struct field *fields;

	/* key fields (non-aggregable, without packets/octets/etc) */
	size_t n_naggr;
	struct field *naggr;

	/* aggregable fields */
	size_t n_aggr;
	struct field *aggr;
};

struct fwm_data
{
	/* using two banks */
	tkvdb_tr *trs[2];

	/* current bank */
	tkvdb_tr *_Atomic tr;

	uint8_t *key;
	uint64_t *val;

	size_t keysize, valsize;
};

struct mo_fwm
{
	char name[TOKEN_MAX_SIZE];
	struct mo_fieldset fieldset;

	time_t last_export;
	int time;

	int limit;

	int dont_create_index;

	/* each thread has it's own data */
	struct fwm_data *data;
};

/* moving average */
struct mavg_val
{
	_Atomic __float128 val;
	_Atomic uint64_t time_prev;
	__float128 limits_max[1]; /* growing array (noverflow items) */
};

struct mavg_data
{
	tkvdb_tr *trs[MAVG_NBANKS];
	_Atomic size_t tr_idx;

	/* per-thread database of overlimited items */
	tkvdb_tr *overlimited_db;

	uint8_t *key;
	uint8_t *val; /* array of struct mavg_val */

	size_t keysize, valsize, val_itemsize;
	int need_more_mem;
};

struct mavg_limit
{
	char name[PATH_MAX];
	char file[PATH_MAX];
	tkvdb_tr *db;
	__float128 *def;
};

struct mo_mavg
{
	char notif_pfx[PATH_MAX]; /* prefix for notification files */

	char name[TOKEN_MAX_SIZE];
	uint32_t size_secs;
	struct mo_fieldset fieldset;
	int merge_secs;

	time_t last_merge, last_bankswap;

	/* limits */
	struct mavg_limit *overflow;
	size_t noverflow;
	/* global database of overlimited items */
	tkvdb_tr *overlimited_db;

	/* each thread has it's own data */
	struct mavg_data *data;
};

struct monit_object
{
	char name[PATH_MAX];
	struct filter_expr *expr;

	struct xe_debug debug;

	/* fixed windows in memory */
	size_t nfwm;
	struct mo_fwm *fwms;

	/* moving averages */
	size_t nmavg;
	struct mo_mavg *mavgs;
};


int monit_objects_init(struct xe_data *data);
int monit_objects_free(struct xe_data *data);

int monit_object_match(struct monit_object *mo, struct nf_flow_info *fi);
int monit_object_process_nf(struct monit_object *mo, size_t thread_id,
	uint64_t time_ns, struct nf_flow_info *flow);

void monit_object_field_print(struct field *fld, FILE *f, uint8_t *data,
	int print_spaces);

/* fixed windows in memory */
int fwm_config(struct aajson *a, aajson_val *value, struct monit_object *mo);
int fwm_fields_init(size_t nthreads, struct mo_fwm *window);
void *fwm_bg_thread(void *);

/* moving averages */
int mavg_config(struct aajson *a, aajson_val *value, struct monit_object *mo);
int mavg_fields_init(size_t nthreads, struct mo_mavg *window);
int mavg_limits_init(struct mo_mavg *window);
int monit_object_mavg_process_nf(struct monit_object *mo, size_t thread_id,
	uint64_t time_ns, struct nf_flow_info *flow);

void *mavg_bg_thread(void *);

#endif

