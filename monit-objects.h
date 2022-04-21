#ifndef monit_objects_h_included
#define monit_objects_h_included

#include "xe-debug.h"
#include "aajson/aajson.h"
#include "filter.h"

#include "tkvdb.h"

#define FWM_DEFAULT_TIMEOUT 30
#define MAVG_DEFAULT_SIZE 5
#define MAVG_MERGE_DEFAULT_TIMEOUT 10

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
	__float128 val;
	__float128 limit_min, limit_max;
	uint64_t time_prev;
};

struct mavg_data
{
	tkvdb_tr *trs[2];

	tkvdb_tr *_Atomic tr;

	uint8_t *key;
	struct mavg_val *val;

	size_t keysize, valsize;
};

struct mo_mavg
{
	char name[TOKEN_MAX_SIZE];
	uint32_t size_secs;
	struct mo_fieldset fieldset;
	int merge_secs;

	time_t last_merge;

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
	struct nf_flow_info *flow);

void monit_object_field_print(struct field *fld, FILE *f, uint8_t *data);

/* fixed windows in memory */
int fwm_config(struct aajson *a, aajson_val *value, struct monit_object *mo);
int fwm_fields_init(size_t nthreads, struct mo_fwm *window);
void *fwm_bg_thread(void *);

/* moving averages */
int mavg_config(struct aajson *a, aajson_val *value, struct monit_object *mo);
int mavg_fields_init(size_t nthreads, struct mo_mavg *window);

void *mavg_bg_thread(void *);

#endif

