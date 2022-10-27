#ifndef monit_objects_h_included
#define monit_objects_h_included

#include "xe-debug.h"
#include "aajson/aajson.h"
#include "filter.h"

#include "tkvdb.h"

#define FWM_DEFAULT_TIMEOUT 30

#define MAVG_DEFAULT_SIZE 5

#define MAVG_DEFAULT_TR_SIZE (1024*1024*256)

#define MAVG_SCRIPT_STR_SIZE (10*1024)

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
	__float128 limits_max[1]; /* growing array (noverlimit items) */
};

struct mavg_data
{
	tkvdb_tr *tr;

	uint8_t *key;
	uint8_t *val; /* array of struct mavg_val */

	size_t keysize, valsize, val_itemsize, key_fullsize;

	/* per-thread database of overlimited items, 2 banks */
	tkvdb_tr *ovr_db[2];
};

struct mavg_limit
{
	char name[PATH_MAX];
	char file[PATH_MAX];

	char action_script[MAVG_SCRIPT_STR_SIZE];
	char back2norm_script[MAVG_SCRIPT_STR_SIZE];

	tkvdb_tr *db;

	/* default */
	__float128 *def;
};

enum MAVG_OVRLM_TYPE
{
	MAVG_OVRLM_GONE,
	MAVG_OVRLM_NEW,
	MAVG_OVRLM_UPDATE
};

struct mavg_ovrlm_data
{
	enum MAVG_OVRLM_TYPE type;
	uint64_t time_dump, time_last;
	__float128 val;
	__float128 limit;
};

struct mo_mavg
{
	char notif_pfx[PATH_MAX]; /* prefix for notification files */

	char name[TOKEN_MAX_SIZE];
	unsigned int size_secs;
	struct mo_fieldset fieldset;
	unsigned int dump_secs;

	time_t last_dump;

	/* limits */
	struct mavg_limit *overlimit;
	size_t noverlimit;

	/* global database of overlimited items */
	tkvdb_tr *glb_ovr_db;

	/* each thread has it's own data */
	size_t nthreads;
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
int monit_object_process_nf(struct xe_data *globl, struct monit_object *mo,
	size_t thread_id, uint64_t time_ns, struct nf_flow_info *flow);

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
int monit_object_mavg_process_nf(struct xe_data *globl,
	struct monit_object *mo, size_t thread_id,
	uint64_t time_ns, struct nf_flow_info *flow);

void *mavg_bg_thread(void *);
void *mavg_act_thread(void *);

#endif

