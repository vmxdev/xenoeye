#ifndef monit_objects_h_included
#define monit_objects_h_included

#include "xe-debug.h"
#include "aajson/aajson.h"
#include "filter.h"

#include "tkvdb.h"

#define FWM_DEFAULT_TIMEOUT 30

#define MAVG_DEFAULT_SIZE 5

#define MAVG_DEFAULT_BACK2NORM 30

#define MAVG_DEFAULT_DB_SIZE (1024*1024*256)

#define MAVG_SCRIPT_STR_SIZE (10*1024)

/*#define MAVG_TYPE __float128*/
#define MAVG_TYPE double

#define CLSF_DEFAULT_TIMEOUT 30
#define CLASSES_MAX 5

/* helper for classes processing */
#define FOR_LIST_OF_CLASSES \
	DO(0, class0)       \
	DO(1, class1)       \
	DO(2, class2)       \
	DO(3, class3)       \
	DO(4, class4)

struct xe_data;
struct flow_info;

struct two_banks_db
{
	tkvdb_tr *bank[2];

	/* current bank */
	atomic_size_t idx;
};

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

struct fwm_thread_data
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
	int is_extended;
	atomic_int is_active;

	char name[TOKEN_MAX_SIZE];
	struct mo_fieldset fieldset;

	time_t last_export;
	int time;

	int limit;

	int dont_create_index;

	/* window has DNS/SNI, processed in a special way */
	int has_dns_field;
	int has_sni_field;

	/* each thread has it's own data */
	struct fwm_thread_data *thread_data;
};


/* classification */
struct classification_thread_data
{
	/* using two banks */
	tkvdb_tr *trs[2];

	/* current bank index */
	atomic_size_t tr_idx;

	uint8_t *key;
	uint64_t val;

	size_t keysize;
};

struct mo_classification
{
	int id;

	time_t last_export;
	int time;
	unsigned int top_percents;

	size_t nfields;
	struct field *fields;

	struct field *val;

	/* each thread has it's own data */
	struct classification_thread_data *thread_data;

	/* classidier db */
	struct two_banks_db db;
};


/* moving average */
struct mavg_val
{
	_Atomic MAVG_TYPE val;
	_Atomic uint64_t time_prev;

	/* growing array (noverlimit + nunderlimit items) */
	_Atomic MAVG_TYPE limits[1];
};

struct mavg_thread_data
{
	/* atomic pointer to database */
	tkvdb_tr *_Atomic db;
	int db_is_full;

	uint8_t *key;
	uint8_t *val; /* array of struct mavg_val */

	size_t keysize, valsize, val_itemsize, key_fullsize;

	/* per-thread database of overlimited items, 2 banks */
	tkvdb_tr *ovr_db[2];
};

struct mavg_limit_ext_stat
{
	char mo_name[TOKEN_MAX_SIZE];
	char name[TOKEN_MAX_SIZE];
	_Atomic int *ptr;
};

struct mavg_limit
{
	char name[PATH_MAX];
	char file[PATH_MAX];

	MAVG_TYPE back2norm_time_ns;

	char action_script[MAVG_SCRIPT_STR_SIZE];
	char back2norm_script[MAVG_SCRIPT_STR_SIZE];

	/* extended statistics on overlimit */
	struct mavg_limit_ext_stat *ext_stat;
	size_t n_ext_stat;

	tkvdb_tr *db;

	/* array of defaults */
	MAVG_TYPE *def;
};


struct mavg_limits
{
	struct mavg_limit *overlimit;
	size_t noverlimit;

	struct mavg_limit *underlimit;
	size_t nunderlimit;
};

enum MAVG_LIM_STATE
{
	MAVG_LIM_NEW,
	MAVG_LIM_UPDATE,
	MAVG_LIM_ALMOST_GONE,
	MAVG_LIM_GONE
};

struct mavg_lim_data
{
	enum MAVG_LIM_STATE state;
	uint64_t time_dump, time_last, time_back2norm;
	MAVG_TYPE val;
	MAVG_TYPE limit;
	MAVG_TYPE back2norm_time_ns;
};

struct mo_mavg
{
	char notif_pfx[PATH_MAX]; /* prefix for notification files */

	char name[TOKEN_MAX_SIZE];
	unsigned int size_secs;
	struct mo_fieldset fieldset;
	unsigned int dump_secs;

	time_t last_dump_check;

	uint64_t start_ns;

	/* limits */
	struct mavg_limits lim[2];
	/* atomic index of current limits bank */
	atomic_size_t lim_curr_idx;

	/* per-mavg database of overlimited items */
	tkvdb_tr *ovrerlm_db;

	/* underlimited items */
	tkvdb_tr *underlm_db;

	size_t db_mem;

	/* each thread has it's own data */
	size_t nthreads;
	struct mavg_thread_data *thr_data;
};

struct monit_object
{
	char dir[PATH_MAX];
	char name[PATH_MAX];

	/* path to config file */
	char mo_path[PATH_MAX];
	/* modification time */
	struct timespec modif_time;
	/* when reloading config this is not 0 */
	int is_reloading;

	struct filter_expr *expr;

	struct xe_debug debug;

	/* fixed windows in memory */
	size_t nfwm;
	struct mo_fwm *fwms;

	/* moving averages */
	size_t nmavg;
	struct mo_mavg *mavgs;

	/* classifications */
	size_t nclassifications;
	struct mo_classification *classifications;

	/* sFlow packet payload parsing */
	int payload_parse_dns;
	int payload_parse_sni;

	/* hierarchical objects */
	size_t n_mo;
	struct monit_object *mos;
};


int monit_objects_init(struct xe_data *data);
int monit_objects_free(struct xe_data *data);

int monit_objects_reload(struct xe_data *data);

int monit_object_match(struct monit_object *mo, struct flow_info *fi);
int monit_object_process_nf(struct xe_data *globl, struct monit_object *mo,
	size_t thread_id, uint64_t time_ns, struct flow_info *flow);

void monit_object_field_print(struct field *fld, FILE *f, uint8_t *data,
	int print_spaces);
void monit_object_field_print_str(struct field *fld, char *str, uint8_t *data,
	int print_spaces);

void monit_object_key_add_fld(struct field *fld, uint8_t *key,
	struct flow_info *flow);

/* fixed windows in memory */
int fwm_config(struct aajson *a, aajson_val *value, struct monit_object *mo);
int fwm_fields_init(size_t nthreads, struct mo_fwm *fwm);
void *fwm_bg_thread(void *);

/* moving averages */
int mavg_config(struct aajson *a, aajson_val *value, struct monit_object *mo);
int mavg_fields_init(size_t nthreads, struct mo_mavg *mavg);
int mavg_limits_init(struct mo_mavg *mavg, int is_reloading);
int mavg_limits_file_load(struct mo_mavg *mavg, struct mavg_limit *l);
void monit_objects_mavg_link_ext_stat(struct xe_data *globl);
int monit_object_mavg_process_nf(struct xe_data *globl,
	struct monit_object *mo, size_t thread_id,
	uint64_t time_ns, struct flow_info *flow);
void mavg_limits_update(struct xe_data *globl, struct monit_object *mo);
void mavg_limits_free(struct mo_mavg *mavg);

/* classification */
void *classification_bg_thread(void *);
int classification_config(struct aajson *a, aajson_val *value,
	struct monit_object *mo);
int classification_fields_init(size_t nthreads,
	struct mo_classification *clsf);
int classification_process_nf(struct monit_object *mo, size_t thread_id,
	struct flow_info *flow);

void *mavg_dump_thread(void *);
void *mavg_act_thread(void *);
void *mavg_check_underlimit_thread(void *);

int act(struct mo_mavg *mw, tkvdb_tr *db, MAVG_TYPE wnd_size_ns, char *mo_name,
	int is_overlim);

#endif

