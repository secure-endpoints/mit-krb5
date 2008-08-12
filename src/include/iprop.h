/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _IPROP_H_RPCGEN
#define _IPROP_H_RPCGEN

#include <gssrpc/rpc.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	u_int utf8str_t_len;
	char *utf8str_t_val;
} utf8str_t;

typedef uint32_t kdb_sno_t;

struct kdbe_time_t {
	uint32_t seconds;
	uint32_t useconds;
};
typedef struct kdbe_time_t kdbe_time_t;

struct kdbe_key_t {
	int32_t k_ver;
	int32_t k_kvno;
	struct {
		u_int k_enctype_len;
		int32_t *k_enctype_val;
	} k_enctype;
	struct {
		u_int k_contents_len;
		utf8str_t *k_contents_val;
	} k_contents;
};
typedef struct kdbe_key_t kdbe_key_t;

struct kdbe_data_t {
	int32_t k_magic;
	utf8str_t k_data;
};
typedef struct kdbe_data_t kdbe_data_t;

struct kdbe_princ_t {
	utf8str_t k_realm;
	struct {
		u_int k_components_len;
		kdbe_data_t *k_components_val;
	} k_components;
	int32_t k_nametype;
};
typedef struct kdbe_princ_t kdbe_princ_t;

struct kdbe_tl_t {
	int16_t tl_type;
	struct {
		u_int tl_data_len;
		char *tl_data_val;
	} tl_data;
};
typedef struct kdbe_tl_t kdbe_tl_t;

typedef struct {
	u_int kdbe_pw_hist_t_len;
	kdbe_key_t *kdbe_pw_hist_t_val;
} kdbe_pw_hist_t;

enum kdbe_attr_type_t {
	AT_ATTRFLAGS = 0,
	AT_MAX_LIFE = 1,
	AT_MAX_RENEW_LIFE = 2,
	AT_EXP = 3,
	AT_PW_EXP = 4,
	AT_LAST_SUCCESS = 5,
	AT_LAST_FAILED = 6,
	AT_FAIL_AUTH_COUNT = 7,
	AT_PRINC = 8,
	AT_KEYDATA = 9,
	AT_TL_DATA = 10,
	AT_LEN = 11,
	AT_MOD_PRINC = 12,
	AT_MOD_TIME = 13,
	AT_MOD_WHERE = 14,
	AT_PW_LAST_CHANGE = 15,
	AT_PW_POLICY = 16,
	AT_PW_POLICY_SWITCH = 17,
	AT_PW_HIST_KVNO = 18,
	AT_PW_HIST = 19,
};
typedef enum kdbe_attr_type_t kdbe_attr_type_t;

struct kdbe_val_t {
	kdbe_attr_type_t av_type;
	union {
		uint32_t av_attrflags;
		uint32_t av_max_life;
		uint32_t av_max_renew_life;
		uint32_t av_exp;
		uint32_t av_pw_exp;
		uint32_t av_last_success;
		uint32_t av_last_failed;
		uint32_t av_fail_auth_count;
		kdbe_princ_t av_princ;
		struct {
			u_int av_keydata_len;
			kdbe_key_t *av_keydata_val;
		} av_keydata;
		struct {
			u_int av_tldata_len;
			kdbe_tl_t *av_tldata_val;
		} av_tldata;
		int16_t av_len;
		uint32_t av_pw_last_change;
		kdbe_princ_t av_mod_princ;
		uint32_t av_mod_time;
		utf8str_t av_mod_where;
		utf8str_t av_pw_policy;
		bool_t av_pw_policy_switch;
		uint32_t av_pw_hist_kvno;
		struct {
			u_int av_pw_hist_len;
			kdbe_pw_hist_t *av_pw_hist_val;
		} av_pw_hist;
		struct {
			u_int av_extension_len;
			char *av_extension_val;
		} av_extension;
	} kdbe_val_t_u;
};
typedef struct kdbe_val_t kdbe_val_t;

typedef struct {
	u_int kdbe_t_len;
	kdbe_val_t *kdbe_t_val;
} kdbe_t;

struct kdb_incr_update_t {
	utf8str_t kdb_princ_name;
	kdb_sno_t kdb_entry_sno;
	kdbe_time_t kdb_time;
	kdbe_t kdb_update;
	bool_t kdb_deleted;
	bool_t kdb_commit;
	struct {
		u_int kdb_kdcs_seen_by_len;
		utf8str_t *kdb_kdcs_seen_by_val;
	} kdb_kdcs_seen_by;
	struct {
		u_int kdb_futures_len;
		char *kdb_futures_val;
	} kdb_futures;
};
typedef struct kdb_incr_update_t kdb_incr_update_t;

typedef struct {
	u_int kdb_ulog_t_len;
	kdb_incr_update_t *kdb_ulog_t_val;
} kdb_ulog_t;

enum update_status_t {
	UPDATE_OK = 0,
	UPDATE_ERROR = 1,
	UPDATE_FULL_RESYNC_NEEDED = 2,
	UPDATE_BUSY = 3,
	UPDATE_NIL = 4,
	UPDATE_PERM_DENIED = 5,
};
typedef enum update_status_t update_status_t;

struct kdb_last_t {
	kdb_sno_t last_sno;
	kdbe_time_t last_time;
};
typedef struct kdb_last_t kdb_last_t;

struct kdb_incr_result_t {
	kdb_last_t lastentry;
	kdb_ulog_t updates;
	update_status_t ret;
};
typedef struct kdb_incr_result_t kdb_incr_result_t;

struct kdb_fullresync_result_t {
	kdb_last_t lastentry;
	update_status_t ret;
};
typedef struct kdb_fullresync_result_t kdb_fullresync_result_t;

#define KRB5_IPROP_PROG 100423
#define KRB5_IPROP_VERS 1

#if defined(__STDC__) || defined(__cplusplus)
#define IPROP_NULL 0
extern  void * iprop_null_1(void *, CLIENT *);
extern  void * iprop_null_1_svc(void *, struct svc_req *);
#define IPROP_GET_UPDATES 1
extern  kdb_incr_result_t * iprop_get_updates_1(kdb_last_t *, CLIENT *);
extern  kdb_incr_result_t * iprop_get_updates_1_svc(kdb_last_t *, struct svc_req *);
#define IPROP_FULL_RESYNC 2
extern  kdb_fullresync_result_t * iprop_full_resync_1(void *, CLIENT *);
extern  kdb_fullresync_result_t * iprop_full_resync_1_svc(void *, struct svc_req *);
extern int krb5_iprop_prog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define IPROP_NULL 0
extern  void * iprop_null_1();
extern  void * iprop_null_1_svc();
#define IPROP_GET_UPDATES 1
extern  kdb_incr_result_t * iprop_get_updates_1();
extern  kdb_incr_result_t * iprop_get_updates_1_svc();
#define IPROP_FULL_RESYNC 2
extern  kdb_fullresync_result_t * iprop_full_resync_1();
extern  kdb_fullresync_result_t * iprop_full_resync_1_svc();
extern int krb5_iprop_prog_1_freeresult ();
#endif /* K&R C */

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_utf8str_t (XDR *, utf8str_t*);
extern  bool_t xdr_kdb_sno_t (XDR *, kdb_sno_t*);
extern  bool_t xdr_kdbe_time_t (XDR *, kdbe_time_t*);
extern  bool_t xdr_kdbe_key_t (XDR *, kdbe_key_t*);
extern  bool_t xdr_kdbe_data_t (XDR *, kdbe_data_t*);
extern  bool_t xdr_kdbe_princ_t (XDR *, kdbe_princ_t*);
extern  bool_t xdr_kdbe_tl_t (XDR *, kdbe_tl_t*);
extern  bool_t xdr_kdbe_pw_hist_t (XDR *, kdbe_pw_hist_t*);
extern  bool_t xdr_kdbe_attr_type_t (XDR *, kdbe_attr_type_t*);
extern  bool_t xdr_kdbe_val_t (XDR *, kdbe_val_t*);
extern  bool_t xdr_kdbe_t (XDR *, kdbe_t*);
extern  bool_t xdr_kdb_incr_update_t (XDR *, kdb_incr_update_t*);
extern  bool_t xdr_kdb_ulog_t (XDR *, kdb_ulog_t*);
extern  bool_t xdr_update_status_t (XDR *, update_status_t*);
extern  bool_t xdr_kdb_last_t (XDR *, kdb_last_t*);
extern  bool_t xdr_kdb_incr_result_t (XDR *, kdb_incr_result_t*);
extern  bool_t xdr_kdb_fullresync_result_t (XDR *, kdb_fullresync_result_t*);

#else /* K&R C */
extern bool_t xdr_utf8str_t ();
extern bool_t xdr_kdb_sno_t ();
extern bool_t xdr_kdbe_time_t ();
extern bool_t xdr_kdbe_key_t ();
extern bool_t xdr_kdbe_data_t ();
extern bool_t xdr_kdbe_princ_t ();
extern bool_t xdr_kdbe_tl_t ();
extern bool_t xdr_kdbe_pw_hist_t ();
extern bool_t xdr_kdbe_attr_type_t ();
extern bool_t xdr_kdbe_val_t ();
extern bool_t xdr_kdbe_t ();
extern bool_t xdr_kdb_incr_update_t ();
extern bool_t xdr_kdb_ulog_t ();
extern bool_t xdr_update_status_t ();
extern bool_t xdr_kdb_last_t ();
extern bool_t xdr_kdb_incr_result_t ();
extern bool_t xdr_kdb_fullresync_result_t ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_IPROP_H_RPCGEN */