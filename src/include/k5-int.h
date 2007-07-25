/*
 * Copyright (C) 1989,1990,1991,1992,1993,1994,1995,2000,2001, 2003,2006,2007 by the Massachusetts Institute of Technology,
 * Cambridge, MA, USA.  All Rights Reserved.
 * 
 * This software is being provided to you, the LICENSEE, by the 
 * Massachusetts Institute of Technology (M.I.T.) under the following 
 * license.  By obtaining, using and/or copying this software, you agree 
 * that you have read, understood, and will comply with these terms and 
 * conditions:  
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify and distribute 
 * this software and its documentation for any purpose and without fee or 
 * royalty is hereby granted, provided that you agree to comply with the 
 * following copyright notice and statements, including the disclaimer, and 
 * that the same appear on ALL copies of the software and documentation, 
 * including modifications that you make for internal use or for 
 * distribution:
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS", AND M.I.T. MAKES NO REPRESENTATIONS 
 * OR WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not 
 * limitation, M.I.T. MAKES NO REPRESENTATIONS OR WARRANTIES OF 
 * MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF 
 * THE LICENSED SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY 
 * PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.   
 * 
 * The name of the Massachusetts Institute of Technology or M.I.T. may NOT 
 * be used in advertising or publicity pertaining to distribution of the 
 * software.  Title to copyright in this software and any associated 
 * documentation shall at all times remain with M.I.T., and USER agrees to 
 * preserve same.
 *
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.  
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * This prototype for k5-int.h (Krb5 internals include file)
 * includes the user-visible definitions from krb5.h and then
 * includes other definitions that are not user-visible but are
 * required for compiling Kerberos internal routines.
 *
 * John Gilmore, Cygnus Support, Sat Jan 21 22:45:52 PST 1995
 */

#ifndef _KRB5_INT_H
#define _KRB5_INT_H

#ifdef KRB5_GENERAL__
#error krb5.h included before k5-int.h
#endif /* KRB5_GENERAL__ */

#include "osconf.h"

/*
 * Begin "k5-config.h"
 */
#ifndef KRB5_CONFIG__
#define KRB5_CONFIG__

/* 
 * Machine-type definitions: PC Clone 386 running Microloss Windows
 */

#if defined(_MSDOS) || defined(_WIN32)
#include "win-mac.h"

/* Kerberos Windows initialization file */
#define KERBEROS_INI	"kerberos.ini"
#define INI_FILES	"Files"
#define INI_KRB_CCACHE	"krb5cc"	/* Location of the ccache */
#define INI_KRB5_CONF	"krb5.ini"	/* Location of krb5.conf file */
#define ANSI_STDIO
#endif

#ifndef KRB5_AUTOCONF__
#define KRB5_AUTOCONF__
#include "autoconf.h"
#endif

#ifndef KRB5_SYSTYPES__
#define KRB5_SYSTYPES__

#ifdef HAVE_SYS_TYPES_H		/* From autoconf.h */
#include <sys/types.h>
#else /* HAVE_SYS_TYPES_H */
typedef unsigned long 	u_long;
typedef unsigned int	u_int;
typedef unsigned short	u_short;
typedef unsigned char	u_char;
#endif /* HAVE_SYS_TYPES_H */
#endif /* KRB5_SYSTYPES__ */


#include "k5-platform.h"
/* not used in krb5.h (yet) */
typedef UINT64_TYPE krb5_ui_8;
typedef INT64_TYPE krb5_int64;


#define DEFAULT_PWD_STRING1 "Enter password"
#define DEFAULT_PWD_STRING2 "Re-enter password for verification"

#define	KRB5_KDB_MAX_LIFE	(60*60*24) /* one day */
#define	KRB5_KDB_MAX_RLIFE	(60*60*24*7) /* one week */
#define	KRB5_KDB_EXPIRATION	2145830400 /* Thu Jan  1 00:00:00 2038 UTC */

/* 
 * Windows requires a different api interface to each function. Here
 * just define it as NULL.
 */
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

/* #define KRB5_OLD_CRYPTO is done in krb5.h */

#endif /* KRB5_CONFIG__ */

/*
 * End "k5-config.h"
 */

/*
 * After loading the configuration definitions, load the Kerberos definitions.
 */
#include <errno.h>
#include "krb5.h"
#include "profile.h"

#include "port-sockets.h"
#include "socket-utils.h"

/* Get mutex support; currently used only for the replay cache.  */
#include "k5-thread.h"

/* Get error info support.  */
#include "k5-err.h"

/* krb5/krb5.h includes many other .h files in the krb5 subdirectory.
   The ones that it doesn't include, we include below.  */

/*
 * Begin "k5-errors.h"
 */
#ifndef KRB5_ERRORS__
#define KRB5_ERRORS__


/* Error codes used in KRB_ERROR protocol messages.
   Return values of library routines are based on a different error table
   (which allows non-ambiguous error codes between subsystems) */

/* KDC errors */
#define	KDC_ERR_NONE			0 /* No error */
#define	KDC_ERR_NAME_EXP		1 /* Client's entry in DB expired */
#define	KDC_ERR_SERVICE_EXP		2 /* Server's entry in DB expired */
#define	KDC_ERR_BAD_PVNO		3 /* Requested pvno not supported */
#define	KDC_ERR_C_OLD_MAST_KVNO		4 /* C's key encrypted in old master */
#define	KDC_ERR_S_OLD_MAST_KVNO		5 /* S's key encrypted in old master */
#define	KDC_ERR_C_PRINCIPAL_UNKNOWN	6 /* Client not found in Kerberos DB */
#define	KDC_ERR_S_PRINCIPAL_UNKNOWN	7 /* Server not found in Kerberos DB */
#define	KDC_ERR_PRINCIPAL_NOT_UNIQUE	8 /* Multiple entries in Kerberos DB */
#define	KDC_ERR_NULL_KEY		9 /* The C or S has a null key */
#define	KDC_ERR_CANNOT_POSTDATE		10 /* Tkt ineligible for postdating */
#define	KDC_ERR_NEVER_VALID		11 /* Requested starttime > endtime */
#define	KDC_ERR_POLICY			12 /* KDC policy rejects request */
#define	KDC_ERR_BADOPTION		13 /* KDC can't do requested opt. */
#define	KDC_ERR_ENCTYPE_NOSUPP		14 /* No support for encryption type */
#define KDC_ERR_SUMTYPE_NOSUPP		15 /* No support for checksum type */
#define KDC_ERR_PADATA_TYPE_NOSUPP	16 /* No support for padata type */
#define KDC_ERR_TRTYPE_NOSUPP		17 /* No support for transited type */
#define KDC_ERR_CLIENT_REVOKED		18 /* C's creds have been revoked */
#define KDC_ERR_SERVICE_REVOKED		19 /* S's creds have been revoked */
#define KDC_ERR_TGT_REVOKED		20 /* TGT has been revoked */
#define KDC_ERR_CLIENT_NOTYET		21 /* C not yet valid */
#define KDC_ERR_SERVICE_NOTYET		22 /* S not yet valid */
#define KDC_ERR_KEY_EXP			23 /* Password has expired */
#define KDC_ERR_PREAUTH_FAILED		24 /* Preauthentication failed */
#define KDC_ERR_PREAUTH_REQUIRED	25 /* Additional preauthentication */
					   /* required */
#define KDC_ERR_SERVER_NOMATCH		26 /* Requested server and */
					   /* ticket don't match*/
/* Application errors */
#define	KRB_AP_ERR_BAD_INTEGRITY 31	/* Decrypt integrity check failed */
#define	KRB_AP_ERR_TKT_EXPIRED	32	/* Ticket expired */
#define	KRB_AP_ERR_TKT_NYV	33	/* Ticket not yet valid */
#define	KRB_AP_ERR_REPEAT	34	/* Request is a replay */
#define	KRB_AP_ERR_NOT_US	35	/* The ticket isn't for us */
#define	KRB_AP_ERR_BADMATCH	36	/* Ticket/authenticator don't match */
#define	KRB_AP_ERR_SKEW		37	/* Clock skew too great */
#define	KRB_AP_ERR_BADADDR	38	/* Incorrect net address */
#define	KRB_AP_ERR_BADVERSION	39	/* Protocol version mismatch */
#define	KRB_AP_ERR_MSG_TYPE	40	/* Invalid message type */
#define	KRB_AP_ERR_MODIFIED	41	/* Message stream modified */
#define	KRB_AP_ERR_BADORDER	42	/* Message out of order */
#define	KRB_AP_ERR_BADKEYVER	44	/* Key version is not available */
#define	KRB_AP_ERR_NOKEY	45	/* Service key not available */
#define	KRB_AP_ERR_MUT_FAIL	46	/* Mutual authentication failed */
#define KRB_AP_ERR_BADDIRECTION	47 	/* Incorrect message direction */
#define KRB_AP_ERR_METHOD	48 	/* Alternative authentication */
					/* method required */
#define KRB_AP_ERR_BADSEQ	49 	/* Incorrect sequence numnber */
					/* in message */
#define KRB_AP_ERR_INAPP_CKSUM	50	/* Inappropriate type of */
					/* checksum in message */
#define KRB_AP_PATH_NOT_ACCEPTED 51	/* Policy rejects transited path */
#define KRB_ERR_RESPONSE_TOO_BIG 52	/* Response too big for UDP, */
					/*   retry with TCP */

/* other errors */
#define KRB_ERR_GENERIC		60 	/* Generic error (description */
					/* in e-text) */
#define	KRB_ERR_FIELD_TOOLONG	61	/* Field is too long for impl. */

#endif /* KRB5_ERRORS__ */
/*
 * End "k5-errors.h"
 */

/*
 * This structure is returned in the e-data field of the KRB-ERROR
 * message when the error calling for an alternative form of
 * authentication is returned, KRB_AP_METHOD.
 */
typedef struct _krb5_alt_method {
	krb5_magic	magic;
	krb5_int32	method;
	unsigned int	length;
	krb5_octet	*data;
} krb5_alt_method;

/*
 * A null-terminated array of this structure is returned by the KDC as
 * the data part of the ETYPE_INFO preauth type.  It informs the
 * client which encryption types are supported.
 * The  same data structure is used by both etype-info and etype-info2
 * but s2kparams must be null when encoding etype-info.
 */
typedef struct _krb5_etype_info_entry {
	krb5_magic	magic;
	krb5_enctype	etype;
	unsigned int	length;
	krb5_octet	*salt;
    krb5_data s2kparams;
} krb5_etype_info_entry;

/* 
 *  This is essentially -1 without sign extension which can screw up
 *  comparisons on 64 bit machines. If the length is this value, then
 *  the salt data is not present. This is to distinguish between not
 *  being set and being of 0 length. 
 */
#define KRB5_ETYPE_NO_SALT VALID_UINT_BITS

typedef krb5_etype_info_entry ** krb5_etype_info;

/*
 * a sam_challenge is returned for alternate preauth 
 */
/*
          SAMFlags ::= BIT STRING {
              use-sad-as-key[0],
              send-encrypted-sad[1],
              must-pk-encrypt-sad[2]
          }
 */
/*
          PA-SAM-CHALLENGE ::= SEQUENCE {
              sam-type[0]                 INTEGER,
              sam-flags[1]                SAMFlags,
              sam-type-name[2]            GeneralString OPTIONAL,
              sam-track-id[3]             GeneralString OPTIONAL,
              sam-challenge-label[4]      GeneralString OPTIONAL,
              sam-challenge[5]            GeneralString OPTIONAL,
              sam-response-prompt[6]      GeneralString OPTIONAL,
              sam-pk-for-sad[7]           EncryptionKey OPTIONAL,
              sam-nonce[8]                INTEGER OPTIONAL,
              sam-cksum[9]                Checksum OPTIONAL
          }
*/
/* sam_type values -- informational only */
#define PA_SAM_TYPE_ENIGMA     1   /*  Enigma Logic */
#define PA_SAM_TYPE_DIGI_PATH  2   /*  Digital Pathways */
#define PA_SAM_TYPE_SKEY_K0    3   /*  S/key where  KDC has key 0 */
#define PA_SAM_TYPE_SKEY       4   /*  Traditional S/Key */
#define PA_SAM_TYPE_SECURID    5   /*  Security Dynamics */
#define PA_SAM_TYPE_CRYPTOCARD 6   /*  CRYPTOCard */
#if 1 /* XXX need to figure out who has which numbers assigned */
#define PA_SAM_TYPE_ACTIVCARD_DEC  6   /*  ActivCard decimal mode */
#define PA_SAM_TYPE_ACTIVCARD_HEX  7   /*  ActivCard hex mode */
#define PA_SAM_TYPE_DIGI_PATH_HEX  8   /*  Digital Pathways hex mode */
#endif
#define PA_SAM_TYPE_EXP_BASE    128 /* experimental */
#define PA_SAM_TYPE_GRAIL		(PA_SAM_TYPE_EXP_BASE+0) /* testing */
#define PA_SAM_TYPE_SECURID_PREDICT	(PA_SAM_TYPE_EXP_BASE+1) /* special */

typedef struct _krb5_predicted_sam_response {
	krb5_magic	magic;
	krb5_keyblock	sam_key;
	krb5_flags	sam_flags; /* Makes key munging easier */
	krb5_timestamp  stime;	/* time on server, for replay detection */
	krb5_int32      susec;
	krb5_principal  client;
	krb5_data       msd;	/* mechanism specific data */
} krb5_predicted_sam_response;

typedef struct _krb5_sam_challenge {
	krb5_magic	magic;
	krb5_int32	sam_type; /* information */
	krb5_flags	sam_flags; /* KRB5_SAM_* values */
	krb5_data	sam_type_name;
	krb5_data	sam_track_id;
	krb5_data	sam_challenge_label;
	krb5_data	sam_challenge;
	krb5_data	sam_response_prompt;
	krb5_data	sam_pk_for_sad;
	krb5_int32	sam_nonce;
	krb5_checksum	sam_cksum;
} krb5_sam_challenge;

typedef struct _krb5_sam_key {	/* reserved for future use */
	krb5_magic	magic;
	krb5_keyblock	sam_key;
} krb5_sam_key;

typedef struct _krb5_enc_sam_response_enc {
	krb5_magic	magic;
	krb5_int32	sam_nonce;
	krb5_timestamp	sam_timestamp;
	krb5_int32	sam_usec;
	krb5_data	sam_sad;
} krb5_enc_sam_response_enc;

typedef struct _krb5_sam_response {
	krb5_magic	magic;
	krb5_int32	sam_type; /* informational */
	krb5_flags	sam_flags; /* KRB5_SAM_* values */
	krb5_data	sam_track_id; /* copied */
	krb5_enc_data	sam_enc_key; /* krb5_sam_key - future use */
	krb5_enc_data	sam_enc_nonce_or_ts; /* krb5_enc_sam_response_enc */
	krb5_int32	sam_nonce;
	krb5_timestamp	sam_patimestamp;
} krb5_sam_response;

typedef struct _krb5_sam_challenge_2 {
	krb5_data	sam_challenge_2_body;
	krb5_checksum	**sam_cksum;		/* Array of checksums */
} krb5_sam_challenge_2;

typedef struct _krb5_sam_challenge_2_body {
	krb5_magic	magic;
	krb5_int32	sam_type; /* information */
	krb5_flags	sam_flags; /* KRB5_SAM_* values */
	krb5_data	sam_type_name;
	krb5_data	sam_track_id;
	krb5_data	sam_challenge_label;
	krb5_data	sam_challenge;
	krb5_data	sam_response_prompt;
	krb5_data	sam_pk_for_sad;
	krb5_int32	sam_nonce;
	krb5_enctype	sam_etype;
} krb5_sam_challenge_2_body;

typedef struct _krb5_sam_response_2 {
	krb5_magic	magic;
	krb5_int32	sam_type; /* informational */
	krb5_flags	sam_flags; /* KRB5_SAM_* values */
	krb5_data	sam_track_id; /* copied */
	krb5_enc_data	sam_enc_nonce_or_sad; /* krb5_enc_sam_response_enc */
	krb5_int32	sam_nonce;
} krb5_sam_response_2;

typedef struct _krb5_enc_sam_response_enc_2 {
	krb5_magic	magic;
	krb5_int32	sam_nonce;
	krb5_data	sam_sad;
} krb5_enc_sam_response_enc_2;

/*
 * Begin "ext-proto.h"
 */
#ifndef KRB5_EXT_PROTO__
#define KRB5_EXT_PROTO__

#include <stdlib.h>
#include <string.h>

#ifndef HAVE_STRDUP
extern char *strdup (const char *);
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#endif /* KRB5_EXT_PROTO__ */
/*
 * End "ext-proto.h"
 */

/*
 * Begin "sysincl.h"
 */
#ifndef KRB5_SYSINCL__
#define KRB5_SYSINCL__

#ifndef KRB5_SYSTYPES__
#define KRB5_SYSTYPES__
/* needed for much of the rest -- but already handled in krb5.h? */
/* #include <sys/types.h> */
#endif /* KRB5_SYSTYPES__ */

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>			/* struct stat, stat() */
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>			/* MAXPATHLEN */
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>			/* prototypes for file-related
					   syscalls; flags for open &
					   friends */
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#endif /* KRB5_SYSINCL__ */
/*
 * End "sysincl.h"
 */

/*
 * Begin "los-proto.h"
 */
#ifndef KRB5_LIBOS_PROTO__
#define KRB5_LIBOS_PROTO__

#include <stdio.h>

struct addrlist;
struct sendto_callback_info;

/* libos.spec */
krb5_error_code krb5_lock_file (krb5_context, int, int);
krb5_error_code krb5_unlock_file (krb5_context, int);
krb5_error_code krb5_sendto_kdc (krb5_context, const krb5_data *,
				 const krb5_data *, krb5_data *, int *, int);

krb5_error_code krb5int_sendto (krb5_context context, const krb5_data *message,
                const struct addrlist *addrs, struct sendto_callback_info* callback_info,
				krb5_data *reply, struct sockaddr *localaddr, socklen_t *localaddrlen,
                struct sockaddr *remoteaddr, socklen_t *remoteaddrlen, int *addr_used);

krb5_error_code krb5_get_krbhst (krb5_context, const krb5_data *, char *** );
krb5_error_code krb5_free_krbhst (krb5_context, char * const * );
krb5_error_code krb5_create_secure_file (krb5_context, const char * pathname);
krb5_error_code krb5_sync_disk_file (krb5_context, FILE *fp);

krb5_error_code krb5int_get_fq_local_hostname (char *, size_t);

krb5_error_code krb5int_init_context_kdc(krb5_context *);

krb5_error_code krb5_os_init_context (krb5_context, krb5_boolean);

void krb5_os_free_context (krb5_context);

/* This function is needed by KfM's KerberosPreferences API 
 * because it needs to be able to specify "secure" */
krb5_error_code os_get_default_config_files 
    (profile_filespec_t **pfiles, krb5_boolean secure);

krb5_error_code krb5_os_hostaddr
	(krb5_context, const char *, krb5_address ***);

/* N.B.: You need to include fake-addrinfo.h *before* k5-int.h if you're
   going to use this structure.  */
struct addrlist {
    struct {
#ifdef FAI_DEFINED
	struct addrinfo *ai;
#else
	struct undefined_addrinfo *ai;
#endif
	void (*freefn)(void *);
	void *data;
    } *addrs;
    int naddrs;
    int space;
};
#define ADDRLIST_INIT { 0, 0, 0 }
extern void krb5int_free_addrlist (struct addrlist *);
extern int krb5int_grow_addrlist (struct addrlist *, int);
extern int krb5int_add_host_to_list (struct addrlist *, const char *,
				     int, int, int, int);

#include <krb5/locate_plugin.h>
krb5_error_code
krb5int_locate_server (krb5_context, const krb5_data *realm,
		       struct addrlist *, enum locate_service_type svc,
		       int sockettype, int family);

#endif /* KRB5_LIBOS_PROTO__ */

/* new encryption provider api */

struct krb5_enc_provider {
    /* keybytes is the input size to make_key; 
       keylength is the output size */
    size_t block_size, keybytes, keylength;

    /* cipher-state == 0 fresh state thrown away at end */
    krb5_error_code (*encrypt) (const krb5_keyblock *key,
				const krb5_data *cipher_state,
				const krb5_data *input,
				krb5_data *output);

    krb5_error_code (*decrypt) (const krb5_keyblock *key,
				const krb5_data *ivec,
				const krb5_data *input,
				krb5_data *output);

    krb5_error_code (*make_key) (const krb5_data *randombits,
				 krb5_keyblock *key);

  krb5_error_code (*init_state) (const krb5_keyblock *key,
				 krb5_keyusage keyusage, krb5_data *out_state);
  krb5_error_code (*free_state) (krb5_data *state);
  
};

struct krb5_hash_provider {
    size_t hashsize, blocksize;

    /* this takes multiple inputs to avoid lots of copying. */
    krb5_error_code (*hash) (unsigned int icount, const krb5_data *input,
			     krb5_data *output);
};

struct krb5_keyhash_provider {
    size_t hashsize;

    krb5_error_code (*hash) (const krb5_keyblock *key,
			     krb5_keyusage keyusage,
			     const krb5_data *ivec,
			     const krb5_data *input,
			     krb5_data *output);

    krb5_error_code (*verify) (const krb5_keyblock *key,
			       krb5_keyusage keyusage,
			       const krb5_data *ivec,
			       const krb5_data *input,
			       const krb5_data *hash,
			       krb5_boolean *valid);
};

typedef void (*krb5_encrypt_length_func) (const struct krb5_enc_provider *enc,
  const struct krb5_hash_provider *hash,
  size_t inputlen, size_t *length);

typedef krb5_error_code (*krb5_crypt_func) (const struct krb5_enc_provider *enc,
  const struct krb5_hash_provider *hash,
  const krb5_keyblock *key, krb5_keyusage keyusage,
  const krb5_data *ivec, 
  const krb5_data *input, krb5_data *output);

typedef krb5_error_code (*krb5_str2key_func) (const struct krb5_enc_provider *enc, const krb5_data *string,
  const krb5_data *salt, const krb5_data *parm, krb5_keyblock *key);

typedef krb5_error_code (*krb5_prf_func)(
					 const struct krb5_enc_provider *enc,
					 const struct krb5_hash_provider *hash,
					 const krb5_keyblock *key,
					 const krb5_data *in, krb5_data *out);

struct krb5_keytypes {
    krb5_enctype etype;
    char *in_string;
    char *out_string;
    const struct krb5_enc_provider *enc;
    const struct krb5_hash_provider *hash;
  size_t prf_length;
    krb5_encrypt_length_func encrypt_len;
    krb5_crypt_func encrypt;
    krb5_crypt_func decrypt;
    krb5_str2key_func str2key;
  krb5_prf_func prf;
    krb5_cksumtype required_ctype;
};

struct krb5_cksumtypes {
    krb5_cksumtype ctype;
    unsigned int flags;
    char *in_string;
    char *out_string;
    /* if the hash is keyed, this is the etype it is keyed with.
       Actually, it can be keyed by any etype which has the same
       enc_provider as the specified etype.  DERIVE checksums can
       be keyed with any valid etype. */
    krb5_enctype keyed_etype;
    /* I can't statically initialize a union, so I'm just going to use
       two pointers here.  The keyhash is used if non-NULL.  If NULL,
       then HMAC/hash with derived keys is used if the relevant flag
       is set.  Otherwise, a non-keyed hash is computed.  This is all
       kind of messy, but so is the krb5 api. */
    const struct krb5_keyhash_provider *keyhash;
    const struct krb5_hash_provider *hash;
    /* This just gets uglier and uglier.  In the key derivation case,
       we produce an hmac.  To make the hmac code work, we can't hack
       the output size indicated by the hash provider, but we may want
       a truncated hmac.  If we want truncation, this is the number of
       bytes we truncate to; it should be 0 otherwise.  */
    unsigned int trunc_size;
};

#define KRB5_CKSUMFLAG_DERIVE		0x0001
#define KRB5_CKSUMFLAG_NOT_COLL_PROOF	0x0002

/*
 * in here to deal with stuff from lib/crypto
 */

void krb5_nfold
(unsigned int inbits, const unsigned char *in,
		unsigned int outbits, unsigned char *out);

krb5_error_code krb5_hmac
(const struct krb5_hash_provider *hash,
		const krb5_keyblock *key, unsigned int icount,
		const krb5_data *input, krb5_data *output);

krb5_error_code krb5int_pbkdf2_hmac_sha1 (const krb5_data *, unsigned long,
					  const krb5_data *,
					  const krb5_data *);

/* Make this a function eventually?  */
#ifdef _WIN32
# define krb5int_zap_data(ptr, len) SecureZeroMemory(ptr, len)
#elif defined(__GNUC__)
static inline void krb5int_zap_data(void *ptr, size_t len)
{
    memset(ptr, 0, len);
    asm volatile ("" : : "g" (ptr), "g" (len));
}
#else
# define krb5int_zap_data(ptr, len) memset((volatile void *)ptr, 0, len)
#endif /* WIN32 */
#define zap(p,l) krb5int_zap_data(p,l)

/* A definition of init_state for DES based encryption systems.
 * sets up an 8-byte IV of all zeros
 */

krb5_error_code krb5int_des_init_state
(const krb5_keyblock *key, krb5_keyusage keyusage, krb5_data *new_state);

/* 
 * normally to free a cipher_state you can just memset the length to zero and
 * free it.
 */
krb5_error_code krb5int_default_free_state
(krb5_data *state);


/*
 * Combine two keys (normally used by the hardware preauth mechanism)
 */
krb5_error_code krb5int_c_combine_keys
(krb5_context context, krb5_keyblock *key1, krb5_keyblock *key2,
		krb5_keyblock *outkey);

void  krb5int_c_free_keyblock
(krb5_context, krb5_keyblock *key);
void  krb5int_c_free_keyblock_contents
	(krb5_context, krb5_keyblock *);
krb5_error_code   krb5int_c_init_keyblock
		(krb5_context, krb5_enctype enctype,
		size_t length, krb5_keyblock **out); 

/*
 * Internal - for cleanup.
 */
extern void krb5int_prng_cleanup (void);


/* 
 * These declarations are here, so both krb5 and k5crypto
 * can get to them.
 * krb5 needs to get to them so it can  make them available to libgssapi.
 */
extern const struct krb5_enc_provider krb5int_enc_arcfour;
extern const struct krb5_hash_provider krb5int_hash_md5;


#ifdef KRB5_OLD_CRYPTO
/* old provider api */

krb5_error_code krb5_crypto_os_localaddr
	(krb5_address ***);

krb5_error_code krb5_crypto_us_timeofday
	(krb5_int32 *,
		krb5_int32 *);

time_t krb5int_gmt_mktime (struct tm *);

#endif /* KRB5_OLD_CRYPTO */

/* this helper fct is in libkrb5, but it makes sense declared here. */

krb5_error_code krb5_encrypt_helper
(krb5_context context, const krb5_keyblock *key,
		krb5_keyusage keyusage, const krb5_data *plain,
		krb5_enc_data *cipher);

/*
 * End "los-proto.h"
 */

/*
 * Begin "libos.h"
 */
#ifndef KRB5_LIBOS__
#define KRB5_LIBOS__

typedef struct _krb5_os_context {
	krb5_magic		magic;
	krb5_int32		time_offset;
	krb5_int32		usec_offset;
	krb5_int32		os_flags;
	char *			default_ccname;
} *krb5_os_context;

/*
 * Flags for the os_flags field
 *
 * KRB5_OS_TOFFSET_VALID means that the time offset fields are valid.
 * The intention is that this facility to correct the system clocks so
 * that they reflect the "real" time, for systems where for some
 * reason we can't set the system clock.  Instead we calculate the
 * offset between the system time and real time, and store the offset
 * in the os context so that we can correct the system clock as necessary.
 *
 * KRB5_OS_TOFFSET_TIME means that the time offset fields should be
 * returned as the time by the krb5 time routines.  This should only
 * be used for testing purposes (obviously!)
 */
#define KRB5_OS_TOFFSET_VALID	1
#define KRB5_OS_TOFFSET_TIME	2

/* lock mode flags */
#define	KRB5_LOCKMODE_SHARED	0x0001
#define	KRB5_LOCKMODE_EXCLUSIVE	0x0002
#define	KRB5_LOCKMODE_DONTBLOCK	0x0004
#define	KRB5_LOCKMODE_UNLOCK	0x0008

#endif /* KRB5_LIBOS__ */
/*
 * End "libos.h"
 */

/*
 * Define our view of the size of a DES key.
 */
#define	KRB5_MIT_DES_KEYSIZE		8
/*
 * Check if des_int.h has been included before us.  If so, then check to see
 * that our view of the DES key size is the same as des_int.h's.
 */
#ifdef	MIT_DES_KEYSIZE
#if	MIT_DES_KEYSIZE != KRB5_MIT_DES_KEYSIZE
error(MIT_DES_KEYSIZE does not equal KRB5_MIT_DES_KEYSIZE)
#endif	/* MIT_DES_KEYSIZE != KRB5_MIT_DES_KEYSIZE */
#endif	/* MIT_DES_KEYSIZE */

/*
 * Begin "preauth.h"
 *
 * (Originally written by Glen Machin at Sandia Labs.)
 */
/*
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 * 
 */
#ifndef KRB5_PREAUTH__
#define KRB5_PREAUTH__

#include <krb5/preauth_plugin.h>

#define CLIENT_ROCK_MAGIC 0x4352434b
/* This structure is passed into the client preauth functions and passed
 * back to the "get_data_proc" function so that it can locate the
 * requested information.  It is opaque to the plugin code and can be
 * expanded in the future as new types of requests are defined which
 * may require other things to be passed through. */
typedef struct _krb5_preauth_client_rock {
	krb5_magic	magic;
	krb5_kdc_rep	*as_reply;
} krb5_preauth_client_rock;

/* This structure lets us keep track of all of the modules which are loaded,
 * turning the list of modules and their lists of implemented preauth types
 * into a single list which we can walk easily. */
typedef struct _krb5_preauth_context {
    int n_modules;
    struct _krb5_preauth_context_module {
	/* Which of the possibly more than one preauth types which the
	 * module supports we're using at this point in the list. */
	krb5_preauthtype pa_type;
	/* Encryption types which the client claims to support -- we
	 * copy them directly into the krb5_kdc_req structure during
	 * krb5_preauth_prepare_request(). */
	krb5_enctype *enctypes;
	/* The plugin's per-plugin context and a function to clear it. */
	void *plugin_context;
	void (*client_fini)(krb5_context context, void *plugin_context);
	/* The module's table, and some of its members, copied here for
	 * convenience when we populated the list. */
	struct krb5plugin_preauth_client_ftable_v0 *ftable;
	const char *name;
	int flags, use_count;
	krb5_error_code (*client_process)(krb5_context context,
					  void *plugin_context,
					  void *request_context,
					  krb5_get_init_creds_opt *opt,
					  preauth_get_client_data_proc get_data_proc,
					  krb5_preauth_client_rock *rock,
					  krb5_kdc_req *request,
					  krb5_data *encoded_request_body,
					  krb5_data *encoded_previous_request,
					  krb5_pa_data *pa_data,
					  krb5_prompter_fct prompter,
					  void *prompter_data,
					  preauth_get_as_key_proc gak_fct,
					  void *gak_data,
					  krb5_data *salt,
					  krb5_data *s2kparams,
					  krb5_keyblock *as_key,
					  krb5_pa_data **out_pa_data);
	krb5_error_code (*client_tryagain)(krb5_context context,
					   void *plugin_context,
					   void *request_context,
					   krb5_get_init_creds_opt *opt,
					   preauth_get_client_data_proc get_data_proc,
					   krb5_preauth_client_rock *rock,
					   krb5_kdc_req *request,
					   krb5_data *encoded_request_body,
					   krb5_data *encoded_previous_request,
					   krb5_pa_data *old_pa_data,
					   krb5_error *err_reply,
					   krb5_prompter_fct prompter,
					   void *prompter_data,
					   preauth_get_as_key_proc gak_fct,
					   void *gak_data,
					   krb5_data *salt,
					   krb5_data *s2kparams,
					   krb5_keyblock *as_key,
					   krb5_pa_data **new_pa_data);
	supply_gic_opts_proc client_supply_gic_opts;
	void (*client_req_init)(krb5_context context, void *plugin_context,
			       void **request_context);
	void (*client_req_fini)(krb5_context context, void *plugin_context,
			       void *request_context);
	/* The per-request context which the client_req_init() function
	 * might allocate, which we'll need to clean up later by
	 * calling the client_req_fini() function. */
	void *request_context;
	/* A pointer to the request_context pointer.  All modules within
	 * a plugin will point at the request_context of the first
	 * module within the plugin. */
	void **request_context_pp;
    } *modules;
} krb5_preauth_context;

typedef struct _krb5_pa_enc_ts {
    krb5_timestamp	patimestamp;
    krb5_int32		pausec;
} krb5_pa_enc_ts;

typedef krb5_error_code (*krb5_preauth_obtain_proc)
    (krb5_context,
		    krb5_pa_data *,
		    krb5_etype_info,
		    krb5_keyblock *, 
		    krb5_error_code ( * )(krb5_context,
					  const krb5_enctype,
					  krb5_data *,
					  krb5_const_pointer,
					  krb5_keyblock **),
		    krb5_const_pointer,
		    krb5_creds *,
		    krb5_kdc_req *,
		    krb5_pa_data **);

typedef krb5_error_code (*krb5_preauth_process_proc)
    (krb5_context,
		    krb5_pa_data *,
		    krb5_kdc_req *,
		    krb5_kdc_rep *,
		    krb5_error_code ( * )(krb5_context,
					  const krb5_enctype,
					  krb5_data *,
					  krb5_const_pointer,
					  krb5_keyblock **),
		    krb5_const_pointer,
		    krb5_error_code ( * )(krb5_context,
					  const krb5_keyblock *,
					  krb5_const_pointer,
					  krb5_kdc_rep * ),
		    krb5_keyblock **,
		    krb5_creds *, 
		    krb5_int32 *,
		    krb5_int32 *);

typedef struct _krb5_preauth_ops {
    krb5_magic magic;
    int     type;
    int	flags;
    krb5_preauth_obtain_proc	obtain;
    krb5_preauth_process_proc	process;
} krb5_preauth_ops;

krb5_error_code krb5_obtain_padata
    	(krb5_context,
		krb5_pa_data **,
		krb5_error_code ( * )(krb5_context,
						      const krb5_enctype,
						      krb5_data *,
						      krb5_const_pointer,
						      krb5_keyblock **),
		krb5_const_pointer, 
		krb5_creds *,
		krb5_kdc_req *);

krb5_error_code krb5_process_padata
	(krb5_context,
		krb5_kdc_req *,
		krb5_kdc_rep *,
		krb5_error_code ( * )(krb5_context,
						      const krb5_enctype,
						      krb5_data *,
						      krb5_const_pointer,
						      krb5_keyblock **),
		krb5_const_pointer,
		krb5_error_code ( * )(krb5_context,
						      const krb5_keyblock *,
						      krb5_const_pointer,
						      krb5_kdc_rep * ),
		krb5_keyblock **, 	
		krb5_creds *, 
		krb5_int32 *);		

void krb5_free_etype_info
    (krb5_context, krb5_etype_info);

/*
 * Preauthentication property flags
 */
#define KRB5_PREAUTH_FLAGS_ENCRYPT	0x00000001
#define KRB5_PREAUTH_FLAGS_HARDWARE	0x00000002

#endif /* KRB5_PREAUTH__ */
/*
 * End "preauth.h"
 */

/*
 * Extending the krb5_get_init_creds_opt structure.  The original
 * krb5_get_init_creds_opt structure is defined publicly.  The
 * new extended version is private.  The original interface
 * assumed a pre-allocated structure which was passed to
 * krb5_get_init_creds_init().  The new interface assumes that
 * the caller will call krb5_get_init_creds_alloc() and
 * krb5_get_init_creds_free().
 *
 * Callers MUST NOT call krb5_get_init_creds_init() after allocating an
 * opts structure using krb5_get_init_creds_alloc().  To do so will
 * introduce memory leaks.  Unfortunately, there is no way to enforce
 * this behavior.
 *
 * Two private flags are added for backward compatibility.
 * KRB5_GET_INIT_CREDS_OPT_EXTENDED says that the structure was allocated
 * with the new krb5_get_init_creds_opt_alloc() function.
 * KRB5_GET_INIT_CREDS_OPT_SHADOWED is set to indicate that the extended
 * structure is a shadow copy of an original krb5_get_init_creds_opt
 * structure.  
 * If KRB5_GET_INIT_CREDS_OPT_SHADOWED is set after a call to
 * krb5int_gic_opt_to_opte(), the resulting extended structure should be
 * freed (using krb5_get_init_creds_free).  Otherwise, the original
 * structure was already extended and there is no need to free it.
 */

#define KRB5_GET_INIT_CREDS_OPT_EXTENDED 0x80000000
#define KRB5_GET_INIT_CREDS_OPT_SHADOWED 0x40000000

#define krb5_gic_opt_is_extended(s) \
    ((s) && ((s)->flags & KRB5_GET_INIT_CREDS_OPT_EXTENDED) ? 1 : 0)
#define krb5_gic_opt_is_shadowed(s) \
    ((s) && ((s)->flags & KRB5_GET_INIT_CREDS_OPT_SHADOWED) ? 1 : 0)


typedef struct _krb5_gic_opt_private {
    int num_preauth_data;
    krb5_gic_opt_pa_data *preauth_data;
} krb5_gic_opt_private;

typedef struct _krb5_gic_opt_ext {
    krb5_flags flags;
    krb5_deltat tkt_life;
    krb5_deltat renew_life;
    int forwardable;
    int proxiable;
    krb5_enctype *etype_list;
    int etype_list_length;
    krb5_address **address_list;
    krb5_preauthtype *preauth_list;
    int preauth_list_length;
    krb5_data *salt;
    /*
     * Do not change anything above this point in this structure.
     * It is identical to the public krb5_get_init_creds_opt structure.
     * New members must be added below.
     */
    krb5_gic_opt_private *opt_private;
} krb5_gic_opt_ext;

krb5_error_code
krb5int_gic_opt_to_opte(krb5_context context,
                        krb5_get_init_creds_opt *opt,
                        krb5_gic_opt_ext **opte,
                        unsigned int force,
                        const char *where);

krb5_error_code
krb5int_copy_data_contents (krb5_context, const krb5_data *, krb5_data *);

krb5_error_code
krb5int_copy_creds_contents (krb5_context, const krb5_creds *, krb5_creds *);

typedef krb5_error_code (*krb5_gic_get_as_key_fct)
    (krb5_context,
		     krb5_principal,
		     krb5_enctype,
		     krb5_prompter_fct,
		     void *prompter_data,
		     krb5_data *salt,
     krb5_data *s2kparams,
		     krb5_keyblock *as_key,
		     void *gak_data);

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds
(krb5_context context,
		krb5_creds *creds,
		krb5_principal client,
		krb5_prompter_fct prompter,
		void *prompter_data,
		krb5_deltat start_time,
		char *in_tkt_service,
		krb5_gic_opt_ext *gic_options,
		krb5_gic_get_as_key_fct gak,
		void *gak_data,
		int *master,
		krb5_kdc_rep **as_reply);

krb5_error_code krb5int_populate_gic_opt (
    krb5_context, krb5_gic_opt_ext **,
    krb5_flags options, krb5_address * const *addrs, krb5_enctype *ktypes,
    krb5_preauthtype *pre_auth_types, krb5_creds *creds);


krb5_error_code KRB5_CALLCONV krb5_do_preauth
	(krb5_context context,
	 krb5_kdc_req *request,
	 krb5_data *encoded_request_body,
	 krb5_data *encoded_previous_request,
	 krb5_pa_data **in_padata, krb5_pa_data ***out_padata,
	 krb5_data *salt, krb5_data *s2kparams,
	 krb5_enctype *etype, krb5_keyblock *as_key,
	 krb5_prompter_fct prompter, void *prompter_data,
	 krb5_gic_get_as_key_fct gak_fct, void *gak_data,
	 krb5_preauth_client_rock *get_data_rock,
	 krb5_gic_opt_ext *opte);
krb5_error_code KRB5_CALLCONV krb5_do_preauth_tryagain
	(krb5_context context,
	 krb5_kdc_req *request,
	 krb5_data *encoded_request_body,
	 krb5_data *encoded_previous_request,
	 krb5_pa_data **in_padata, krb5_pa_data ***out_padata,
	 krb5_error *err_reply,
	 krb5_data *salt, krb5_data *s2kparams,
	 krb5_enctype *etype, krb5_keyblock *as_key,
	 krb5_prompter_fct prompter, void *prompter_data,
	 krb5_gic_get_as_key_fct gak_fct, void *gak_data,
	 krb5_preauth_client_rock *get_data_rock,
	 krb5_gic_opt_ext *opte);
void KRB5_CALLCONV krb5_init_preauth_context
	(krb5_context);
void KRB5_CALLCONV krb5_free_preauth_context
	(krb5_context);
void KRB5_CALLCONV krb5_clear_preauth_context_use_counts
	(krb5_context);
void KRB5_CALLCONV krb5_preauth_prepare_request
	(krb5_context, krb5_gic_opt_ext *, krb5_kdc_req *);
void KRB5_CALLCONV krb5_preauth_request_context_init
	(krb5_context);
void KRB5_CALLCONV krb5_preauth_request_context_fini
	(krb5_context);

void KRB5_CALLCONV krb5_free_sam_challenge
	(krb5_context, krb5_sam_challenge * );
void KRB5_CALLCONV krb5_free_sam_challenge_2
	(krb5_context, krb5_sam_challenge_2 * );
void KRB5_CALLCONV krb5_free_sam_challenge_2_body
	(krb5_context, krb5_sam_challenge_2_body *);
void KRB5_CALLCONV krb5_free_sam_response
	(krb5_context, krb5_sam_response * );
void KRB5_CALLCONV krb5_free_sam_response_2
	(krb5_context, krb5_sam_response_2 * );
void KRB5_CALLCONV krb5_free_predicted_sam_response
	(krb5_context, krb5_predicted_sam_response * );
void KRB5_CALLCONV krb5_free_enc_sam_response_enc
	(krb5_context, krb5_enc_sam_response_enc * );
void KRB5_CALLCONV krb5_free_enc_sam_response_enc_2
	(krb5_context, krb5_enc_sam_response_enc_2 * );
void KRB5_CALLCONV krb5_free_sam_challenge_contents
	(krb5_context, krb5_sam_challenge * );
void KRB5_CALLCONV krb5_free_sam_challenge_2_contents
	(krb5_context, krb5_sam_challenge_2 * );
void KRB5_CALLCONV krb5_free_sam_challenge_2_body_contents
	(krb5_context, krb5_sam_challenge_2_body * );
void KRB5_CALLCONV krb5_free_sam_response_contents
	(krb5_context, krb5_sam_response * );
void KRB5_CALLCONV krb5_free_sam_response_2_contents
	(krb5_context, krb5_sam_response_2 *);
void KRB5_CALLCONV krb5_free_predicted_sam_response_contents
	(krb5_context, krb5_predicted_sam_response * );
void KRB5_CALLCONV krb5_free_enc_sam_response_enc_contents
	(krb5_context, krb5_enc_sam_response_enc * );
void KRB5_CALLCONV krb5_free_enc_sam_response_enc_2_contents
	(krb5_context, krb5_enc_sam_response_enc_2 * );
 
void KRB5_CALLCONV krb5_free_pa_enc_ts
	(krb5_context, krb5_pa_enc_ts *);

/* #include "krb5/wordsize.h" -- comes in through base-defs.h. */
#include "com_err.h"
#include "k5-plugin.h"

struct _krb5_context {
	krb5_magic	magic;
	krb5_enctype	*in_tkt_ktypes;
	unsigned int	in_tkt_ktype_count;
	krb5_enctype	*tgs_ktypes;
	unsigned int	tgs_ktype_count;
	struct _krb5_os_context	os_context;
	char		*default_realm;
	profile_t	profile;
	void		*db_context;
	int		ser_ctx_count;
	void		*ser_ctx;
	/* allowable clock skew */
	krb5_deltat 	clockskew;
	krb5_cksumtype	kdc_req_sumtype;
	krb5_cksumtype	default_ap_req_sumtype;
	krb5_cksumtype	default_safe_sumtype;
	krb5_flags 	kdc_default_options;
	krb5_flags	library_options;
	krb5_boolean	profile_secure;
	int		fcc_default_format;
	krb5_prompt_type *prompt_types;
	/* Message size above which we'll try TCP first in send-to-kdc
	   type code.  Aside from the 2**16 size limit, we put no
	   absolute limit on the UDP packet size.  */
	int		udp_pref_limit;

	/* Use the config-file ktypes instead of app-specified?  */
	krb5_boolean	use_conf_ktypes;

#ifdef KRB5_DNS_LOOKUP
        krb5_boolean    profile_in_memory;
#endif /* KRB5_DNS_LOOKUP */

    /* locate_kdc module stuff */
    struct plugin_dir_handle libkrb5_plugins;
    struct krb5plugin_service_locate_ftable *vtbl;
    void (**locate_fptrs)(void);

    /* preauth module stuff */
    struct plugin_dir_handle preauth_plugins;
    krb5_preauth_context *preauth_context;

    /* error detail info */
    struct errinfo err;
};

/* could be used in a table to find an etype and initialize a block */


#define KRB5_LIBOPT_SYNC_KDCTIME	0x0001

/* internal message representations */

typedef struct _krb5_safe {
    krb5_magic magic;
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time, optional */
    krb5_int32 usec;			/* microsecond portion of time,
					   optional */
    krb5_ui_4 seq_number;		/* sequence #, optional */
    krb5_address *s_address;	/* sender address */
    krb5_address *r_address;	/* recipient address, optional */
    krb5_checksum *checksum;	/* data integrity checksum */
} krb5_safe;

typedef struct _krb5_priv {
    krb5_magic magic;
    krb5_enc_data enc_part;		/* encrypted part */
} krb5_priv;

typedef struct _krb5_priv_enc_part {
    krb5_magic magic;
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time, optional */
    krb5_int32 usec;			/* microsecond portion of time, opt. */
    krb5_ui_4 seq_number;		/* sequence #, optional */
    krb5_address *s_address;	/* sender address */
    krb5_address *r_address;	/* recipient address, optional */
} krb5_priv_enc_part;

void KRB5_CALLCONV krb5_free_safe
	(krb5_context, krb5_safe * );
void KRB5_CALLCONV krb5_free_priv
	(krb5_context, krb5_priv * );
void KRB5_CALLCONV krb5_free_priv_enc_part
	(krb5_context, krb5_priv_enc_part * );

/*
 * Begin "asn1.h"
 */
#ifndef KRB5_ASN1__
#define KRB5_ASN1__

/* ASN.1 encoding knowledge; KEEP IN SYNC WITH ASN.1 defs! */
/* here we use some knowledge of ASN.1 encodings */
/* 
  Ticket is APPLICATION 1.
  Authenticator is APPLICATION 2.
  AS_REQ is APPLICATION 10.
  AS_REP is APPLICATION 11.
  TGS_REQ is APPLICATION 12.
  TGS_REP is APPLICATION 13.
  AP_REQ is APPLICATION 14.
  AP_REP is APPLICATION 15.
  KRB_SAFE is APPLICATION 20.
  KRB_PRIV is APPLICATION 21.
  KRB_CRED is APPLICATION 22.
  EncASRepPart is APPLICATION 25.
  EncTGSRepPart is APPLICATION 26.
  EncAPRepPart is APPLICATION 27.
  EncKrbPrivPart is APPLICATION 28.
  EncKrbCredPart is APPLICATION 29.
  KRB_ERROR is APPLICATION 30.
 */
/* allow either constructed or primitive encoding, so check for bit 6
   set or reset */
#define krb5_is_krb_ticket(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x61 ||\
				    (dat)->data[0] == 0x41))
#define krb5_is_krb_authenticator(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x62 ||\
				    (dat)->data[0] == 0x42))
#define krb5_is_as_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6a ||\
				    (dat)->data[0] == 0x4a))
#define krb5_is_as_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6b ||\
				    (dat)->data[0] == 0x4b))
#define krb5_is_tgs_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6c ||\
				    (dat)->data[0] == 0x4c))
#define krb5_is_tgs_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6d ||\
				    (dat)->data[0] == 0x4d))
#define krb5_is_ap_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6e ||\
				    (dat)->data[0] == 0x4e))
#define krb5_is_ap_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6f ||\
				    (dat)->data[0] == 0x4f))
#define krb5_is_krb_safe(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x74 ||\
				    (dat)->data[0] == 0x54))
#define krb5_is_krb_priv(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x75 ||\
				    (dat)->data[0] == 0x55))
#define krb5_is_krb_cred(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x76 ||\
				    (dat)->data[0] == 0x56))
#define krb5_is_krb_enc_as_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x79 ||\
				    (dat)->data[0] == 0x59))
#define krb5_is_krb_enc_tgs_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7a ||\
				    (dat)->data[0] == 0x5a))
#define krb5_is_krb_enc_ap_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7b ||\
				    (dat)->data[0] == 0x5b))
#define krb5_is_krb_enc_krb_priv_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7c ||\
				    (dat)->data[0] == 0x5c))
#define krb5_is_krb_enc_krb_cred_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7d ||\
				    (dat)->data[0] == 0x5d))
#define krb5_is_krb_error(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7e ||\
				    (dat)->data[0] == 0x5e))

/*************************************************************************
 * Prototypes for krb5_encode.c
 *************************************************************************/

/*
   krb5_error_code encode_krb5_structure(const krb5_structure *rep,
					 krb5_data **code);
   modifies  *code
   effects   Returns the ASN.1 encoding of *rep in **code.
             Returns ASN1_MISSING_FIELD if a required field is emtpy in *rep.
             Returns ENOMEM if memory runs out.
*/

krb5_error_code encode_krb5_authenticator
	(const krb5_authenticator *rep, krb5_data **code);

krb5_error_code encode_krb5_ticket
	(const krb5_ticket *rep, krb5_data **code);

krb5_error_code encode_krb5_encryption_key
	(const krb5_keyblock *rep, krb5_data **code);

krb5_error_code encode_krb5_enc_tkt_part
	(const krb5_enc_tkt_part *rep, krb5_data **code);

krb5_error_code encode_krb5_enc_kdc_rep_part
	(const krb5_enc_kdc_rep_part *rep, krb5_data **code);

/* yes, the translation is identical to that used for KDC__REP */ 
krb5_error_code encode_krb5_as_rep
	(const krb5_kdc_rep *rep, krb5_data **code);

/* yes, the translation is identical to that used for KDC__REP */ 
krb5_error_code encode_krb5_tgs_rep
	(const krb5_kdc_rep *rep, krb5_data **code);

krb5_error_code encode_krb5_ap_req
	(const krb5_ap_req *rep, krb5_data **code);

krb5_error_code encode_krb5_ap_rep
	(const krb5_ap_rep *rep, krb5_data **code);

krb5_error_code encode_krb5_ap_rep_enc_part
	(const krb5_ap_rep_enc_part *rep, krb5_data **code);

krb5_error_code encode_krb5_as_req
	(const krb5_kdc_req *rep, krb5_data **code);

krb5_error_code encode_krb5_tgs_req
	(const krb5_kdc_req *rep, krb5_data **code);

krb5_error_code encode_krb5_kdc_req_body
	(const krb5_kdc_req *rep, krb5_data **code);

krb5_error_code encode_krb5_safe
	(const krb5_safe *rep, krb5_data **code);

krb5_error_code encode_krb5_safe_with_body
	(const krb5_safe *rep, const krb5_data *body, krb5_data **code);

krb5_error_code encode_krb5_priv
	(const krb5_priv *rep, krb5_data **code);

krb5_error_code encode_krb5_enc_priv_part
	(const krb5_priv_enc_part *rep, krb5_data **code);

krb5_error_code encode_krb5_cred
	(const krb5_cred *rep, krb5_data **code);

krb5_error_code encode_krb5_enc_cred_part
	(const krb5_cred_enc_part *rep, krb5_data **code);

krb5_error_code encode_krb5_error
	(const krb5_error *rep, krb5_data **code);

krb5_error_code encode_krb5_authdata
	(const krb5_authdata **rep, krb5_data **code);

krb5_error_code encode_krb5_pwd_sequence
	(const passwd_phrase_element *rep, krb5_data **code);

krb5_error_code encode_krb5_pwd_data
	(const krb5_pwd_data *rep, krb5_data **code);

krb5_error_code encode_krb5_padata_sequence
	(const krb5_pa_data ** rep, krb5_data **code);

krb5_error_code encode_krb5_alt_method
	(const krb5_alt_method *, krb5_data **code);

krb5_error_code encode_krb5_etype_info
	(const krb5_etype_info_entry **, krb5_data **code);
krb5_error_code encode_krb5_etype_info2
	(const krb5_etype_info_entry **, krb5_data **code);

krb5_error_code encode_krb5_enc_data
    	(const krb5_enc_data *, krb5_data **);

krb5_error_code encode_krb5_pa_enc_ts
    	(const krb5_pa_enc_ts *, krb5_data **);

krb5_error_code encode_krb5_sam_challenge
	(const krb5_sam_challenge * , krb5_data **);

krb5_error_code encode_krb5_sam_key
	(const krb5_sam_key * , krb5_data **);

krb5_error_code encode_krb5_enc_sam_response_enc
	(const krb5_enc_sam_response_enc * , krb5_data **);

krb5_error_code encode_krb5_sam_response
	(const krb5_sam_response * , krb5_data **);

krb5_error_code encode_krb5_sam_challenge_2
	(const krb5_sam_challenge_2 * , krb5_data **);

krb5_error_code encode_krb5_sam_challenge_2_body
	(const krb5_sam_challenge_2_body * , krb5_data **);

krb5_error_code encode_krb5_enc_sam_response_enc_2
	(const krb5_enc_sam_response_enc_2 * , krb5_data **);

krb5_error_code encode_krb5_sam_response_2
	(const krb5_sam_response_2 * , krb5_data **);

krb5_error_code encode_krb5_predicted_sam_response
	(const krb5_predicted_sam_response * , krb5_data **);

krb5_error_code encode_krb5_setpw_req
(const krb5_principal target, char *password, krb5_data **code);

/*************************************************************************
 * End of prototypes for krb5_encode.c
 *************************************************************************/

krb5_error_code decode_krb5_sam_challenge
       (const krb5_data *, krb5_sam_challenge **);

krb5_error_code decode_krb5_enc_sam_key
       (const krb5_data *, krb5_sam_key **);

krb5_error_code decode_krb5_enc_sam_response_enc
       (const krb5_data *, krb5_enc_sam_response_enc **);

krb5_error_code decode_krb5_sam_response
       (const krb5_data *, krb5_sam_response **);

krb5_error_code decode_krb5_predicted_sam_response
       (const krb5_data *, krb5_predicted_sam_response **);

krb5_error_code decode_krb5_sam_challenge_2
	(const krb5_data *, krb5_sam_challenge_2 **);

krb5_error_code decode_krb5_sam_challenge_2_body
	(const krb5_data *, krb5_sam_challenge_2_body **);

krb5_error_code decode_krb5_enc_sam_response_enc_2
	(const krb5_data *, krb5_enc_sam_response_enc_2 **);

krb5_error_code decode_krb5_sam_response_2
	(const krb5_data *, krb5_sam_response_2 **);


/*************************************************************************
 * Prototypes for krb5_decode.c
 *************************************************************************/

krb5_error_code krb5_validate_times
       (krb5_context, 
		       krb5_ticket_times *);

/*
   krb5_error_code decode_krb5_structure(const krb5_data *code,
                                         krb5_structure **rep);
                                         
   requires  Expects **rep to not have been allocated;
              a new *rep is allocated regardless of the old value.
   effects   Decodes *code into **rep.
	     Returns ENOMEM if memory is exhausted.
             Returns asn1 and krb5 errors.
*/

krb5_error_code decode_krb5_authenticator
	(const krb5_data *code, krb5_authenticator **rep);

krb5_error_code decode_krb5_ticket
	(const krb5_data *code, krb5_ticket **rep);

krb5_error_code decode_krb5_encryption_key
	(const krb5_data *output, krb5_keyblock **rep);

krb5_error_code decode_krb5_enc_tkt_part
	(const krb5_data *output, krb5_enc_tkt_part **rep);

krb5_error_code decode_krb5_enc_kdc_rep_part
	(const krb5_data *output, krb5_enc_kdc_rep_part **rep);

krb5_error_code decode_krb5_as_rep
	(const krb5_data *output, krb5_kdc_rep **rep);

krb5_error_code decode_krb5_tgs_rep
	(const krb5_data *output, krb5_kdc_rep **rep);

krb5_error_code decode_krb5_ap_req
	(const krb5_data *output, krb5_ap_req **rep);

krb5_error_code decode_krb5_ap_rep
	(const krb5_data *output, krb5_ap_rep **rep);

krb5_error_code decode_krb5_ap_rep_enc_part
	(const krb5_data *output, krb5_ap_rep_enc_part **rep);

krb5_error_code decode_krb5_as_req
	(const krb5_data *output, krb5_kdc_req **rep);

krb5_error_code decode_krb5_tgs_req
	(const krb5_data *output, krb5_kdc_req **rep);

krb5_error_code decode_krb5_kdc_req_body
	(const krb5_data *output, krb5_kdc_req **rep);

krb5_error_code decode_krb5_safe
	(const krb5_data *output, krb5_safe **rep);

krb5_error_code decode_krb5_safe_with_body
	(const krb5_data *output, krb5_safe **rep, krb5_data *body);

krb5_error_code decode_krb5_priv
	(const krb5_data *output, krb5_priv **rep);

krb5_error_code decode_krb5_enc_priv_part
	(const krb5_data *output, krb5_priv_enc_part **rep);

krb5_error_code decode_krb5_cred
	(const krb5_data *output, krb5_cred **rep);

krb5_error_code decode_krb5_enc_cred_part
	(const krb5_data *output, krb5_cred_enc_part **rep);

krb5_error_code decode_krb5_error
	(const krb5_data *output, krb5_error **rep);

krb5_error_code decode_krb5_authdata
	(const krb5_data *output, krb5_authdata ***rep);

krb5_error_code decode_krb5_pwd_sequence
	(const krb5_data *output, passwd_phrase_element **rep);

krb5_error_code decode_krb5_pwd_data
	(const krb5_data *output, krb5_pwd_data **rep);

krb5_error_code decode_krb5_padata_sequence
	(const krb5_data *output, krb5_pa_data ***rep);

krb5_error_code decode_krb5_alt_method
	(const krb5_data *output, krb5_alt_method **rep);

krb5_error_code decode_krb5_etype_info
	(const krb5_data *output, krb5_etype_info_entry ***rep);

krb5_error_code decode_krb5_etype_info2
	(const krb5_data *output, krb5_etype_info_entry ***rep);

krb5_error_code decode_krb5_enc_data
	(const krb5_data *output, krb5_enc_data **rep);

krb5_error_code decode_krb5_pa_enc_ts
	(const krb5_data *output, krb5_pa_enc_ts **rep);

krb5_error_code decode_krb5_sam_key
	(const krb5_data *, krb5_sam_key **);

struct _krb5_key_data;		/* kdb.h */
krb5_error_code
krb5int_ldap_encode_sequence_of_keys (struct _krb5_key_data *key_data,
				      krb5_int16 n_key_data,
				      krb5_int32 mkvno,
				      krb5_data **code);

krb5_error_code
krb5int_ldap_decode_sequence_of_keys (krb5_data *in,
				      struct _krb5_key_data **out,
				      krb5_int16 *n_key_data,
				      int *mkvno);

/*************************************************************************
 * End of prototypes for krb5_decode.c
 *************************************************************************/

#endif /* KRB5_ASN1__ */
/*
 * End "asn1.h"
 */


/*
 * Internal krb5 library routines
 */
krb5_error_code krb5_encrypt_tkt_part
	(krb5_context,
		const krb5_keyblock *,
		krb5_ticket * );


krb5_error_code krb5_encode_kdc_rep
	(krb5_context,
		krb5_msgtype,
		const krb5_enc_kdc_rep_part *,
		int using_subkey,
		const krb5_keyblock *,
		krb5_kdc_rep *,
		krb5_data ** );

krb5_boolean krb5int_auth_con_chkseqnum
	(krb5_context ctx, krb5_auth_context ac, krb5_ui_4 in_seq);
/*
 * [De]Serialization Handle and operations.
 */
struct __krb5_serializer {
    krb5_magic		odtype;
    krb5_error_code	(*sizer) (krb5_context,
						  krb5_pointer,
						  size_t *);
    krb5_error_code	(*externalizer) (krb5_context,
							 krb5_pointer,
							 krb5_octet **,
							 size_t *);
    krb5_error_code	(*internalizer) (krb5_context,
							 krb5_pointer *,
							 krb5_octet **,
							 size_t *);
};
typedef const struct __krb5_serializer * krb5_ser_handle;
typedef struct __krb5_serializer krb5_ser_entry;

krb5_ser_handle krb5_find_serializer
	(krb5_context,
		krb5_magic);
krb5_error_code krb5_register_serializer
	(krb5_context,
			const krb5_ser_entry *);

/* Determine the external size of a particular opaque structure */
krb5_error_code KRB5_CALLCONV krb5_size_opaque
	(krb5_context,
		krb5_magic,
		krb5_pointer,
		size_t *);

/* Serialize the structure into a buffer */
krb5_error_code KRB5_CALLCONV krb5_externalize_opaque
	(krb5_context,
		krb5_magic,
		krb5_pointer,
		krb5_octet **,
		size_t *);

/* Deserialize the structure from a buffer */
krb5_error_code KRB5_CALLCONV krb5_internalize_opaque
	(krb5_context,
		krb5_magic,
		krb5_pointer *,
		krb5_octet **,
		size_t *);

/* Serialize data into a buffer */
krb5_error_code krb5_externalize_data
	(krb5_context,
		krb5_pointer,
		krb5_octet **,
		size_t *);
/*
 * Initialization routines.
 */

/* Initialize serialization for krb5_[os_]context */
krb5_error_code KRB5_CALLCONV krb5_ser_context_init
	(krb5_context);

/* Initialize serialization for krb5_auth_context */
krb5_error_code KRB5_CALLCONV krb5_ser_auth_context_init
	(krb5_context);

/* Initialize serialization for krb5_keytab */
krb5_error_code KRB5_CALLCONV krb5_ser_keytab_init
	(krb5_context);

/* Initialize serialization for krb5_ccache */
krb5_error_code KRB5_CALLCONV krb5_ser_ccache_init
	(krb5_context);

/* Initialize serialization for krb5_rcache */
krb5_error_code KRB5_CALLCONV krb5_ser_rcache_init
	(krb5_context);

/* [De]serialize 4-byte integer */
krb5_error_code KRB5_CALLCONV krb5_ser_pack_int32
	(krb5_int32,
		krb5_octet **,
		size_t *);
krb5_error_code KRB5_CALLCONV krb5_ser_unpack_int32
	(krb5_int32 *,
		krb5_octet **,
		size_t *);
/* [De]serialize 8-byte integer */
krb5_error_code KRB5_CALLCONV krb5_ser_pack_int64
	(krb5_int64, krb5_octet **, size_t *);
krb5_error_code KRB5_CALLCONV krb5_ser_unpack_int64
	(krb5_int64 *, krb5_octet **, size_t *);
/* [De]serialize byte string */
krb5_error_code KRB5_CALLCONV krb5_ser_pack_bytes
	(krb5_octet *,
		size_t,
		krb5_octet **,
		size_t *);
krb5_error_code KRB5_CALLCONV krb5_ser_unpack_bytes
	(krb5_octet *,
		size_t,
		krb5_octet **,
		size_t *);

krb5_error_code KRB5_CALLCONV krb5int_cc_default
	(krb5_context, krb5_ccache *);

krb5_error_code KRB5_CALLCONV krb5_cc_retrieve_cred_default
	(krb5_context, krb5_ccache, krb5_flags,
			krb5_creds *, krb5_creds *);

krb5_boolean KRB5_CALLCONV
krb5_creds_compare (krb5_context in_context,
                    krb5_creds *in_creds,
                    krb5_creds *in_compare_creds);

void krb5int_set_prompt_types
	(krb5_context, krb5_prompt_type *);

krb5_error_code
krb5int_generate_and_save_subkey (krb5_context, krb5_auth_context,
				  krb5_keyblock * /* Old keyblock, not new!  */);

/* set and change password helpers */

krb5_error_code krb5int_mk_chpw_req
	(krb5_context context, krb5_auth_context auth_context, 
 			krb5_data *ap_req, char *passwd, krb5_data *packet);
krb5_error_code krb5int_rd_chpw_rep
	(krb5_context context, krb5_auth_context auth_context,
		       krb5_data *packet, int *result_code,
		       krb5_data *result_data);
krb5_error_code KRB5_CALLCONV krb5_chpw_result_code_string
	(krb5_context context, int result_code,
			char **result_codestr);
krb5_error_code  krb5int_mk_setpw_req
	(krb5_context context, krb5_auth_context auth_context,
 			krb5_data *ap_req, krb5_principal targetprinc, char *passwd, krb5_data *packet);
krb5_error_code krb5int_rd_setpw_rep
	(krb5_context context, krb5_auth_context auth_context,
		       krb5_data *packet, int *result_code,
		       krb5_data *result_data);
krb5_error_code krb5int_setpw_result_code_string
	(krb5_context context, int result_code,
			const char **result_codestr);

struct srv_dns_entry {
    struct srv_dns_entry *next;
    int priority;
    int weight;
    unsigned short port;
    char *host;
};
#ifdef KRB5_DNS_LOOKUP
krb5_error_code
krb5int_make_srv_query_realm(const krb5_data *realm,
			     const char *service,
			     const char *protocol,
			     struct srv_dns_entry **answers);
void krb5int_free_srv_dns_data(struct srv_dns_entry *);
#endif

/*
 * Convenience function for structure magic number
 */
#define KRB5_VERIFY_MAGIC(structure,magic_number) \
    if ((structure)->magic != (magic_number)) return (magic_number);

/* to keep lint happy */
#define krb5_xfree(val) free((char *)(val))

/* To keep happy libraries which are (for now) accessing internal stuff */

/* Make sure to increment by one when changing the struct */
#define KRB5INT_ACCESS_STRUCT_VERSION 10

#ifndef ANAME_SZ
struct ktext;			/* from krb.h, for krb524 support */
#endif
typedef struct _krb5int_access {
    /* crypto stuff */
    const struct krb5_hash_provider *md5_hash_provider;
    const struct krb5_enc_provider *arcfour_enc_provider;
    krb5_error_code (* krb5_hmac) (const struct krb5_hash_provider *hash,
				   const krb5_keyblock *key,
				   unsigned int icount, const krb5_data *input,
				   krb5_data *output);
    /* service location and communication */
    krb5_error_code (*sendto_udp) (krb5_context, const krb5_data *msg,
				   const struct addrlist *, struct sendto_callback_info*, krb5_data *reply,
				   struct sockaddr *, socklen_t *,struct sockaddr *,
				   socklen_t *, int *);
    krb5_error_code (*add_host_to_list)(struct addrlist *lp,
					const char *hostname,
					int port, int secport,
					int socktype, int family);
    void (*free_addrlist) (struct addrlist *);

    krb5_error_code (*make_srv_query_realm)(const krb5_data *realm,
					    const char *service,
					    const char *protocol,
					    struct srv_dns_entry **answers);
    void (*free_srv_dns_data)(struct srv_dns_entry *);
    int (*use_dns_kdc)(krb5_context);

    /* krb4 compatibility stuff -- may be null if not enabled */
    krb5_int32 (*krb_life_to_time)(krb5_int32, int);
    int (*krb_time_to_life)(krb5_int32, krb5_int32);
    int (*krb524_encode_v4tkt)(struct ktext *, char *, unsigned int *);
    krb5_error_code (*krb5int_c_mandatory_cksumtype)
        (krb5_context, krb5_enctype, krb5_cksumtype *);
    krb5_error_code (KRB5_CALLCONV *krb5_ser_pack_int64)
        (krb5_int64, krb5_octet **, size_t *);
    krb5_error_code (KRB5_CALLCONV *krb5_ser_unpack_int64)
        (krb5_int64 *, krb5_octet **, size_t *);

    /* Used for KDB LDAP back end.  */
    krb5_error_code
    (*asn1_ldap_encode_sequence_of_keys) (struct _krb5_key_data *key_data,
					  krb5_int16 n_key_data,
					  krb5_int32 mkvno,
					  krb5_data **code);

    krb5_error_code
    (*asn1_ldap_decode_sequence_of_keys) (krb5_data *in,
					  struct _krb5_key_data **out,
					  krb5_int16 *n_key_data,
					  int *mkvno);
} krb5int_access;

#define KRB5INT_ACCESS_VERSION \
    (((krb5_int32)((sizeof(krb5int_access) & 0xFFFF) | \
		   (KRB5INT_ACCESS_STRUCT_VERSION << 16))) & 0xFFFFFFFF)

krb5_error_code KRB5_CALLCONV krb5int_accessor
	(krb5int_access*, krb5_int32);

/* Ick -- some krb524 and krb4 support placed in the krb5 library,
   because AFS (and potentially other applications?) use the krb4
   object as an opaque token, which (in some implementations) is not
   in fact a krb4 ticket, so we don't want to drag in the krb4 support
   just to enable this.  */

#define KRB524_SERVICE "krb524"
#define KRB524_PORT 4444

/* v4lifetime.c */
extern krb5_int32 krb5int_krb_life_to_time(krb5_int32, int);
extern int krb5int_krb_time_to_life(krb5_int32, krb5_int32);

/* conv_creds.c */
int krb5int_encode_v4tkt
	(struct ktext *v4tkt, char *buf, unsigned int *encoded_len);

/* send524.c */
int krb5int_524_sendto_kdc
        (krb5_context context, const krb5_data * message, 
	 const krb5_data * realm, krb5_data * reply,
	 struct sockaddr *, socklen_t *);

/* temporary -- this should be under lib/krb5/ccache somewhere */

struct _krb5_ccache {
    krb5_magic magic;
    const struct _krb5_cc_ops *ops;
    krb5_pointer data;
};

/*
 * Per-type ccache cursor.
 */
struct krb5_cc_ptcursor {
    const struct _krb5_cc_ops *ops;
    krb5_pointer data;
};
typedef struct krb5_cc_ptcursor *krb5_cc_ptcursor;

struct _krb5_cc_ops {
    krb5_magic magic;
    char *prefix;
    const char * (KRB5_CALLCONV *get_name) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *resolve) (krb5_context, krb5_ccache *,
					    const char *);
    krb5_error_code (KRB5_CALLCONV *gen_new) (krb5_context, krb5_ccache *);
    krb5_error_code (KRB5_CALLCONV *init) (krb5_context, krb5_ccache,
					    krb5_principal);
    krb5_error_code (KRB5_CALLCONV *destroy) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *close) (krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *store) (krb5_context, krb5_ccache,
					    krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *retrieve) (krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds *,
					    krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *get_princ) (krb5_context, krb5_ccache,
					    krb5_principal *);
    krb5_error_code (KRB5_CALLCONV *get_first) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *);
    krb5_error_code (KRB5_CALLCONV *get_next) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *, krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *end_get) (krb5_context, krb5_ccache,
					    krb5_cc_cursor *);
    krb5_error_code (KRB5_CALLCONV *remove_cred) (krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds *);
    krb5_error_code (KRB5_CALLCONV *set_flags) (krb5_context, krb5_ccache,
					    krb5_flags);
    krb5_error_code (KRB5_CALLCONV *get_flags) (krb5_context, krb5_ccache,
						krb5_flags *);
    krb5_error_code (KRB5_CALLCONV *ptcursor_new)(krb5_context,
						  krb5_cc_ptcursor *);
    krb5_error_code (KRB5_CALLCONV *ptcursor_next)(krb5_context,
						   krb5_cc_ptcursor,
						   krb5_ccache *);
    krb5_error_code (KRB5_CALLCONV *ptcursor_free)(krb5_context,
						   krb5_cc_ptcursor *);
    krb5_error_code (KRB5_CALLCONV *move)(krb5_context, krb5_ccache);
    krb5_error_code (KRB5_CALLCONV *lastchange)(krb5_context,
						krb5_ccache, krb5_timestamp *);
    krb5_error_code (KRB5_CALLCONV *wasdefault)(krb5_context, krb5_ccache,
						krb5_timestamp *);
};

extern const krb5_cc_ops *krb5_cc_dfl_ops;

krb5_error_code
krb5int_cc_os_default_name(krb5_context context, char **name);

/*
 * Cursor for iterating over ccache types
 */
struct krb5_cc_typecursor;
typedef struct krb5_cc_typecursor *krb5_cc_typecursor;

krb5_error_code
krb5int_cc_typecursor_new(krb5_context context, krb5_cc_typecursor *cursor);

krb5_error_code
krb5int_cc_typecursor_next(
    krb5_context context,
    krb5_cc_typecursor cursor,
    const struct _krb5_cc_ops **ops);

krb5_error_code
krb5int_cc_typecursor_free(
    krb5_context context,
    krb5_cc_typecursor *cursor);

typedef struct _krb5_donot_replay {
    krb5_magic magic;
    krb5_ui_4 hash;
    char *server;			/* null-terminated */
    char *client;			/* null-terminated */
    krb5_int32 cusec;
    krb5_timestamp ctime;
} krb5_donot_replay;

krb5_error_code krb5_rc_default 
	(krb5_context,
		krb5_rcache *);
krb5_error_code krb5_rc_resolve_type 
	(krb5_context,
		krb5_rcache *,char *);
krb5_error_code krb5_rc_resolve_full 
	(krb5_context,
		krb5_rcache *,char *);
char * krb5_rc_get_type 
	(krb5_context,
		krb5_rcache);
char * krb5_rc_default_type 
	(krb5_context);
char * krb5_rc_default_name 
	(krb5_context);
krb5_error_code krb5_auth_to_rep 
	(krb5_context,
		krb5_tkt_authent *,
		krb5_donot_replay *);


krb5_error_code KRB5_CALLCONV krb5_rc_initialize
	(krb5_context, krb5_rcache,krb5_deltat);
krb5_error_code KRB5_CALLCONV krb5_rc_recover_or_initialize
	(krb5_context, krb5_rcache,krb5_deltat);
krb5_error_code KRB5_CALLCONV krb5_rc_recover
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_destroy
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_close
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_store
	(krb5_context, krb5_rcache,krb5_donot_replay *);
krb5_error_code KRB5_CALLCONV krb5_rc_expunge
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_get_lifespan
	(krb5_context, krb5_rcache,krb5_deltat *);
char *KRB5_CALLCONV krb5_rc_get_name
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_resolve
	(krb5_context, krb5_rcache, char *);

typedef struct _krb5_kt_ops {
    krb5_magic magic;
    char *prefix;
    /* routines always present */
    krb5_error_code (KRB5_CALLCONV *resolve) 
	(krb5_context,
		 const char *,
		 krb5_keytab *);
    krb5_error_code (KRB5_CALLCONV *get_name) 
	(krb5_context,
		 krb5_keytab,
		 char *,
		 unsigned int);
    krb5_error_code (KRB5_CALLCONV *close) 
	(krb5_context,
		 krb5_keytab);
    krb5_error_code (KRB5_CALLCONV *get) 
	(krb5_context,
		 krb5_keytab,
		 krb5_const_principal,
		 krb5_kvno,
		 krb5_enctype,
		 krb5_keytab_entry *);
    krb5_error_code (KRB5_CALLCONV *start_seq_get) 
	(krb5_context,
		 krb5_keytab,
		 krb5_kt_cursor *);	
    krb5_error_code (KRB5_CALLCONV *get_next) 
	(krb5_context,
		 krb5_keytab,
		 krb5_keytab_entry *,
		 krb5_kt_cursor *);
    krb5_error_code (KRB5_CALLCONV *end_get) 
	(krb5_context,
		 krb5_keytab,
		 krb5_kt_cursor *);
    /* routines to be included on extended version (write routines) */
    krb5_error_code (KRB5_CALLCONV *add) 
	(krb5_context,
		 krb5_keytab,
		 krb5_keytab_entry *);
    krb5_error_code (KRB5_CALLCONV *remove) 
	(krb5_context,
		 krb5_keytab,
		  krb5_keytab_entry *);

    /* Handle for serializer */
    const krb5_ser_entry *serializer;
} krb5_kt_ops;

extern const krb5_kt_ops krb5_kt_dfl_ops;

extern krb5_error_code krb5int_translate_gai_error (int);

/* Not sure it's ready for exposure just yet.  */
extern krb5_error_code
krb5int_c_mandatory_cksumtype (krb5_context, krb5_enctype, krb5_cksumtype *);

extern int krb5int_crypto_init (void);
extern int krb5int_prng_init(void);

#define krb5_copy_error_state(CTX, OCTX) \
	krb5int_set_error(&(CTX)->errinfo, (OCTX)->errinfo.code, "%s", (OCTX)->errinfo.msg)

/*
 * Referral definitions, debugging hooks, and subfunctions.
 */
#define        KRB5_REFERRAL_MAXHOPS	5
/* #define DEBUG_REFERRALS */

#ifdef DEBUG_REFERRALS
void krb5int_dbgref_dump_principal(char *, krb5_principal);
#endif

/* Common hostname-parsing code. */
krb5_error_code KRB5_CALLCONV krb5int_clean_hostname
	(krb5_context,
		const char *,
		char *,
		size_t);

/* Use the above four instead.  */
krb5_boolean KRB5_CALLCONV valid_enctype
	(krb5_enctype ktype);
krb5_boolean KRB5_CALLCONV valid_cksumtype
	(krb5_cksumtype ctype);
krb5_boolean KRB5_CALLCONV is_coll_proof_cksum
	(krb5_cksumtype ctype);
krb5_boolean KRB5_CALLCONV is_keyed_cksum
	(krb5_cksumtype ctype);

krb5_error_code KRB5_CALLCONV krb5_random_confounder
	(size_t, krb5_pointer);

krb5_error_code krb5_encrypt_data
	(krb5_context context, krb5_keyblock *key, 
		krb5_pointer ivec, krb5_data *data, 
		krb5_enc_data *enc_data);

krb5_error_code krb5_decrypt_data
	(krb5_context context, krb5_keyblock *key, 
		krb5_pointer ivec, krb5_enc_data *data, 
		krb5_data *enc_data);

struct _krb5_kt_ops;
struct _krb5_kt {	/* should move into k5-int.h */
    krb5_magic magic;
    const struct _krb5_kt_ops *ops;
    krb5_pointer data;
};

krb5_error_code krb5_set_default_in_tkt_ktypes
	(krb5_context,
		const krb5_enctype *);
krb5_error_code krb5_get_default_in_tkt_ktypes
	(krb5_context,
		krb5_enctype **);

krb5_error_code krb5_set_default_tgs_ktypes
	(krb5_context,
		const krb5_enctype *);

krb5_error_code KRB5_CALLCONV krb5_get_tgs_ktypes
	(krb5_context,
		krb5_const_principal,
		krb5_enctype **);

void KRB5_CALLCONV krb5_free_ktypes
	(krb5_context, krb5_enctype *);

krb5_boolean krb5_is_permitted_enctype
	(krb5_context, krb5_enctype);

krb5_error_code krb5_kdc_rep_decrypt_proc
	(krb5_context,
		const krb5_keyblock *,
		krb5_const_pointer,
		krb5_kdc_rep * );
krb5_error_code KRB5_CALLCONV krb5_decrypt_tkt_part
	(krb5_context,
		const krb5_keyblock *,
		krb5_ticket * );
krb5_error_code krb5_get_cred_from_kdc
	(krb5_context,
		krb5_ccache,		/* not const, as reading may save
					   state */
		krb5_creds *,
		krb5_creds **,
		krb5_creds *** );
krb5_error_code krb5_get_cred_from_kdc_validate
	(krb5_context,
		krb5_ccache,		/* not const, as reading may save
					   state */
		krb5_creds *,
		krb5_creds **,
		krb5_creds *** );
krb5_error_code krb5_get_cred_from_kdc_renew
	(krb5_context,
		krb5_ccache,		/* not const, as reading may save
					   state */
		krb5_creds *,
		krb5_creds **,
		krb5_creds *** );

krb5_error_code krb5_get_cred_via_tkt
	(krb5_context,
		   krb5_creds *,
		   krb5_flags,
		   krb5_address * const *,
		   krb5_creds *,
		   krb5_creds **);

krb5_error_code KRB5_CALLCONV krb5_copy_addr
	(krb5_context,
		const krb5_address *,
		krb5_address **);

void krb5_init_ets
	(krb5_context);
void krb5_free_ets
	(krb5_context);
krb5_error_code krb5_generate_subkey
	(krb5_context,
		const krb5_keyblock *, krb5_keyblock **);
krb5_error_code krb5_generate_seq_number
	(krb5_context,
		const krb5_keyblock *, krb5_ui_4 *);

krb5_error_code KRB5_CALLCONV krb5_kt_register
	(krb5_context,
		const struct _krb5_kt_ops * );

/* use krb5_free_keytab_entry_contents instead */
krb5_error_code KRB5_CALLCONV krb5_kt_free_entry
	(krb5_context,
		krb5_keytab_entry * );

krb5_error_code krb5_principal2salt_norealm
	(krb5_context,
		krb5_const_principal, krb5_data *);

unsigned int KRB5_CALLCONV krb5_get_notification_message
	(void);

/* chk_trans.c */
krb5_error_code krb5_check_transited_list
	(krb5_context, const krb5_data *trans,
	 const krb5_data *realm1, const krb5_data *realm2);

/* free_rtree.c */
void krb5_free_realm_tree
	(krb5_context,
		krb5_principal *);

void KRB5_CALLCONV krb5_free_authenticator_contents
	(krb5_context, krb5_authenticator * );

void KRB5_CALLCONV krb5_free_address
	(krb5_context, krb5_address * );

void KRB5_CALLCONV krb5_free_enc_tkt_part
	(krb5_context, krb5_enc_tkt_part * );

void KRB5_CALLCONV krb5_free_tickets
	(krb5_context, krb5_ticket ** );
void KRB5_CALLCONV krb5_free_kdc_req
	(krb5_context, krb5_kdc_req * );
void KRB5_CALLCONV krb5_free_kdc_rep
	(krb5_context, krb5_kdc_rep * );
void KRB5_CALLCONV krb5_free_last_req
	(krb5_context, krb5_last_req_entry ** );
void KRB5_CALLCONV krb5_free_enc_kdc_rep_part
	(krb5_context, krb5_enc_kdc_rep_part * );
void KRB5_CALLCONV krb5_free_ap_req
	(krb5_context, krb5_ap_req * );
void KRB5_CALLCONV krb5_free_ap_rep
	(krb5_context, krb5_ap_rep * );
void KRB5_CALLCONV krb5_free_cred
	(krb5_context, krb5_cred *);
void KRB5_CALLCONV krb5_free_cred_enc_part
	(krb5_context, krb5_cred_enc_part *);
void KRB5_CALLCONV krb5_free_pa_data
	(krb5_context, krb5_pa_data **);
void KRB5_CALLCONV krb5_free_tkt_authent
	(krb5_context, krb5_tkt_authent *);
void KRB5_CALLCONV krb5_free_pwd_data
	(krb5_context, krb5_pwd_data *);
void KRB5_CALLCONV krb5_free_pwd_sequences
	(krb5_context, passwd_phrase_element **);
krb5_error_code krb5_set_config_files
	(krb5_context, const char **);

krb5_error_code KRB5_CALLCONV krb5_get_default_config_files
	(char ***filenames);

void KRB5_CALLCONV krb5_free_config_files
	(char **filenames);
krb5_error_code krb5_send_tgs
	(krb5_context,
		krb5_flags,
		const krb5_ticket_times *,
		const krb5_enctype *,
		krb5_const_principal,
		krb5_address * const *,
		krb5_authdata * const *,
		krb5_pa_data * const *,
		const krb5_data *,
		krb5_creds *,
		krb5_response * );
krb5_error_code krb5_decode_kdc_rep
	(krb5_context,
		krb5_data *,
		const krb5_keyblock *,
		krb5_kdc_rep ** );

krb5_error_code krb5_rd_req_decoded
	(krb5_context,
		krb5_auth_context *,
		const krb5_ap_req *,
		krb5_const_principal,
		krb5_keytab,
		krb5_flags *,
		krb5_ticket **);

krb5_error_code krb5_rd_req_decoded_anyflag
	(krb5_context,
		krb5_auth_context *,
		const krb5_ap_req *,
		krb5_const_principal,
		krb5_keytab,
		krb5_flags *,
		krb5_ticket **);
krb5_error_code KRB5_CALLCONV krb5_cc_register
	(krb5_context,
		const krb5_cc_ops *,
		krb5_boolean );
krb5_error_code krb5_walk_realm_tree
	(krb5_context,
		const krb5_data *,
		const krb5_data *,
		krb5_principal **,
		int);
krb5_error_code KRB5_CALLCONV krb5_auth_con_set_req_cksumtype
	(krb5_context,
		krb5_auth_context,
		krb5_cksumtype);

krb5_error_code krb5_auth_con_set_safe_cksumtype
	(krb5_context,
		krb5_auth_context,
		krb5_cksumtype);
krb5_error_code krb5_auth_con_setivector
	(krb5_context,
		krb5_auth_context,
		krb5_pointer);

krb5_error_code krb5_auth_con_getivector
	(krb5_context,
		krb5_auth_context,
		krb5_pointer *);

krb5_error_code krb5_auth_con_setpermetypes
	(krb5_context,
	    krb5_auth_context,
	    const krb5_enctype *);

krb5_error_code krb5_auth_con_getpermetypes
	(krb5_context,
	    krb5_auth_context,
	    krb5_enctype **);

krb5_error_code KRB5_CALLCONV
krb5int_server_decrypt_ticket_keyblock
  	(krb5_context context,
                const krb5_keyblock *key,
                krb5_ticket  *ticket);

krb5_error_code krb5_read_message (krb5_context, krb5_pointer, krb5_data *);
krb5_error_code krb5_write_message (krb5_context, krb5_pointer, krb5_data *);
int krb5_net_read (krb5_context, int , char *, int);
int krb5_net_write (krb5_context, int , const char *, int);

krb5_error_code KRB5_CALLCONV krb5_get_realm_domain
	(krb5_context,
		const char *,
		char ** );

krb5_error_code krb5_gen_portaddr
	(krb5_context,
		const krb5_address *,
		krb5_const_pointer,
		krb5_address **);
krb5_error_code krb5_gen_replay_name
	(krb5_context,
		const krb5_address *,
		const char *,
		char **);
krb5_error_code krb5_make_fulladdr
	(krb5_context,
		krb5_address *,
		krb5_address *,
		krb5_address *);

krb5_error_code krb5_set_debugging_time
	(krb5_context, krb5_timestamp, krb5_int32);
krb5_error_code krb5_use_natural_time
	(krb5_context);
krb5_error_code krb5_set_time_offsets
	(krb5_context, krb5_timestamp, krb5_int32);
krb5_error_code krb5int_check_clockskew(krb5_context, krb5_timestamp);
/*
 * The realm iterator functions
 */

krb5_error_code KRB5_CALLCONV krb5_realm_iterator_create
	(krb5_context context, void **iter_p);

krb5_error_code KRB5_CALLCONV krb5_realm_iterator
	(krb5_context context, void **iter_p, char **ret_realm);

void KRB5_CALLCONV krb5_realm_iterator_free
	(krb5_context context, void **iter_p);

void KRB5_CALLCONV krb5_free_realm_string
	(krb5_context context, char *str);

/* Some data comparison and conversion functions.  */
#if 0
static inline int data_cmp(krb5_data d1, krb5_data d2)
{
    if (d1.length < d2.length) return -1;
    if (d1.length > d2.length) return 1;
    return memcmp(d1.data, d2.data, d1.length);
}
static inline int data_eq (krb5_data d1, krb5_data d2)
{
    return data_cmp(d1, d2) == 0;
}
#else
static inline int data_eq (krb5_data d1, krb5_data d2)
{
    return (d1.length == d2.length
	    && !memcmp(d1.data, d2.data, d1.length));
}
#endif
static inline krb5_data string2data (char *str)
{
    krb5_data d;
    d.magic = KV5M_DATA;
    d.length = strlen(str);
    d.data = str;
    return d;
}
static inline int data_eq_string (krb5_data d, char *s)
{
    return data_eq(d, string2data(s));
}
static inline int authdata_eq (krb5_authdata a1, krb5_authdata a2)
{
    return (a1.ad_type == a2.ad_type
	    && a1.length == a2.length
	    && !memcmp(a1.contents, a2.contents, a1.length));
}
#endif /* _KRB5_INT_H */