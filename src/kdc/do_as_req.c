/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * KDC Routines to deal with AS_REQ's
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_do_as_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/kdb.h>
#include <stdio.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <errno.h>
#include <com_err.h>

#include <sys/types.h>
#include <krb5/ext-proto.h>

extern krb5_cs_table_entry *csarray[];
extern int max_cryptosystem;		/* max entry in array */
extern krb5_data empty_string;		/* initialized to {0, ""} */
extern krb5_timestamp infinity;		/* greater than every valid timestamp */
extern krb5_deltat max_life_for_realm;	/* XXX should be a parameter? */
extern krb5_deltat max_renewable_life_for_realm; /* XXX should be a parameter? */

static krb5_error_code prepare_error PROTOTYPE((krb5_as_req *,
						int,
						krb5_data **));
extern int against_postdate_policy PROTOTYPE((krb5_timestamp));

/*
 * Do all the processing required for a AS_REQ
 */

/* XXX needs lots of cleanup and modularizing */

#define isset(flagfield, flag) (flagfield & flag)
#define set(flagfield, flag) (flagfield &= flag)

#ifndef	min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

krb5_error_code
process_as_req(request, response)
register krb5_as_req *request;
krb5_data **response;			/* filled in with a response packet */
{

    krb5_db_entry client, server;
    krb5_kdc_rep reply;
    krb5_enc_kdc_rep_part reply_encpart;
    krb5_ticket ticket_reply;
    krb5_enc_tkt_part enc_tkt_reply;
    krb5_error_code retval;
    int nprincs;
    krb5_boolean more;
    krb5_timestamp kdc_time;
    krb5_keyblock *session_key;

    krb5_timestamp until, rtime;

    nprincs = 1;
    if (retval = krb5_db_get_principal(request->client, &client, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&client, nprincs);
	return(prepare_error(request, KDC_ERR_PRINCIPAL_NOT_UNIQUE, response));
    } else if (nprincs != 1) {
	krb5_db_free_principal(&client, nprincs);
	return(prepare_error(request, KDC_ERR_C_PRINCIPAL_UNKNOWN, response));
    }	
	
    nprincs = 1;
    if (retval = krb5_db_get_principal(request->server, &server, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&client, 1);
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error(request, KDC_ERR_PRINCIPAL_NOT_UNIQUE, response));
    } else if (nprincs != 1) {
	krb5_db_free_principal(&client, 1);
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error(request, KDC_ERR_S_PRINCIPAL_UNKNOWN, response));
    }

    if (retval = krb5_timeofday(&kdc_time))
	return(retval);

    if (request->etype > max_cryptosystem ||
	!csarray[request->etype]->system) {
	/* unsupported etype */

#define cleanup() {krb5_db_free_principal(&client, 1); krb5_db_free_principal(&server, 1); }

	cleanup();
	return(prepare_error(request, KDC_ERR_ETYPE_NOSUPP, response));
    }

    if (retval = (*(csarray[request->etype]->system->random_key))(csarray[request->etype]->random_sequence, &session_key)) {
	/* random key failed */
	cleanup();
	return(retval);
    }

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1); krb5_db_free_principal(&server, 1); bzero((char *)session_key, krb5_keyblock_size(session_key)); }


    ticket_reply.server = request->server;
    ticket_reply.etype = request->etype;
    ticket_reply.skvno = server.kvno;

    enc_tkt_reply.flags = 0;

        /* It should be noted that local policy may affect the  */
        /* processing of any of these flags.  For example, some */
        /* realms may refuse to issue renewable tickets         */

    /* XXX procedurize */
    if (isset(request->kdc_options, KDC_OPT_FORWARDED) ||
	isset(request->kdc_options, KDC_OPT_PROXY) ||
	isset(request->kdc_options, KDC_OPT_RENEW) ||
	isset(request->kdc_options, KDC_OPT_VALIDATE) ||
	isset(request->kdc_options, KDC_OPT_REUSE_SKEY) ||
	isset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	/* none of these options is valid for an AS request */
	cleanup();
	return(prepare_error(request, KDC_ERR_BADOPTION, response));
    }

    if (isset(request->kdc_options, KDC_OPT_FORWARDABLE))
	set(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

    if (isset(request->kdc_options, KDC_OPT_PROXIABLE))
	set(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE))
	set(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    if (isset(request->kdc_options, KDC_OPT_DUPLICATE_SKEY))
	set(enc_tkt_reply.flags, TKT_FLG_DUPLICATE_SKEY);


    enc_tkt_reply.session = session_key;
    enc_tkt_reply.client = request->client;
    enc_tkt_reply.transited = empty_string; /* equivalent of "" */
    enc_tkt_reply.times.authtime = kdc_time;

    if (isset(request->kdc_options, KDC_OPT_POSTDATED)) {
	if (against_postdate_policy(request->from)) {
	    cleanup();
	    return(prepare_error(request, KDC_ERR_POLICY, response));
	}
	set(enc_tkt_reply.flags, TKT_FLG_INVALID);
	enc_tkt_reply.times.starttime = request->from;
    } else
	enc_tkt_reply.times.starttime = kdc_time;
    

    until = (request->till == 0) ? infinity : request->till;

    enc_tkt_reply.times.endtime =
	min(until,
	    min(enc_tkt_reply.times.starttime + client.max_life,
		min(enc_tkt_reply.times.starttime + server.max_life,
		    enc_tkt_reply.times.starttime + max_life_for_realm)));

    if (isset(request->kdc_options, KDC_OPT_RENEWABLE_OK) && 
	request->till && (enc_tkt_reply.times.endtime < request->till)) {

	/* we set the RENEWABLE option for later processing */

	set(request->kdc_options, KDC_OPT_RENEWABLE);
	request->rtime = request->till;
    }
    rtime = (request->rtime == 0) ? infinity : request->rtime;

    if (isset(request->kdc_options, KDC_OPT_RENEWABLE)) {
	set(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
	enc_tkt_reply.times.renew_till =
	    min(rtime, min(enc_tkt_reply.times.starttime +
			   client.max_renewable_life,
			   min(enc_tkt_reply.times.starttime +
			       server.max_renewable_life,
			       enc_tkt_reply.times.starttime +
			       max_renewable_life_for_realm)));
    } else
	enc_tkt_reply.times.renew_till = 0; /* XXX */

    enc_tkt_reply.caddrs = request->addresses;
    enc_tkt_reply.authorization_data = 0; /* XXX? */

    /* XXX need separate etypes for ticket encryption and kdc_rep encryption */

    if (retval = krb5_encrypt_tkt_part(&enc_tkt_reply,
				       server.key, &ticket_reply)) {
	cleanup();
	return retval;
    }

    krb5_db_free_principal(&server, 1);

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1);bzero((char *)session_key, krb5_keyblock_size(session_key)); bzero(ticket_reply.enc_part.data, ticket_reply.enc_part.length); free(ticket_reply.enc_part.data);}


    /* Start assembling the response */
    reply.client = request->client;
    reply.etype = request->etype;
    reply.ckvno = client.kvno;
    reply.ticket = &ticket_reply;

    reply_encpart.session = session_key;
    reply_encpart.last_req = 0;		/* XXX */
    reply_encpart.ctime = request->ctime;
    reply_encpart.key_exp = client.expiration;
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;

    /* copy the time fields EXCEPT for authtime; it's location
       is used for ktime */
    reply_encpart.times = enc_tkt_reply.times;
    reply_encpart.times.authtime = kdc_time;

    reply_encpart.caddrs = enc_tkt_reply.caddrs;

    /* finished with session key */
    bzero((char *)session_key, krb5_keyblock_size(session_key));

#undef cleanup
#define cleanup() { krb5_db_free_principal(&client, 1); bzero(ticket_reply.enc_part.data, ticket_reply.enc_part.length); free(ticket_reply.enc_part.data);}

    /* now encode/encrypt the response */

    retval = krb5_encode_kdc_rep(KRB5_AS_REP, &reply, &reply_encpart,
				 client.key, response);
    cleanup();
    return retval;
}

static krb5_error_code
prepare_error (request, error, response)
register krb5_as_req *request;
int error;
krb5_data **response;
{
    krb5_error errpkt;
    krb5_error_code retval;


    errpkt.ctime = request->ctime;
    errpkt.cmsec = 0;

    if (retval = krb5_ms_timeofday(&errpkt.stime, &errpkt.smsec))
	return(retval);
    errpkt.error = error;
    errpkt.server = request->server;
    errpkt.client = request->client;
    errpkt.text.length = strlen(error_message(error+KRB5KDC_ERR_NONE))+1;
    if (!(errpkt.text.data = malloc(errpkt.text.length)))
	return ENOMEM;
    (void) strcpy(errpkt.text.data, error_message(error+KRB5KDC_ERR_NONE));

    retval = encode_krb5_error(&errpkt, &response);
    free(errpkt.text.data);
    return retval;
}
