/*
 * lib/krb5/os/def_realm.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_get_default_realm(), krb5_set_default_realm(),
 * krb5_free_default_realm() functions.
 */

#include "k5-int.h"
#include "os-proto.h"
#include <stdio.h>
#ifdef _WIN32
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>
#endif

#ifdef KRB5_DNS_LOOKUP	     
#ifdef WSHELPER
#include <wshelper.h>
#else /* WSHELPER */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#endif /* WSHELPER */

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define MAX_DNS_NAMELEN (15*(MAXHOSTNAMELEN + 1)+1)

#endif /* KRB5_DNS_LOOKUP */

/*
 * Retrieves the default realm to be used if no user-specified realm is
 *  available.  [e.g. to interpret a user-typed principal name with the
 *  realm omitted for convenience]
 * 
 *  returns system errors, NOT_ENOUGH_SPACE, KV5M_CONTEXT
*/

/*
 * Implementation:  the default realm is stored in a configuration file,
 * named by krb5_config_file;  the first token in this file is taken as
 * the default local realm name.
 */

#ifdef _WIN32
static char *win32_get_windows_domain(void);
#endif /* _WIN32 */

krb5_error_code KRB5_CALLCONV
krb5_get_default_realm(krb5_context context, char **lrealm)
{
    char *realm = 0;
    char *cp;
    krb5_error_code retval;

    if (!context || (context->magic != KV5M_CONTEXT)) 
        return KV5M_CONTEXT;

    if (context->default_realm == 0) {
        /*
         * XXX should try to figure out a reasonable default based
         * on the host's DNS domain.
         */
        if (context->profile != 0) {
            retval = profile_get_string(context->profile, "libdefaults",
                                        "default_realm", 0, 0,
                                        &realm);

            if (!retval && realm) {
                context->default_realm = malloc(strlen(realm) + 1);
                if (!context->default_realm) {
                    profile_release_string(realm);
                    return ENOMEM;
                }
                strcpy(context->default_realm, realm);
                profile_release_string(realm);
            }
        }
    }
#if !defined(KRB5_DNS_LOOKUP) && !defined(_WIN32)
    if (context->default_realm == 0)
        return KRB5_CONFIG_CANTOPEN;
#endif
#if defined(KRB5_DNS_LOOKUP)
    if (context->default_realm == 0) {
        int use_dns =  _krb5_use_dns_realm(context);
        if ( use_dns ) {
            /*
             * Since this didn't appear in our config file, try looking
             * it up via DNS.  Look for a TXT records of the form:
             *
             * _kerberos.<localhost>
             * _kerberos.<domainname>
             * _kerberos.<searchlist>
             *
             */
            char localhost[MAX_DNS_NAMELEN+1];
            char * p;

            krb5int_get_fq_local_hostname (localhost, sizeof(localhost));

            if ( localhost[0] ) {
                p = localhost;
                do {
                    retval = krb5_try_realm_txt_rr("_kerberos", p,
                                                   &context->default_realm);
                    p = strchr(p,'.');
                    if (p)
                        p++;
                } while (retval && p && p[0]);

                if (retval)
                    retval = krb5_try_realm_txt_rr("_kerberos", "",
                                                   &context->default_realm);
            } else {
                retval = krb5_try_realm_txt_rr("_kerberos", "",
                                               &context->default_realm);
            }
            if (retval) {
                return(KRB5_CONFIG_NODEFREALM);
            }

            if (context->default_realm != NULL &&
                 context->default_realm[0] == 0) {
                free (context->default_realm);
                context->default_realm = 0;
            }
        }
    }
#endif /* KRB5_DNS_LOOKUP */
#ifdef _WIN32
    if (context->default_realm == 0) {
        /*
         * If a Windows system is joined to a domain, use the domain
         * as the default realm.
         */
        context->default_realm = win32_get_windows_domain();
    }
#endif /* _WIN32 */

    if (context->default_realm == 0)
	return(KRB5_CONFIG_NODEFREALM);

    realm = context->default_realm;
    
    if (!(*lrealm = cp = malloc((unsigned int) strlen(realm) + 1)))
        return ENOMEM;
    strcpy(cp, realm);
    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_set_default_realm(krb5_context context, const char *lrealm)
{
    if (!context || (context->magic != KV5M_CONTEXT)) 
	    return KV5M_CONTEXT;

    if (context->default_realm) {
	    free(context->default_realm);
	    context->default_realm = 0;
    }

    /* Allow the user to clear the default realm setting by passing in 
       NULL */
    if (!lrealm) return 0;

    context->default_realm = malloc(strlen (lrealm) + 1);

    if (!context->default_realm)
	    return ENOMEM;

    strcpy(context->default_realm, lrealm);
    return(0);

}

void KRB5_CALLCONV
krb5_free_default_realm(krb5_context context, char *lrealm)
{
    free (lrealm);
}

#ifdef _WIN32
static BOOL
win32_GetSecurityLogonSessionData(PSECURITY_LOGON_SESSION_DATA * ppSessionData)
{
    NTSTATUS Status = 0;
    HANDLE  TokenHandle;
    TOKEN_STATISTICS Stats;
    DWORD   ReqLen;
    BOOL    Success;

    if (!ppSessionData)
        return FALSE;
    *ppSessionData = NULL;

    Success = OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &TokenHandle );
    if ( !Success ) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetSecurityLogonSessionData OpenProcessToken failed\n");
#endif /* NODEBUG */
        return FALSE;
    }
    Success = GetTokenInformation( TokenHandle, TokenStatistics, &Stats, sizeof(TOKEN_STATISTICS), &ReqLen );
    CloseHandle( TokenHandle );
    if ( !Success ) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetSecurityLogonSessionData GetTokenInformation failed\n");
#endif /* NODEBUG */
        return FALSE;
    }
    Status = LsaGetLogonSessionData( &Stats.AuthenticationId, ppSessionData );
    if ( FAILED(Status) || !ppSessionData ) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetSecurityLogonSessionData LsaGetLogonSessionData failed\n");
#endif /* NODEBUG */
        return FALSE;
    }
    return TRUE;
}

static BOOL
win32_get_STRING_from_registry(HKEY hBaseKey, char * key, char * value, char * outbuf, DWORD  outlen)
{
    HKEY hKey;
    DWORD dwCount;
    LONG rc;

    if (!outbuf || outlen == 0)
        return FALSE;

    rc = RegOpenKeyExA(hBaseKey, key, 0, KEY_QUERY_VALUE, &hKey);
    if (rc)
        return FALSE;

    dwCount = outlen;
    rc = RegQueryValueExA(hKey, value, 0, 0, (LPBYTE) outbuf, &dwCount);
    RegCloseKey(hKey);

    return rc?FALSE:TRUE;
}

static BOOL
WINAPI
win32_UnicodeStringToANSI(UNICODE_STRING uInputString, LPSTR lpszOutputString, int nOutStringLen)
{
    CPINFO CodePageInfo;

    GetCPInfo(CP_ACP, &CodePageInfo);

    if (CodePageInfo.MaxCharSize > 1)
        // Only supporting non-Unicode strings
        return FALSE;

    if (uInputString.Buffer && ((LPBYTE) uInputString.Buffer)[1] == '\0')
    {
        // Looks like unicode, better translate it
        // UNICODE_STRING specifies the length of the buffer string in Bytes not WCHARS
        WideCharToMultiByte(CP_ACP, 0, (LPCWSTR) uInputString.Buffer, uInputString.Length/2,
                            lpszOutputString, nOutStringLen-1, NULL, NULL);
        lpszOutputString[min(uInputString.Length/2,nOutStringLen-1)] = '\0';
        return TRUE;
    }

    lpszOutputString[0] = '\0';
    return FALSE;
}

static char *
win32_get_windows_domain(void)
{
    char * realm = NULL;
    CHAR  DnsDomainName[256];
    PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;
    BOOL    Success = FALSE;
    OSVERSIONINFOEX verinfo;
    int supported = 0;

    verinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO *)&verinfo);
    supported = (verinfo.dwMajorVersion > 5) ||
        (verinfo.dwMajorVersion == 5 && verinfo.dwMinorVersion >= 1);

    // If we could not get a TGT from the cache we won't know what the
    // Kerberos Domain should have been.  On Windows XP and 2003 Server
    // we can extract it from the Security Logon Session Data.  However,
    // the required fields are not supported on Windows 2000.  :(
    if ( supported && win32_GetSecurityLogonSessionData(&pSessionData) ) {
        if ( pSessionData->DnsDomainName.MaximumLength > 0 &&
             pSessionData->DnsDomainName.Length <= pSessionData->DnsDomainName.MaximumLength &&
             pSessionData->DnsDomainName.Buffer )
        {

            if (win32_UnicodeStringToANSI(pSessionData->DnsDomainName,
                                          DnsDomainName, sizeof(DnsDomainName)))
                realm = _strdup(DnsDomainName);

        }
        LsaFreeReturnBuffer(pSessionData);
    }

    if (realm == NULL) {
        if ( win32_get_STRING_from_registry(HKEY_CURRENT_USER,
                                            "Volatile Environment",
                                            "USERDNSDOMAIN",
                                            DnsDomainName,
                                            sizeof(DnsDomainName)))
        {
            realm = _strdup(DnsDomainName);
        }
    }

    return realm;
}
#endif /* _WIN32 */
