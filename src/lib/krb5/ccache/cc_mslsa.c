/*
 * lib/krb5/ccache/cc_mslsa.c
 *
 * Copyright 2007,2009 Secure Endpoints Inc.
 *
 * Copyright 2003,2004 by the Massachusetts Institute of Technology.
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
 * Copyright 2000 by Carnegie Mellon University
 *
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Carnegie Mellon
 * University not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
 * ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Implementation of microsoft windows lsa credentials cache
 */

#ifdef _WIN32
#define UNICODE
#define _UNICODE
#include "k5-int.h"
#include "com_err.h"
#include "cc-int.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <conio.h>
#include <time.h>

#define SECURITY_WIN32
#include <security.h>
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#include <ntsecapi.h>
#pragma warning(push)
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(pop)


/* The following two features can only be built using the version of the
 * Platform SDK for Microsoft Windows Vista.  If AES support is defined
 * in NTSecAPI.h then we know that we have the required data structures.
 *
 * To build with the Windows XP SP2 SDK, the NTSecAPI.h from the Vista
 * SDK should be used in place of the XP SP2 SDK version.
 */
#ifndef TRUST_ATTRIBUTE_CROSS_ORGANIZATION
typedef struct _KERB_TICKET_CACHE_INFO_EX2 {
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
    UNICODE_STRING ServerName;
    UNICODE_STRING ServerRealm;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    LARGE_INTEGER RenewTime;
    LONG EncryptionType;
    ULONG TicketFlags;

    //
    // the following are new in KERB_TICKET_CACHE_INFO_EX2
    //
    ULONG SessionKeyType;
    ULONG BranchId;
} KERB_TICKET_CACHE_INFO_EX2, *PKERB_TICKET_CACHE_INFO_EX2;

static const int KerbQueryTicketCacheEx2Message = 25;
#endif

#ifndef TRUST_ATTRIBUTE_TRUST_USES_AES_KEYS
typedef struct KERB_CRYPTO_KEY32 {
    LONG KeyType;
    ULONG Length;
    ULONG Offset;
} KERB_CRYPTO_KEY32, *PKERB_CRYPTO_KEY32;

typedef struct _KERB_SUBMIT_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    ULONG Flags;
    KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
    ULONG KerbCredSize;
    ULONG KerbCredOffset;
} KERB_SUBMIT_TKT_REQUEST, *PKERB_SUBMIT_TKT_REQUEST;

static const int KerbSubmitTicketMessage = 26;
#endif
#define KERB_SUBMIT_TICKET 1
#define HAVE_CACHE_INFO_EX2 1

#define MAX_MSG_SIZE 256
#define MAX_MSPRINC_SIZE 1024
#define KRB5_OK 0

/* THREAD SAFETY
 * The functions is_windows_2000(), is_windows_xp(),
 * does_retrieve_ticket_cache_ticket() and does_query_ticket_cache_ex2()
 * contain static variables to cache the responses of the tests being
 * performed.  There is no harm in the test being performed more than
 * once since the result will always be the same.
 */

static BOOL
is_windows_2000 (void)
{
   static BOOL fChecked = FALSE;
   static BOOL fIsWin2K = FALSE;

   if (!fChecked)
   {
       OSVERSIONINFO Version;

       memset (&Version, 0x00, sizeof(Version));
       Version.dwOSVersionInfoSize = sizeof(Version);

       if (GetVersionEx (&Version))
       {
           if (Version.dwPlatformId == VER_PLATFORM_WIN32_NT &&
                Version.dwMajorVersion >= 5)
               fIsWin2K = TRUE;
#ifndef NODEBUG
           if (fIsWin2K)
               OutputDebugStringA("cc_mslsa: is Win2000\n");
#endif /* NODEBUG */
       }
       fChecked = TRUE;
   }

   return fIsWin2K;
}

static BOOL
is_windows_xp (void)
{
   static BOOL fChecked = FALSE;
   static BOOL fIsWinXP = FALSE;

   if (!fChecked)
   {
       OSVERSIONINFO Version;

       memset (&Version, 0x00, sizeof(Version));
       Version.dwOSVersionInfoSize = sizeof(Version);

       if (GetVersionEx (&Version))
       {
           if (Version.dwPlatformId == VER_PLATFORM_WIN32_NT &&
                (Version.dwMajorVersion > 5 ||
                 Version.dwMajorVersion == 5 && Version.dwMinorVersion >= 1) )
               fIsWinXP = TRUE;
#ifndef NODEBUG
           if (fIsWinXP)
               OutputDebugStringA("cc_mslsa: is WinXP\n");
#endif /* NODEBUG */
       }
       fChecked = TRUE;
   }

   return fIsWinXP;
}

static BOOL
is_windows_vista (void)
{
    static BOOL fChecked = FALSE;
    static BOOL fIsVista = FALSE;

    if (!fChecked)
    {
	OSVERSIONINFO Version;

	memset (&Version, 0x00, sizeof(Version));
	Version.dwOSVersionInfoSize = sizeof(Version);

	if (GetVersionEx (&Version))
	{
	    if (Version.dwPlatformId == VER_PLATFORM_WIN32_NT && Version.dwMajorVersion >= 6)
		fIsVista = TRUE;
#ifndef NODEBUG
            if (fIsVista)
                OutputDebugStringA("cc_mslsa: is Vista\n");
#endif /* NODEBUG */
	}
	fChecked = TRUE;
    }

    return fIsVista;
}

static BOOL
is_process_uac_limited (void)
{
    static BOOL fChecked = FALSE;
    static BOOL fIsUAC = FALSE;

    if (!fChecked)
    {
	NTSTATUS Status = 0;
	HANDLE  TokenHandle;
	DWORD   ElevationLevel;
	DWORD   ReqLen;
	BOOL    Success;

	if (is_windows_vista()) {
	    Success = OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &TokenHandle );
	    if ( Success ) {
		Success = GetTokenInformation( TokenHandle,
					       TokenOrigin+1 /* ElevationLevel */,
					       &ElevationLevel, sizeof(DWORD), &ReqLen );
		CloseHandle( TokenHandle );
		if ( Success && ElevationLevel == 3 /* Limited */ )
		    fIsUAC = TRUE;
#ifndef NODEBUG
                if (fIsUAC)
                    OutputDebugStringA("cc_mslsa: UAC restricted process\n");
#endif /* NODEBUG */
	    }
	}
	fChecked = TRUE;
    }
    return fIsUAC;

}

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
typedef BOOL (WINAPI *LPFN_DISABLEWOW64FSREDIRECTION) (PVOID *);
typedef BOOL (WINAPI *LPFN_REVERTWOW64FSREDIRECTION) (PVOID);


/*
 * Obtain the file info structure for the specified file.
 * If a full path is not specified, the search order is the
 * same as that used by LoadLibrary().
 */
static BOOL
GetFileVersion (char *filename, LARGE_INTEGER *liVer)
{
    DWORD dwHandle;
    DWORD dwSize;
    char* pInfo = NULL;
    BOOL  rc;
    UINT uLen;
    void *pbuf;
    VS_FIXEDFILEINFO vsf;

    dwSize = GetFileVersionInfoSizeA(filename,&dwHandle);
    if (dwSize == 0) {
        rc = FALSE;
        goto done;
    }
    pInfo = (char*)malloc(dwSize);
    if (!pInfo) {
        rc = FALSE;
        goto done;
    }
    rc = GetFileVersionInfoA(filename, dwHandle, dwSize, pInfo);
    if (!rc)
        goto done;
    rc = VerQueryValueA(pInfo,"\\",&pbuf, &uLen);
    if (!rc)
        goto done;
    memcpy(&vsf, pbuf, sizeof(VS_FIXEDFILEINFO));

    liVer->LowPart = vsf.dwFileVersionLS;
    liVer->HighPart = vsf.dwFileVersionMS;
    rc = TRUE;

  done:
    if (pInfo)
        free(pInfo);
    return rc;
}


/*
 * The broken versions of Wow64 are found on Windows XP64 and
 * Windows 2003 64-bit.  A hotfix was developed in Jan 2009
 * that is included in the 64-bit kerberos.dll (5.2.3790.3999).
 * Microsoft Knowledgebase 960077.
 *
 * When testing for the fix, the Wow64 file redirection must
 * be disabled.
 */
static BOOL
is_broken_wow64(void)
{
    static BOOL fChecked = FALSE;
    static BOOL fIsBrokenWow64 = FALSE;

    if (!fChecked)
    {
	BOOL isWow64 = FALSE;
	OSVERSIONINFO Version;
	HANDLE h1 = NULL;
	LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;
        LPFN_DISABLEWOW64FSREDIRECTION fnDisableWow64FsRedirection = NULL;
        LPFN_REVERTWOW64FSREDIRECTION fnRevertWow64FsRedirection = NULL;

	h1 = GetModuleHandle(L"kernel32.dll"); /* no refcount increase */
	fnIsWow64Process =
	    (LPFN_ISWOW64PROCESS)GetProcAddress(h1, "IsWow64Process");

	/* If we don't find the fnIsWow64Process function then we
	 * are not running in a broken Wow64
	 */
	if (fnIsWow64Process) {
	    memset (&Version, 0x00, sizeof(Version));
	    Version.dwOSVersionInfoSize = sizeof(Version);

	    if (fnIsWow64Process(GetCurrentProcess(), &isWow64) &&
		GetVersionEx (&Version)) {
		if (isWow64 &&
		    Version.dwPlatformId == VER_PLATFORM_WIN32_NT &&
		    Version.dwMajorVersion < 6)
                {
                    PVOID Wow64RedirectionState;
                    LARGE_INTEGER fvFile, fvHotFixMin;

                    fnDisableWow64FsRedirection =
                        (LPFN_DISABLEWOW64FSREDIRECTION)GetProcAddress(h1, "Wow64DisableWow64FsRedirection");
                    fnRevertWow64FsRedirection =
                        (LPFN_REVERTWOW64FSREDIRECTION)GetProcAddress(h1, "Wow64RevertWow64FsRedirection");

                    fvHotFixMin.LowPart = (3790 << 16) | 3999;
                    fvHotFixMin.HighPart = (5 << 16) | 2;

                    fnDisableWow64FsRedirection(&Wow64RedirectionState);
		    if (!GetFileVersion("kerberos.dll", &fvFile) ||
                        fvFile.HighPart != fvHotFixMin.HighPart ||
                        fvFile.LowPart < fvHotFixMin.LowPart)
                        fIsBrokenWow64 = TRUE;
#ifndef NODEBUG
                    if (fIsBrokenWow64)
                        OutputDebugStringA("cc_mslsa: is Broken WOW64 environment\n");
#endif /* NODEBUG */
                    fnRevertWow64FsRedirection(Wow64RedirectionState);
                }
	    }
	}
	fChecked = TRUE;
    }

    return fIsBrokenWow64;
}

/* This flag is only supported by versions of Windows which have obtained
 * a code change from Microsoft.   When the code change is installed,
 * setting this flag will cause all retrieved credentials to be stored
 * in the LSA cache.
 */
#ifndef KERB_RETRIEVE_TICKET_CACHE_TICKET
#define KERB_RETRIEVE_TICKET_CACHE_TICKET  0x20
#endif

static VOID
ReportWinError(krb5_context context, char *szCaller, BOOL bStatus, NTSTATUS Status)
{
    DWORD dwError = bStatus ? LsaNtStatusToWinError(Status) : Status;
    CHAR szMsgBuf[MAX_MSG_SIZE];
    DWORD dwRes;

    dwRes = FormatMessageA ( FORMAT_MESSAGE_FROM_SYSTEM,
                            NULL,
                            dwError,
                            MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US),
                            szMsgBuf,
                            MAX_MSG_SIZE,
                            NULL);
    if (dwRes) {
        krb5_set_error_message( context, KRB5_FCC_INTERNAL,
                                "%s: %s (0x%x)",
                                szCaller, szMsgBuf, Status);
    } else {
        krb5_set_error_message( context, KRB5_FCC_INTERNAL,
                                "%s: Error 0x%x",
                                szCaller, Status);
    }
}

static BOOL
WINAPI
UnicodeToANSI(LPTSTR lpInputString, LPSTR lpszOutputString, int nOutStringLen)
{
    CPINFO CodePageInfo;

    GetCPInfo(CP_ACP, &CodePageInfo);

    if (CodePageInfo.MaxCharSize > 1) {
        // Only supporting non-Unicode strings
        int reqLen = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR) lpInputString, -1,
                                         NULL, 0, NULL, NULL);
        if ( reqLen > nOutStringLen)
        {
            return FALSE;
        } else {
            if (WideCharToMultiByte(CP_ACP,
				    /* WC_NO_BEST_FIT_CHARS | */ WC_COMPOSITECHECK,
				    (LPCWSTR) lpInputString, -1,
				    lpszOutputString,
				    nOutStringLen, NULL, NULL) == 0)
		return FALSE;
        }
    }
    else
    {
        // Looks like unicode, better translate it
        if (WideCharToMultiByte(CP_ACP,
				/* WC_NO_BEST_FIT_CHARS | */ WC_COMPOSITECHECK,
				(LPCWSTR) lpInputString, -1,
				lpszOutputString,
				nOutStringLen, NULL, NULL) == 0)
	    return FALSE;
    }

    return TRUE;
}  // UnicodeToANSI

static VOID
WINAPI
ANSIToUnicode(LPSTR lpInputString, LPTSTR lpszOutputString, int nOutStringLen)
{
    // Looks like ANSI or MultiByte, better translate it
    MultiByteToWideChar(CP_ACP, 0, (LPCSTR) lpInputString, -1,
                        (LPWSTR) lpszOutputString, nOutStringLen);
}  // ANSIToUnicode


static void
MITPrincToMSPrinc(krb5_context context, krb5_principal principal, UNICODE_STRING * msprinc)
{
    char *aname = NULL;

    if (!krb5_unparse_name(context, principal, &aname)) {
        msprinc->Length = strlen(aname) * sizeof(WCHAR);
        if ( msprinc->Length <= msprinc->MaximumLength )
            ANSIToUnicode(aname, msprinc->Buffer, msprinc->MaximumLength);
        else
            msprinc->Length = 0;
        krb5_free_unparsed_name(context,aname);
    }
}

static BOOL
UnicodeStringToMITPrinc(UNICODE_STRING *service, WCHAR *realm, krb5_context context,
                        krb5_principal *principal)
{
    WCHAR princbuf[512];
    char aname[512];

    princbuf[0]=0;
    wcsncpy(princbuf, service->Buffer, service->Length/sizeof(WCHAR));
    princbuf[service->Length/sizeof(WCHAR)]=0;
    wcscat(princbuf, L"@");
    wcscat(princbuf, realm);
    if (UnicodeToANSI(princbuf, aname, sizeof(aname))) {
        if (krb5_parse_name(context, aname, principal) == 0)
	    return TRUE;
#ifndef NODEBUG
        else
            OutputDebugStringA("cc_mslsa: UnicodeStringToMITPrinc krb5_parse_name failed\n");
#endif /* NODEBUG */
    }
#ifndef NODEBUG
    else
        OutputDebugStringA("cc_mslsa: UnicodeStringToMITPrinc UnicodeToANSI failed\n");
#endif /* NODEBUG */

    return FALSE;
}


static BOOL
KerbExternalNameToMITPrinc(KERB_EXTERNAL_NAME *msprinc, WCHAR *realm, krb5_context context,
                           krb5_principal *principal)
{
    WCHAR princbuf[512],tmpbuf[128];
    char aname[512];
    USHORT i;
    princbuf[0]=0;
    for (i=0;i<msprinc->NameCount;i++) {
        wcsncpy(tmpbuf, msprinc->Names[i].Buffer,
                msprinc->Names[i].Length/sizeof(WCHAR));
        tmpbuf[msprinc->Names[i].Length/sizeof(WCHAR)]=0;
        if (princbuf[0])
            wcscat(princbuf, L"/");
        wcscat(princbuf, tmpbuf);
    }
    wcscat(princbuf, L"@");
    wcscat(princbuf, realm);
    if (UnicodeToANSI(princbuf, aname, sizeof(aname))) {
        if (krb5_parse_name(context, aname, principal) == 0)
	    return TRUE;
#ifndef NODEBUG
        else
            OutputDebugStringA("cc_mslsa: KerbExternalNameToMITPrinc krb5_parse_name failed\n");
#endif /* NODEBUG */
    }
#ifndef NODEBUG
    else
        OutputDebugStringA("cc_mslsa: KerbExternalNameToMITPrinc UnicodeToANSI failed\n");
#endif /* NODEBUG */
    return FALSE;
}

static time_t
FileTimeToUnixTime(LARGE_INTEGER *ltime)
{
    FILETIME filetime, localfiletime;
    SYSTEMTIME systime;
    struct tm utime;
    filetime.dwLowDateTime=ltime->LowPart;
    filetime.dwHighDateTime=ltime->HighPart;
    FileTimeToLocalFileTime(&filetime, &localfiletime);
    FileTimeToSystemTime(&localfiletime, &systime);
    utime.tm_sec=systime.wSecond;
    utime.tm_min=systime.wMinute;
    utime.tm_hour=systime.wHour;
    utime.tm_mday=systime.wDay;
    utime.tm_mon=systime.wMonth-1;
    utime.tm_year=systime.wYear-1900;
    utime.tm_isdst=-1;
    return(mktime(&utime));
}

static void
MSSessionKeyToMITKeyblock(KERB_CRYPTO_KEY *mskey, krb5_context context, krb5_keyblock *keyblock)
{
    krb5_keyblock tmpblock;
    tmpblock.magic=KV5M_KEYBLOCK;
    tmpblock.enctype=mskey->KeyType;
    tmpblock.length=mskey->Length;
    tmpblock.contents=mskey->Value;
    krb5_copy_keyblock_contents(context, &tmpblock, keyblock);
}

static BOOL
IsMSSessionKeyNull(KERB_CRYPTO_KEY *mskey)
{
    DWORD i;

    if (mskey->KeyType == KERB_ETYPE_NULL)
	return TRUE;

    for ( i=0; i<mskey->Length; i++ ) {
	if (mskey->Value[i])
	    return FALSE;
    }

#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: MS Session Key is NULL\n");
#endif /* NODEBUG */
    return TRUE;
}

static void
MSFlagsToMITFlags(ULONG msflags, ULONG *mitflags)
{
    *mitflags=msflags;
}

static BOOL
MSTicketToMITTicket(KERB_EXTERNAL_TICKET *msticket, krb5_context context, krb5_data *ticket)
{
    krb5_data tmpdata, *newdata = 0;
    krb5_error_code rc;

    tmpdata.magic=KV5M_DATA;
    tmpdata.length=msticket->EncodedTicketSize;
    tmpdata.data=msticket->EncodedTicket;

    // this is ugly and will break krb5_free_data()
    // now that this is being done within the library it won't break krb5_free_data()
    rc = krb5_copy_data(context, &tmpdata, &newdata);
    if (rc) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: MSTicketToMITTicket krb5_copy_data failed\n");
#endif /* NODEBUG */
        return FALSE;
    }
    memcpy(ticket, newdata, sizeof(krb5_data));
    krb5_xfree(newdata);
    return TRUE;
}

/*
 * PreserveInitialTicketIdentity()
 *
 * This will find the "PreserveInitialTicketIdentity" key in the registry.
 * Returns 1 to preserve and 0 to not.
 */

static DWORD
PreserveInitialTicketIdentity(void)
{
    HKEY hKey;
    DWORD size = sizeof(DWORD);
    DWORD type = REG_DWORD;
    const char *key_path = "Software\\MIT\\Kerberos5";
    const char *value_name = "PreserveInitialTicketIdentity";
    DWORD retval = 1;     /* default to Preserve */

    if (RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        goto syskey;
    if (RegQueryValueExA(hKey, value_name, 0, &type, (LPBYTE)&retval, &size) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        goto syskey;
    }
    RegCloseKey(hKey);
    goto done;

  syskey:
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        goto done;
    if (RegQueryValueExA(hKey, value_name, 0, &type, (LPBYTE)&retval, &size) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        goto done;
    }
    RegCloseKey(hKey);

  done:
    return retval;
}


static BOOL
MSCredToMITCred(KERB_EXTERNAL_TICKET *msticket, UNICODE_STRING ClientRealm,
                krb5_context context, krb5_creds *creds)
{
    WCHAR wrealm[128];
    ZeroMemory(creds, sizeof(krb5_creds));
    creds->magic=KV5M_CREDS;

    // construct Client Principal
    wcsncpy(wrealm, ClientRealm.Buffer, ClientRealm.Length/sizeof(WCHAR));
    wrealm[ClientRealm.Length/sizeof(WCHAR)]=0;
    if (!KerbExternalNameToMITPrinc(msticket->ClientName, wrealm, context, &creds->client)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: MSCredToMITCred failed (1)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    // construct Service Principal
    wcsncpy(wrealm, msticket->DomainName.Buffer,
            msticket->DomainName.Length/sizeof(WCHAR));
    wrealm[msticket->DomainName.Length/sizeof(WCHAR)]=0;
    if (!KerbExternalNameToMITPrinc(msticket->ServiceName, wrealm, context, &creds->server))
        return FALSE;
    MSSessionKeyToMITKeyblock(&msticket->SessionKey, context,
                              &creds->keyblock);
    MSFlagsToMITFlags(msticket->TicketFlags, &creds->ticket_flags);
    creds->times.starttime=FileTimeToUnixTime(&msticket->StartTime);
    creds->times.endtime=FileTimeToUnixTime(&msticket->EndTime);
    creds->times.renew_till=FileTimeToUnixTime(&msticket->RenewUntil);

    creds->addresses = NULL;

    if (!MSTicketToMITTicket(msticket, context, &creds->ticket)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: MSCredToMITCred failed (2)\n");
#endif /* NODEBUG */
        return FALSE;
    }
    return TRUE;
}

#ifdef HAVE_CACHE_INFO_EX2
/* CacheInfoEx2ToMITCred is used when we do not need the real ticket */
static BOOL
CacheInfoEx2ToMITCred(KERB_TICKET_CACHE_INFO_EX2 *info,
                      krb5_context context, krb5_creds *creds)
{
    WCHAR wrealm[128];
    ZeroMemory(creds, sizeof(krb5_creds));
    creds->magic=KV5M_CREDS;

    // construct Client Principal
    wcsncpy(wrealm, info->ClientRealm.Buffer, info->ClientRealm.Length/sizeof(WCHAR));
    wrealm[info->ClientRealm.Length/sizeof(WCHAR)]=0;
    if (!UnicodeStringToMITPrinc(&info->ClientName, wrealm, context, &creds->client)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: CacheInfoEx2ToMITCred failed (1)\n");
#endif /* NODEBUG */
	return FALSE;
    }
    // construct Service Principal
    wcsncpy(wrealm, info->ServerRealm.Buffer,
            info->ServerRealm.Length/sizeof(WCHAR));
    wrealm[info->ServerRealm.Length/sizeof(WCHAR)]=0;
    if (!UnicodeStringToMITPrinc(&info->ServerName, wrealm, context, &creds->server)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: CacheInfoEx2ToMITCred failed (2)\n");
#endif /* NODEBUG */
	return FALSE;
    }
    creds->keyblock.magic = KV5M_KEYBLOCK;
    creds->keyblock.enctype = info->SessionKeyType;
    creds->ticket_flags = info->TicketFlags;
    MSFlagsToMITFlags(info->TicketFlags, &creds->ticket_flags);
    creds->times.starttime=FileTimeToUnixTime(&info->StartTime);
    creds->times.endtime=FileTimeToUnixTime(&info->EndTime);
    creds->times.renew_till=FileTimeToUnixTime(&info->RenewTime);

    /* MS Tickets are addressless.  MIT requires an empty address
     * not a NULL list of addresses.
     */
    creds->addresses = (krb5_address **)malloc(sizeof(krb5_address *));
    memset(creds->addresses, 0, sizeof(krb5_address *));

    return TRUE;
}
#endif /* HAVE_CACHE_INFO_EX2 */

static BOOL
PackageConnectLookup(HANDLE *pLogonHandle, ULONG *pPackageId, krb5_context context)
{
    LSA_STRING Name;
    NTSTATUS Status;

    Status = LsaConnectUntrusted(
        pLogonHandle
        );

    if (FAILED(Status))
    {
        if (context)
            ReportWinError(context, "PackageConnectLookup [1]", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: PackageConnectLookup LsaConnectUntrusted failed\n");
#endif /* NODEBUG */
        return FALSE;
    }

    Name.Buffer = MICROSOFT_KERBEROS_NAME_A;
    Name.Length = strlen(Name.Buffer);
    Name.MaximumLength = Name.Length;

    Status = LsaLookupAuthenticationPackage(
        *pLogonHandle,
        &Name,
        pPackageId
        );

    if (FAILED(Status))
    {
        LsaDeregisterLogonProcess(*pLogonHandle);
        if (context)
            ReportWinError(context, "PackageConnectLookup [2]", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: PackageConnectLookup LsaLookupAuthenticationPackage failed\n");
#endif /* NODEBUG */
        return FALSE;
    }

    return TRUE;

}

static BOOL
does_retrieve_ticket_cache_ticket (void)
{
   static BOOL fChecked = FALSE;
   static BOOL fCachesTicket = FALSE;

   if (!fChecked)
   {
       NTSTATUS Status = 0;
       NTSTATUS SubStatus = 0;
       HANDLE LogonHandle = 0;
       ULONG  PackageId;
       ULONG RequestSize;
       PKERB_RETRIEVE_TKT_REQUEST pTicketRequest = NULL;
       PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
       ULONG ResponseSize;

       RequestSize = sizeof(*pTicketRequest) + 1;

       if (!PackageConnectLookup(&LogonHandle, &PackageId, NULL)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: does_retrieve_ticket_cache_ticket failed (1)\n");
#endif /* NODEBUG */
           return FALSE;
       }
       pTicketRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LMEM_ZEROINIT, RequestSize);
       if (!pTicketRequest) {
           LsaDeregisterLogonProcess(LogonHandle);
#ifndef NODEBUG
           OutputDebugStringA("cc_mslsa: does_retrieve_ticket_cache_ticket LocalAlloc failed (2)\n");
#endif /* NODEBUG */
           return FALSE;
       }

       pTicketRequest->MessageType = KerbRetrieveEncodedTicketMessage;
       pTicketRequest->LogonId.LowPart = 0;
       pTicketRequest->LogonId.HighPart = 0;
       pTicketRequest->TargetName.Length = 0;
       pTicketRequest->TargetName.MaximumLength = 0;
       pTicketRequest->TargetName.Buffer = (PWSTR) (pTicketRequest + 1);
       pTicketRequest->CacheOptions = KERB_RETRIEVE_TICKET_CACHE_TICKET;
       pTicketRequest->EncryptionType = 0;
       pTicketRequest->TicketFlags = 0;

       Status = LsaCallAuthenticationPackage( LogonHandle,
                                              PackageId,
                                              pTicketRequest,
                                              RequestSize,
                                              &pTicketResponse,
                                              &ResponseSize,
                                              &SubStatus
                                              );

       LocalFree(pTicketRequest);
       if (pTicketResponse)
           LsaFreeReturnBuffer(pTicketResponse);
       LsaDeregisterLogonProcess(LogonHandle);

       if (FAILED(Status) || FAILED(SubStatus)) {
           if ( SubStatus == STATUS_NOT_SUPPORTED ||
                SubStatus == SEC_E_TARGET_UNKNOWN) {
               /* 1. The combination of the two CacheOption flags
                *    is not supported; therefore, the new flag is supported.
                * 2. The target name is unknown; therefore, the new flag is supported.
                */
               fCachesTicket = TRUE;
#ifndef NODEBUG
               if (SubStatus == STATUS_NOT_SUPPORTED)
                   OutputDebugStringA("cc_mslsa: does_retrieve_ticket_cache_ticket fCachesTicket STATUS_NOT_SUPPORTED\n");
               else if (SubStatus == SEC_E_TARGET_UNKNOWN)
                   OutputDebugStringA("cc_mslsa: does_retrieve_ticket_cache_ticket fCachesTicket SEC_E_TARGET_UNKNOWN\n");
#endif /* NODEBUG */

           }
       }
       fChecked = TRUE;
   }

   return fCachesTicket;
}

#ifdef HAVE_CACHE_INFO_EX2
static BOOL
does_query_ticket_cache_ex2 (void)
{
   static BOOL fChecked = FALSE;
   static BOOL fEx2Response = FALSE;

   if (!fChecked)
   {
       NTSTATUS Status = 0;
       NTSTATUS SubStatus = 0;
       HANDLE LogonHandle = 0;
       ULONG  PackageId;
       ULONG RequestSize;
       PKERB_QUERY_TKT_CACHE_REQUEST pCacheRequest = NULL;
       PKERB_QUERY_TKT_CACHE_EX2_RESPONSE pCacheResponse = NULL;
       ULONG ResponseSize;

       RequestSize = sizeof(*pCacheRequest) + 1;

       if (!PackageConnectLookup(&LogonHandle, &PackageId, NULL)) {
#ifndef NODEBUG
           OutputDebugStringA("cc_mslsa: does_query_ticket_cache_ex2 failed (1)\n");
#endif /* NODEBUG */
           return FALSE;
       }
       pCacheRequest = (PKERB_QUERY_TKT_CACHE_REQUEST) LocalAlloc(LMEM_ZEROINIT, RequestSize);
       if (!pCacheRequest) {
           LsaDeregisterLogonProcess(LogonHandle);
#ifndef NODEBUG
           OutputDebugStringA("cc_mslsa: does_query_ticket_cache_ex2 LocalAlloc failed\n");
#endif /* NODEBUG */
           return FALSE;
       }

       pCacheRequest->MessageType = KerbQueryTicketCacheEx2Message;
       pCacheRequest->LogonId.LowPart = 0;
       pCacheRequest->LogonId.HighPart = 0;

       Status = LsaCallAuthenticationPackage( LogonHandle,
                                              PackageId,
                                              pCacheRequest,
                                              RequestSize,
                                              &pCacheResponse,
                                              &ResponseSize,
                                              &SubStatus
                                              );

       LocalFree(pCacheRequest);
       if (pCacheResponse)
           LsaFreeReturnBuffer(pCacheResponse);
       LsaDeregisterLogonProcess(LogonHandle);

       if (!(FAILED(Status) || FAILED(SubStatus))) {
           LsaFreeReturnBuffer(pCacheResponse);
#ifndef NODEBUG
           OutputDebugStringA("cc_mslsa: does_query_ticket_cache_ex2 fEx2Response\n");
#endif /* NODEBUG */
           fEx2Response = TRUE;
       }
       fChecked = TRUE;
   }

   return fEx2Response;
}
#endif /* HAVE_CACHE_INFO_EX2 */

static DWORD

ConcatenateUnicodeStrings(UNICODE_STRING *pTarget, UNICODE_STRING Source1, UNICODE_STRING Source2)
{
    //
    // The buffers for Source1 and Source2 cannot overlap pTarget's
    // buffer.  Source1.Length + Source2.Length must be <= 0xFFFF,
    // otherwise we overflow...
    //

    USHORT TotalSize = Source1.Length + Source2.Length;
    PBYTE buffer = (PBYTE) pTarget->Buffer;

    if (Source1.Length > Source1.MaximumLength || Source1.MaximumLength == 0 ||
        Source2.Length > Source2.MaximumLength || Source2.MaximumLength == 0)
    {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: ConcatenateUnicodeStrings ERROR_INVALID_PARAMETER\n");
#endif /* NODEBUG */
        return ERROR_INVALID_PARAMETER;
    }
    if (TotalSize > pTarget->MaximumLength) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: ConcatenateUnicodeStrings ERROR_INSUFFICIENT_BUFFER\n");
#endif /* NODEBUG */
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if ( pTarget->Buffer != Source1.Buffer )
        memcpy(buffer, Source1.Buffer, Source1.Length);
    memcpy(buffer + Source1.Length, Source2.Buffer, Source2.Length);

    pTarget->Length = TotalSize;
    return ERROR_SUCCESS;
}

static BOOL
get_STRING_from_registry(HKEY hBaseKey, char * key, char * value, char * outbuf, DWORD  outlen)
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
GetSecurityLogonSessionData(PSECURITY_LOGON_SESSION_DATA * ppSessionData)
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

//
// IsKerberosLogon() does not validate whether or not there are valid tickets in the
// cache.  It validates whether or not it is reasonable to assume that if we
// attempted to retrieve valid tickets we could do so.  Microsoft does not
// automatically renew expired tickets.  Therefore, the cache could contain
// expired or invalid tickets.  Microsoft also caches the user's password
// and will use it to retrieve new TGTs if the cache is empty and tickets
// are requested.

static BOOL
IsKerberosLogon(VOID)
{
    PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;
    BOOL    Success = FALSE;

    if ( GetSecurityLogonSessionData(&pSessionData) ) {
        if ( pSessionData->AuthenticationPackage.MaximumLength > 0 &&
             pSessionData->AuthenticationPackage.Length <= pSessionData->AuthenticationPackage.MaximumLength &&
             pSessionData->AuthenticationPackage.Buffer ) {
            WCHAR buffer[256];
            WCHAR *usBuffer;
            int usLength;

            Success = FALSE;
            usBuffer = (pSessionData->AuthenticationPackage).Buffer;
            usLength = (pSessionData->AuthenticationPackage).Length;
            if (usLength < 256)
            {
                lstrcpynW (buffer, usBuffer, usLength);
                lstrcatW (buffer,L"");
                if ( !lstrcmpW(L"Kerberos",buffer) )
                    Success = TRUE;
            }
        }
        LsaFreeReturnBuffer(pSessionData);
    }
#ifndef NODEBUG
    if (!Success)
        OutputDebugStringA("cc_mslsa: NOT IsKerberosLogon\n");
#endif /* NODEBUG */

    return Success;
}

static DWORD
ConstructTicketRequest(UNICODE_STRING DomainName, PKERB_RETRIEVE_TKT_REQUEST * outRequest, ULONG * outSize)
{
    DWORD Error;
    UNICODE_STRING TargetPrefix;
    USHORT TargetSize;
    ULONG RequestSize;
    PKERB_RETRIEVE_TKT_REQUEST pTicketRequest = NULL;

    *outRequest = NULL;
    *outSize = 0;

    //
    // Set up the "krbtgt/" target prefix into a UNICODE_STRING so we
    // can easily concatenate it later.
    //

    TargetPrefix.Buffer = L"krbtgt/";
    TargetPrefix.Length = wcslen(TargetPrefix.Buffer) * sizeof(WCHAR);
    TargetPrefix.MaximumLength = TargetPrefix.Length;

    //
    // We will need to concatenate the "krbtgt/" prefix and the
    // Logon Session's DnsDomainName into our request's target name.
    //
    // Therefore, first compute the necessary buffer size for that.
    //
    // Note that we might theoretically have integer overflow.
    //

    TargetSize = TargetPrefix.Length + DomainName.Length;

    //
    // The ticket request buffer needs to be a single buffer.  That buffer
    // needs to include the buffer for the target name.
    //

    RequestSize = sizeof(*pTicketRequest) + TargetSize;

    //
    // Allocate the request buffer and make sure it's zero-filled.
    //

    pTicketRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LMEM_ZEROINIT, RequestSize);
    if (!pTicketRequest) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: ConstructTicketRequest LocalAlloc failed\n");
#endif /* NODEBUG */
        return GetLastError();
    }
    //
    // Concatenate the target prefix with the previous reponse's
    // target domain.
    //

    pTicketRequest->TargetName.Length = 0;
    pTicketRequest->TargetName.MaximumLength = TargetSize;
    pTicketRequest->TargetName.Buffer = (PWSTR) (pTicketRequest + 1);
    Error = ConcatenateUnicodeStrings(&(pTicketRequest->TargetName),
                                        TargetPrefix,
                                        DomainName);
    *outRequest = pTicketRequest;
    *outSize    = RequestSize;
    return Error;
}

static BOOL
PurgeAllTickets(HANDLE LogonHandle, ULONG  PackageId, krb5_context context)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    KERB_PURGE_TKT_CACHE_REQUEST PurgeRequest;

    PurgeRequest.MessageType = KerbPurgeTicketCacheMessage;
    PurgeRequest.LogonId.LowPart = 0;
    PurgeRequest.LogonId.HighPart = 0;
    PurgeRequest.ServerName.Buffer = L"";
    PurgeRequest.ServerName.Length = 0;
    PurgeRequest.ServerName.MaximumLength = 0;
    PurgeRequest.RealmName.Buffer = L"";
    PurgeRequest.RealmName.Length = 0;
    PurgeRequest.RealmName.MaximumLength = 0;
    Status = LsaCallAuthenticationPackage(LogonHandle,
                                           PackageId,
                                           &PurgeRequest,
                                           sizeof(PurgeRequest),
                                           NULL,
                                           NULL,
                                           &SubStatus
                                           );
    if (context) {
        if (FAILED(Status)) {
            ReportWinError( context, "PurgeAllTickets KerbPurgeTicketCacheMessage Status",
                            TRUE, Status);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: PurgeAllTickets KerbPurgeTicketCacheMessage failed (1)\n");
#endif /* NODEBUG */
            return FALSE;
        }

        if (FAILED(SubStatus))
        {
            ReportWinError( context, "PurgeAllTickets KerbPurgeTicketCacheMessage SubStatus",
                            TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: PurgeAllTickets KerbPurgeTicketCacheMessage failed (2)\n");
#endif /* NODEBUG */
            return FALSE;
        }
    }

    return TRUE;
}

static BOOL
PurgeTicket2000( HANDLE LogonHandle, ULONG  PackageId,
                 krb5_context context, krb5_creds *cred )
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    KERB_PURGE_TKT_CACHE_REQUEST * pPurgeRequest;
    DWORD dwRequestLen = sizeof(KERB_PURGE_TKT_CACHE_REQUEST) + 2048;
    char * sname = NULL, * srealm = NULL;

    if (krb5_unparse_name(context, cred->server, &sname)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: PurgeTicket2000 krb5_unparse_name failed\n");
#endif /* NODEBUG */
        return FALSE;
    }

    pPurgeRequest = malloc(dwRequestLen);
    if ( pPurgeRequest == NULL ) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: PurgeTicket2000 malloc failed\n");
#endif /* NODEBUG */
        krb5_free_unparsed_name(context, sname);
        return FALSE;
    }
    memset(pPurgeRequest, 0, dwRequestLen);

    srealm = strrchr(sname, '@');
    *srealm = '\0';
    srealm++;

    pPurgeRequest->MessageType = KerbPurgeTicketCacheMessage;
    pPurgeRequest->LogonId.LowPart = 0;
    pPurgeRequest->LogonId.HighPart = 0;
    pPurgeRequest->ServerName.Buffer = (PWSTR)(((CHAR *)pPurgeRequest)+sizeof(KERB_PURGE_TKT_CACHE_REQUEST));
    pPurgeRequest->ServerName.Length = strlen(sname)*sizeof(WCHAR);
    pPurgeRequest->ServerName.MaximumLength = 512;
    ANSIToUnicode(sname, pPurgeRequest->ServerName.Buffer,
                  pPurgeRequest->ServerName.MaximumLength/sizeof(WCHAR));
    pPurgeRequest->RealmName.Buffer = (PWSTR)(((CHAR *)pPurgeRequest)+sizeof(KERB_PURGE_TKT_CACHE_REQUEST)+512);
    pPurgeRequest->RealmName.Length = strlen(srealm)*sizeof(WCHAR);
    pPurgeRequest->RealmName.MaximumLength = 512;
    ANSIToUnicode(srealm, pPurgeRequest->RealmName.Buffer,
                  pPurgeRequest->RealmName.MaximumLength/sizeof(WCHAR));

    Status = LsaCallAuthenticationPackage( LogonHandle,
                                           PackageId,
                                           pPurgeRequest,
                                           dwRequestLen,
                                           NULL,
                                           NULL,
                                           &SubStatus
                                           );
    free(pPurgeRequest);
    krb5_free_unparsed_name(context, sname);

    if (context) {
        if (FAILED(Status)) {
            ReportWinError( context, "PurgeTicket2000 KerbPurgeTicketCacheMessage Status",
                            TRUE, Status);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: PurgeTicket2000 KerbPurgeTicketCacheMessage failed (1)\n");
#endif /* NODEBUG */
            return FALSE;
        }

        if (FAILED(SubStatus))
        {
            ReportWinError( context, "PurgeTicket2000 KerbPurgeTicketCacheMessage SubStatus",
                            TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: PurgeTicket2000 KerbPurgeTicketCacheMessage failed (2)\n");
#endif /* NODEBUG */
            return FALSE;
        }
    }

    return TRUE;
}


static BOOL
PurgeTicketXP( HANDLE LogonHandle, ULONG  PackageId,
               krb5_context context, krb5_flags flags, krb5_creds *cred)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    KERB_PURGE_TKT_CACHE_EX_REQUEST * pPurgeRequest;
    DWORD dwRequestLen = sizeof(KERB_PURGE_TKT_CACHE_EX_REQUEST) + 4096;
    char * cname = NULL, * crealm = NULL;
    char * sname = NULL, * srealm = NULL;

    if (krb5_unparse_name(context, cred->client, &cname)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: PurgeTicketXP krb5_unparse_name failed (1)\n");
#endif /* NODEBUG */
        return FALSE;
    }
    if (krb5_unparse_name(context, cred->server, &sname)) {
        krb5_free_unparsed_name(context, cname);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: PurgeTicketXP krb5_unparse_name failed (2)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    pPurgeRequest = malloc(dwRequestLen);
    if ( pPurgeRequest == NULL ) {
        krb5_free_unparsed_name(context,cname);
        krb5_free_unparsed_name(context,sname);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: PurgeTicketXP malloc failed\n");
#endif /* NODEBUG */
        return FALSE;
    }
    memset(pPurgeRequest, 0, dwRequestLen);

    crealm = strrchr(cname, '@');
    *crealm = '\0';
    crealm++;

    srealm = strrchr(sname, '@');
    *srealm = '\0';
    srealm++;

    pPurgeRequest->MessageType = KerbPurgeTicketCacheExMessage;
    pPurgeRequest->LogonId.LowPart = 0;
    pPurgeRequest->LogonId.HighPart = 0;
    pPurgeRequest->Flags = 0;
    pPurgeRequest->TicketTemplate.ClientName.Buffer = (PWSTR)((CHAR *)pPurgeRequest + sizeof(KERB_PURGE_TKT_CACHE_EX_REQUEST));
    pPurgeRequest->TicketTemplate.ClientName.Length = strlen(cname)*sizeof(WCHAR);
    pPurgeRequest->TicketTemplate.ClientName.MaximumLength = 512;
    ANSIToUnicode(cname, pPurgeRequest->TicketTemplate.ClientName.Buffer,
                  pPurgeRequest->TicketTemplate.ClientName.MaximumLength/sizeof(WCHAR));

    pPurgeRequest->TicketTemplate.ClientRealm.Buffer = (PWSTR)(((CHAR *)pPurgeRequest)+sizeof(KERB_PURGE_TKT_CACHE_EX_REQUEST) + 512);
    pPurgeRequest->TicketTemplate.ClientRealm.Length = strlen(crealm)*sizeof(WCHAR);
    pPurgeRequest->TicketTemplate.ClientRealm.MaximumLength = 512;
    ANSIToUnicode(crealm, pPurgeRequest->TicketTemplate.ClientRealm.Buffer,
                  pPurgeRequest->TicketTemplate.ClientRealm.MaximumLength/sizeof(WCHAR));

    pPurgeRequest->TicketTemplate.ServerName.Buffer = (PWSTR)(((CHAR *)pPurgeRequest)+sizeof(KERB_PURGE_TKT_CACHE_EX_REQUEST) + 1024);
    pPurgeRequest->TicketTemplate.ServerName.Length = strlen(sname)*sizeof(WCHAR);
    pPurgeRequest->TicketTemplate.ServerName.MaximumLength = 512;
    ANSIToUnicode(sname, pPurgeRequest->TicketTemplate.ServerName.Buffer,
                  pPurgeRequest->TicketTemplate.ServerName.MaximumLength/sizeof(WCHAR));

    pPurgeRequest->TicketTemplate.ServerRealm.Buffer = (PWSTR)(((CHAR *)pPurgeRequest)+sizeof(KERB_PURGE_TKT_CACHE_EX_REQUEST) + 1536);
    pPurgeRequest->TicketTemplate.ServerRealm.Length = strlen(srealm)*sizeof(WCHAR);
    pPurgeRequest->TicketTemplate.ServerRealm.MaximumLength = 512;
    ANSIToUnicode(srealm, pPurgeRequest->TicketTemplate.ServerRealm.Buffer,
                  pPurgeRequest->TicketTemplate.ServerRealm.MaximumLength/sizeof(WCHAR));

    pPurgeRequest->TicketTemplate.StartTime;
    pPurgeRequest->TicketTemplate.EndTime;
    pPurgeRequest->TicketTemplate.RenewTime;
    pPurgeRequest->TicketTemplate.EncryptionType = cred->keyblock.enctype;
    pPurgeRequest->TicketTemplate.TicketFlags = flags;

    Status = LsaCallAuthenticationPackage( LogonHandle,
                                           PackageId,
                                           pPurgeRequest,
                                           dwRequestLen,
                                           NULL,
                                           NULL,
                                           &SubStatus
                                           );
    free(pPurgeRequest);
    krb5_free_unparsed_name(context,cname);
    krb5_free_unparsed_name(context,sname);

    if (context) {
        if (FAILED(Status)) {
            ReportWinError( context, "PurgeTicketXP KerbPurgeTicketCacheExMessage Status",
                            TRUE, Status);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: PurgeTicketXP KerbPurgeTicketCacheExMessage failed (1)\n");
#endif /* NODEBUG */
            return FALSE;
        }

        if (FAILED(SubStatus))
        {
            ReportWinError( context, "PurgeTicketXP KerbPurgeTicketCacheExMessage SubStatus",
                            TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: PurgeTicketXP KerbPurgeTicketCacheExMessage failed (2)\n");
#endif /* NODEBUG */
            return FALSE;
        }
    }

    return TRUE;
}

#ifdef KERB_SUBMIT_TICKET
static BOOL
KerbSubmitTicket( HANDLE LogonHandle, ULONG  PackageId,
                  krb5_context context, krb5_creds *cred)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    KERB_SUBMIT_TKT_REQUEST * pSubmitRequest;
    DWORD dwRequestLen;
    krb5_auth_context auth_context;
    krb5_keyblock * keyblock = 0;
    krb5_replay_data replaydata;
    krb5_data * krb_cred = 0;
    krb5_error_code rc;

    if (krb5_auth_con_init(context, &auth_context)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: KerbSubmitTicket krb5_auth_con_init failed\n");
#endif /* NODEBUG */
        return FALSE;
    }

    if (krb5_auth_con_setflags(context, auth_context,
                               KRB5_AUTH_CONTEXT_RET_TIME | KRB5_AUTH_CONTEXT_USE_SUBKEY)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: KerbSubmitTicket krb5_auth_con_setflags failed\n");
#endif /* NODEBUG */
        return FALSE;
    }

    krb5_auth_con_getsendsubkey(context, auth_context, &keyblock);
    if (keyblock == NULL)
        krb5_auth_con_getkey(context, auth_context, &keyblock);

    /* make up a key, any key, that can be used to generate the
    * encrypted KRB_CRED pdu.  The Vista release LSA requires
    * that an enctype other than NULL be used. */
    if (keyblock == NULL) {
        keyblock = (krb5_keyblock *)malloc(sizeof(krb5_keyblock));
        keyblock->enctype = ENCTYPE_ARCFOUR_HMAC;
        keyblock->length = 16;
        keyblock->contents = (krb5_octet *)malloc(16);
        keyblock->contents[0] = 0xde;
        keyblock->contents[1] = 0xad;
        keyblock->contents[2] = 0xbe;
        keyblock->contents[3] = 0xef;
        keyblock->contents[4] = 0xfe;
        keyblock->contents[5] = 0xed;
        keyblock->contents[6] = 0xf0;
        keyblock->contents[7] = 0xd;
        keyblock->contents[8] = 0xde;
        keyblock->contents[9] = 0xad;
        keyblock->contents[10] = 0xbe;
        keyblock->contents[11] = 0xef;
        keyblock->contents[12] = 0xfe;
        keyblock->contents[13] = 0xed;
        keyblock->contents[14] = 0xf0;
        keyblock->contents[15] = 0xd;
        krb5_auth_con_setsendsubkey(context, auth_context, keyblock);
    }
    rc = krb5_mk_1cred(context, auth_context, cred, &krb_cred, &replaydata);
    if (rc) {
        krb5_auth_con_free(context, auth_context);
        if (keyblock)
            krb5_free_keyblock(context, keyblock);
        if (krb_cred)
            krb5_free_data(context, krb_cred);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: KerbSubmitTicket krb5_mk_1cred failed\n");
#endif /* NODEBUG */
        return FALSE;
    }

    dwRequestLen = sizeof(KERB_SUBMIT_TKT_REQUEST) + krb_cred->length + (keyblock ? keyblock->length : 0);

    pSubmitRequest = (PKERB_SUBMIT_TKT_REQUEST)malloc(dwRequestLen);
    memset(pSubmitRequest, 0, dwRequestLen);

    pSubmitRequest->MessageType = KerbSubmitTicketMessage;
    pSubmitRequest->LogonId.LowPart = 0;
    pSubmitRequest->LogonId.HighPart = 0;
    pSubmitRequest->Flags = 0;

    if (keyblock) {
        pSubmitRequest->Key.KeyType = keyblock->enctype;
        pSubmitRequest->Key.Length = keyblock->length;
        pSubmitRequest->Key.Offset = sizeof(KERB_SUBMIT_TKT_REQUEST)+krb_cred->length;
    } else {
        pSubmitRequest->Key.KeyType = ENCTYPE_NULL;
        pSubmitRequest->Key.Length = 0;
        pSubmitRequest->Key.Offset = 0;
    }
    pSubmitRequest->KerbCredSize = krb_cred->length;
    pSubmitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
    memcpy(((CHAR *)pSubmitRequest)+sizeof(KERB_SUBMIT_TKT_REQUEST),
           krb_cred->data, krb_cred->length);
    if (keyblock)
        memcpy(((CHAR *)pSubmitRequest)+sizeof(KERB_SUBMIT_TKT_REQUEST)+krb_cred->length,
                keyblock->contents, keyblock->length);
    krb5_free_data(context, krb_cred);

    Status = LsaCallAuthenticationPackage( LogonHandle,
                                           PackageId,
                                           pSubmitRequest,
                                           dwRequestLen,
                                           NULL,
                                           NULL,
                                           &SubStatus
                                           );
    free(pSubmitRequest);
    if (keyblock)
        krb5_free_keyblock(context, keyblock);
    krb5_auth_con_free(context, auth_context);

    if (context) {
        if (FAILED(Status)) {
            ReportWinError( context, "KerbSubmitTicket KerbSubmitTicketMessage Status",
                            TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: KerbSubmitTicket KerbSubmitTicketMessage failed (1)\n");
#endif /* NODEBUG */
            return FALSE;
        }

        if (FAILED(SubStatus))
        {
            ReportWinError( context, "KerbSubmitTicket KerbSubmitTicketMessage SubStatus",
                            TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: KerbSubmitTicket KerbSubmitTicketMessage failed (1)\n");
#endif /* NODEBUG */
            return FALSE;
        }
    }

    return TRUE;
}
#endif /* KERB_SUBMIT_TICKET */

/*
 * A simple function to determine if there is an exact match between two tickets
 * We rely on the fact that the external tickets contain the raw Kerberos ticket.
 * If the EncodedTicket fields match, the KERB_EXTERNAL_TICKETs must be the same.
 */
static BOOL
KerbExternalTicketMatch( PKERB_EXTERNAL_TICKET one, PKERB_EXTERNAL_TICKET two )
{
    if ( one->EncodedTicketSize != two->EncodedTicketSize )
        return FALSE;

    if ( memcmp(one->EncodedTicket, two->EncodedTicket, one->EncodedTicketSize) )
         return FALSE;

    return TRUE;
}

krb5_boolean
krb5_is_permitted_tgs_enctype(krb5_context context, krb5_const_principal princ, krb5_enctype etype)
{
    krb5_enctype *list, *ptr;
    krb5_boolean ret;

    if (krb5_get_tgs_ktypes(context, princ, &list))
        return(0);

    ret = 0;

    for (ptr = list; *ptr; ptr++)
	if (*ptr == etype)
	    ret = 1;

    krb5_free_ktypes (context, list);

    return(ret);
}

#define ENABLE_PURGING 1
// to allow the purging of expired tickets from LSA cache.  This is necessary
// to force the retrieval of new TGTs.  Microsoft does not appear to retrieve
// new tickets when they expire.  Instead they continue to accept the expired
// tickets.  This is safe to do because the LSA purges its cache when it
// retrieves a new TGT (ms calls this renew) but not when it renews the TGT
// (ms calls this refresh).
//
// This function returns TRUE iff a ticket is retrieved and FALSE otherwise.

static BOOL
GetMSTGT( HANDLE LogonHandle, ULONG PackageId,
          krb5_context context,
          KERB_EXTERNAL_TICKET **ticket, BOOL enforce_tgs_enctypes)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    DWORD    Error = 0;
    BOOL     bRet = FALSE;

    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
    PKERB_RETRIEVE_TKT_REQUEST pTicketRequest = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
    ULONG RequestSize;
    ULONG ResponseSize;
#ifdef ENABLE_PURGING
    int    purge_cache = 0;
#endif /* ENABLE_PURGING */
    int    ignore_cache = 0;
    krb5_enctype *etype_list = NULL, *ptr = NULL, etype = 0;

    memset(&CacheRequest, 0, sizeof(KERB_QUERY_TKT_CACHE_REQUEST));
    CacheRequest.MessageType = KerbRetrieveTicketMessage;
    CacheRequest.LogonId.LowPart = 0;
    CacheRequest.LogonId.HighPart = 0;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        &CacheRequest,
        sizeof(CacheRequest),
        &pTicketResponse,
        &ResponseSize,
        &SubStatus
        );

    if (FAILED(Status))
    {
        // if the call to LsaCallAuthenticationPackage failed we cannot
        // perform any queries most likely because the Kerberos package
        // is not available or we do not have access
        ReportWinError(context, "GetMSTGT KerbRetrieveTicketMessage Status", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSTGT KerbRetrieveTicketMessage failed (1)\n");
#endif /* NODEBUG */
        goto cleanup;
    }

    if (FAILED(SubStatus)) {
        PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;
        BOOL    Success = FALSE;
        OSVERSIONINFOEX verinfo;
        int supported = 0;

        // SubStatus 0x8009030E is SEC_E_NO_CREDENTIALS
        if (SubStatus != 0x8009030E) {
            ReportWinError(context, "GetMSTGT KerbRetrieveTicketMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetMSTGT KerbRetrieveTicketMessage failed (2)\n");
#endif /* NODEBUG */
            goto cleanup;
        }

        verinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        GetVersionEx((OSVERSIONINFO *)&verinfo);
        supported = (verinfo.dwMajorVersion > 5) ||
            (verinfo.dwMajorVersion == 5 && verinfo.dwMinorVersion >= 1);

        // If we could not get a TGT from the cache we won't know what the
        // Kerberos Domain should have been.  On Windows XP and 2003 Server
        // we can extract it from the Security Logon Session Data.  However,
        // the required fields are not supported on Windows 2000.  :(
        if ( supported && GetSecurityLogonSessionData(&pSessionData) ) {
            if ( pSessionData->DnsDomainName.MaximumLength > 0 &&
                 pSessionData->DnsDomainName.Length <= pSessionData->DnsDomainName.MaximumLength &&
                 pSessionData->DnsDomainName.Buffer ) {
                Error = ConstructTicketRequest(pSessionData->DnsDomainName,
                                               &pTicketRequest, &RequestSize);
                LsaFreeReturnBuffer(pSessionData);
                if ( Error ) {
                    ReportWinError(context, "GetMSTGT ConstructTicketRequest (session)", FALSE, Error);
#ifndef NODEBUG
                    OutputDebugStringA("cc_mslsa: GetMSTGT ConstructTicketRequest (session)\n");
#endif /* NODEBUG */
                    goto cleanup;
                }
            } else {
                LsaFreeReturnBuffer(pSessionData);
                goto use_userdnsdomain;
            }
        } else {
            CHAR  UserDnsDomain[256];
            WCHAR UnicodeUserDnsDomain[256];
            UNICODE_STRING wrapper;

          use_userdnsdomain:
            if ( !get_STRING_from_registry(HKEY_CURRENT_USER,
                                          "Volatile Environment",
                                          "USERDNSDOMAIN",
                                           UserDnsDomain,
                                           sizeof(UserDnsDomain)
                                           ) )
            {
                ReportWinError(context, "GetMSTGT USERDNSDOMAIN not found", FALSE, GetLastError());
#ifndef NODEBUG
                OutputDebugStringA("cc_mslsa: GetMSTGT USERDNSDOMAIN not found\n");
#endif /* NODEBUG */
                goto cleanup;
            }

            ANSIToUnicode(UserDnsDomain,UnicodeUserDnsDomain,256);
            wrapper.Buffer = UnicodeUserDnsDomain;
            wrapper.Length = wcslen(UnicodeUserDnsDomain) * sizeof(WCHAR);
            wrapper.MaximumLength = sizeof(UnicodeUserDnsDomain);

            Error = ConstructTicketRequest(wrapper,
                                           &pTicketRequest, &RequestSize);
            if ( Error ) {
                ReportWinError(context, "GetMSTGT ConstructTicketRequest (registry)", FALSE, Error);
#ifndef NODEBUG
                OutputDebugStringA("cc_mslsa: GetMSTGT ConstructTicketRequest (registry)\n");
#endif /* NODEBUG */
                goto cleanup;
            }
        }
    } else {
        /* We have succeeded in obtaining a credential from the cache.
         * Assuming the enctype is one that we support and the ticket
         * has not expired and is not marked invalid we will use it.
         * Otherwise, we must create a new ticket request and obtain
         * a credential we can use.
         */

#ifdef PURGE_ALL
        purge_cache = 1;
#else
        /* Check Supported Enctypes */
        if ( !IsMSSessionKeyNull(&pTicketResponse->Ticket.SessionKey) &&
             (!enforce_tgs_enctypes ||
               krb5_is_permitted_tgs_enctype(context, NULL, pTicketResponse->Ticket.SessionKey.KeyType))) {
            FILETIME Now, MinLife, EndTime, LocalEndTime;
            __int64  temp;
            // FILETIME is in units of 100 nano-seconds
            // If obtained tickets are either expired or have a lifetime
            // less than 20 minutes, retry ...
            GetSystemTimeAsFileTime(&Now);
            EndTime.dwLowDateTime=pTicketResponse->Ticket.EndTime.LowPart;
            EndTime.dwHighDateTime=pTicketResponse->Ticket.EndTime.HighPart;
            FileTimeToLocalFileTime(&EndTime, &LocalEndTime);
            temp = Now.dwHighDateTime;
            temp <<= 32;
            temp = Now.dwLowDateTime;
            temp += 1200 * 10000;
            MinLife.dwHighDateTime = (DWORD)((temp >> 32) & 0xFFFFFFFF);
            MinLife.dwLowDateTime = (DWORD)(temp & 0xFFFFFFFF);
            if (CompareFileTime(&MinLife, &LocalEndTime) >= 0) {
#ifdef ENABLE_PURGING
                purge_cache = 1;
#else
                ignore_cache = 1;
#endif /* ENABLE_PURGING */
            }
            if (pTicketResponse->Ticket.TicketFlags & KERB_TICKET_FLAGS_invalid) {
                ignore_cache = 1;   // invalid, need to attempt a TGT request
            }

            bRet = TRUE;
            goto cleanup;           // we have a valid ticket, all done
        } else {
            // not supported
            ignore_cache = 1;
        }
#endif /* PURGE_ALL */

        Error = ConstructTicketRequest(pTicketResponse->Ticket.TargetDomainName,
                                        &pTicketRequest, &RequestSize);
        if ( Error ) {
            ReportWinError(context, "GetMSTGT ConstructTicketRequest (response)", FALSE, Error);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetMSTGT ConstructTicketRequest (response)\n");
#endif /* NODEBUG */
            goto cleanup;
        }

        //
        // Free the previous response buffer so we can get the new response.
        //

        if ( pTicketResponse ) {
            memset(pTicketResponse,0,sizeof(KERB_RETRIEVE_TKT_RESPONSE));
            LsaFreeReturnBuffer(pTicketResponse);
            pTicketResponse = NULL;
        }

#ifdef ENABLE_PURGING
        if ( purge_cache ) {
            //
            // Purge the existing tickets which we cannot use so new ones can
            // be requested.  It is not possible to purge just the TGT.  All
            // service tickets must be purged.
            //
            PurgeAllTickets(LogonHandle, PackageId, context);
        }
#endif /* ENABLE_PURGING */
    }

    //
    // Initialize the request of the request.
    //

    pTicketRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pTicketRequest->LogonId.LowPart = 0;
    pTicketRequest->LogonId.HighPart = 0;
    // Note: pTicketRequest->TargetName set up above
#ifdef ENABLE_PURGING
    pTicketRequest->CacheOptions = ((ignore_cache || !purge_cache) ?
                                     KERB_RETRIEVE_TICKET_DONT_USE_CACHE : 0L);
#else
    pTicketRequest->CacheOptions = (ignore_cache ? KERB_RETRIEVE_TICKET_DONT_USE_CACHE : 0L);
#endif /* ENABLE_PURGING */
    pTicketRequest->TicketFlags = 0L;
    pTicketRequest->EncryptionType = 0L;

    Status = LsaCallAuthenticationPackage( LogonHandle,
                                           PackageId,
                                           pTicketRequest,
                                           RequestSize,
                                           &pTicketResponse,
                                           &ResponseSize,
                                           &SubStatus
                                           );

    if (FAILED(Status))
    {
        ReportWinError(context, "GetMSTGT KerbRetrieveEncodedTicketMessage Status", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSTGT KerbRetrieveEncodedTicketMessage failed (1)\n");
#endif /* NODEBUG */
        goto cleanup;
    }

    if (FAILED(SubStatus))
    {
        ReportWinError(context, "GetMSTGT KerbRetrieveEncodedTicketMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSTGT KerbRetrieveEncodedTicketMessage failed (2)\n");
#endif /* NODEBUG */
        goto cleanup;
    }

    //
    // Check to make sure the new tickets we received are of a type we support
    //

    /* Check Supported Enctypes */
    if ( !enforce_tgs_enctypes ||
         krb5_is_permitted_tgs_enctype(context, NULL, pTicketResponse->Ticket.SessionKey.KeyType) ) {
        bRet = TRUE;
        goto cleanup;       // we have a valid ticket, all done
    }

    if (krb5_get_tgs_ktypes(context, NULL, &etype_list)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSTGT krb5_get_tgs_ktypes failed\n");
#endif /* NODEBUG */
        ptr = etype_list = NULL;
        etype = ENCTYPE_DES_CBC_CRC;
    } else {
        ptr = etype_list + 1;
        etype = *etype_list;
    }

    while ( etype ) {
        // Try once more but this time specify the Encryption Type
        // (This will not store the retrieved tickets in the LSA cache unless
        // 0 is supported.)
        pTicketRequest->EncryptionType = etype;
        pTicketRequest->CacheOptions = 0;
        if ( does_retrieve_ticket_cache_ticket() )
            pTicketRequest->CacheOptions |= KERB_RETRIEVE_TICKET_CACHE_TICKET;

        if ( pTicketResponse ) {
            memset(pTicketResponse,0,sizeof(KERB_RETRIEVE_TKT_RESPONSE));
            LsaFreeReturnBuffer(pTicketResponse);
            pTicketResponse = NULL;
        }

        Status = LsaCallAuthenticationPackage( LogonHandle,
                                               PackageId,
                                               pTicketRequest,
                                               RequestSize,
                                               &pTicketResponse,
                                               &ResponseSize,
                                               &SubStatus
                                               );

        if (FAILED(Status))
        {
            ReportWinError(context, "GetMSTGT KerbRetrieveEncodedTicketMessage with etype Status", TRUE, Status);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetMSTGT KerbRetrieveEncodedTicketMessage with etype failed (1)\n");
#endif /* NODEBUG */
            goto cleanup;
        }

        if (FAILED(SubStatus))
        {
            ReportWinError(context, "GetMSTGT KerbRetrieveEncodedTicketMessage with etype SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSTGT KerbRetrieveEncodedTicketMessage with etype failed (2)\n");
#endif /* NODEBUG */
            goto cleanup;
        }

        if ( pTicketResponse->Ticket.SessionKey.KeyType == etype &&
             (!enforce_tgs_enctypes ||
             krb5_is_permitted_tgs_enctype(context, NULL, pTicketResponse->Ticket.SessionKey.KeyType)) ) {
            bRet = TRUE;
            goto cleanup;       // we have a valid ticket, all done
        }

        if ( ptr ) {
            etype = *ptr++;
        } else {
            etype = 0;
        }

        // do not leak memory the lsa allocated if we have more than
        // one etype in the list
        memset(pTicketResponse,0,sizeof(KERB_RETRIEVE_TKT_RESPONSE));
        LsaFreeReturnBuffer(pTicketResponse);
        pTicketResponse = NULL;
    }

    krb5_set_error_message( context, KRB5_CC_NOTFOUND,
                            "GetMSTGT etype not found");
#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: GetMSTGT etype not found\n");
#endif /* NODEBUG */

  cleanup:
    if ( etype_list )
        krb5_free_ktypes(context, etype_list);

    if ( pTicketRequest )
        LocalFree(pTicketRequest);

    if (bRet == FALSE)
    {
        if (pTicketResponse) {
            memset(pTicketResponse,0,sizeof(KERB_RETRIEVE_TKT_RESPONSE));
            LsaFreeReturnBuffer(pTicketResponse);
            pTicketResponse = NULL;
        }
        *ticket = NULL;
        return(FALSE);
    }

    *ticket = &(pTicketResponse->Ticket);
    return(TRUE);
}

static BOOL
GetQueryTktCacheResponseW2K( HANDLE LogonHandle, ULONG PackageId,
                             krb5_context context,
                             PKERB_QUERY_TKT_CACHE_RESPONSE * ppResponse)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;

    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
    PKERB_QUERY_TKT_CACHE_RESPONSE pQueryResponse = NULL;
    ULONG ResponseSize;

    CacheRequest.MessageType = KerbQueryTicketCacheMessage;
    CacheRequest.LogonId.LowPart = 0;
    CacheRequest.LogonId.HighPart = 0;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        &CacheRequest,
        sizeof(CacheRequest),
        &pQueryResponse,
        &ResponseSize,
        &SubStatus
        );

    if ( !(FAILED(Status) || FAILED(SubStatus)) ) {
        *ppResponse = pQueryResponse;
        return TRUE;
    }

    if ( context ) {
        if (FAILED(Status))
        {
            ReportWinError(context, "GetQueryTktCacheResponseW2K KerbQueryTicketCacheMessage Status", TRUE, Status);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetQueryTktCacheResponseW2K KerbQueryTicketCacheMessage failed (1)\n");
#endif /* NODEBUG */
        }

        if (FAILED(SubStatus))
        {
            ReportWinError(context, "GetQueryTktCacheResponseW2K KerbQueryTicketCacheMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetQueryTktCacheResponseW2K KerbQueryTicketCacheMessage failed (1)\n");
#endif /* NODEBUG */
        }
    }

    return FALSE;
}

static BOOL
GetQueryTktCacheResponseXP( HANDLE LogonHandle, ULONG PackageId,
                            krb5_context context,
                            PKERB_QUERY_TKT_CACHE_EX_RESPONSE * ppResponse)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;

    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
    PKERB_QUERY_TKT_CACHE_EX_RESPONSE pQueryResponse = NULL;
    ULONG ResponseSize;

    CacheRequest.MessageType = KerbQueryTicketCacheExMessage;
    CacheRequest.LogonId.LowPart = 0;
    CacheRequest.LogonId.HighPart = 0;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        &CacheRequest,
        sizeof(CacheRequest),
        &pQueryResponse,
        &ResponseSize,
        &SubStatus
        );

    if ( !(FAILED(Status) || FAILED(SubStatus)) ) {
        *ppResponse = pQueryResponse;
        return TRUE;
    }

    if ( context ) {
        if (FAILED(Status))
        {
            ReportWinError(context, "GetQueryTktCacheResponseXP KerbQueryTicketCacheExMessage Status", TRUE, Status);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetQueryTktCacheResponseXP KerbQueryTicketCacheExMessage failed (1)\n");
#endif /* NODEBUG */
        }

        if (FAILED(SubStatus))
        {
            ReportWinError(context, "GetQueryTktCacheResponseXP KerbQueryTicketCacheExMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetQueryTktCacheResponseXP KerbQueryTicketCacheExMessage failed (2)\n");
#endif /* NODEBUG */
        }
    }

    return FALSE;
}

#ifdef HAVE_CACHE_INFO_EX2
static BOOL
GetQueryTktCacheResponseEX2( HANDLE LogonHandle, ULONG PackageId,
                             krb5_context context,
                             PKERB_QUERY_TKT_CACHE_EX2_RESPONSE * ppResponse)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;

    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
    PKERB_QUERY_TKT_CACHE_EX2_RESPONSE pQueryResponse = NULL;
    ULONG ResponseSize;

    CacheRequest.MessageType = KerbQueryTicketCacheEx2Message;
    CacheRequest.LogonId.LowPart = 0;
    CacheRequest.LogonId.HighPart = 0;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        &CacheRequest,
        sizeof(CacheRequest),
        &pQueryResponse,
        &ResponseSize,
        &SubStatus
        );

    if ( !(FAILED(Status) || FAILED(SubStatus)) ) {
        *ppResponse = pQueryResponse;
        return TRUE;
    }

    if ( context ) {
        if (FAILED(Status))
        {
            ReportWinError(context, "GetQueryTktCacheResponseEX2 KerbQueryTicketCacheEx2Message Status", TRUE, Status);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetQueryTktCacheResponseEX2 KerbQueryTicketCacheEx2Message failed (1)\n");
#endif /* NODEBUG */
        }

        if (FAILED(SubStatus))
        {
            ReportWinError(context, "GetQueryTktCacheResponseEX2 KerbQueryTicketCacheEx2Message SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: GetQueryTktCacheResponseEX2 KerbQueryTicketCacheEx2Message failed (2)\n");
#endif /* NODEBUG */
        }
    }

    return FALSE;
}
#endif /* HAVE_CACHE_INFO_EX2 */

static krb5_error_code
GetMSCacheTicketFromMITCred( HANDLE LogonHandle, ULONG PackageId,
                             krb5_context context, krb5_creds *creds,
                             PKERB_EXTERNAL_TICKET *ticket)
{
    DWORD dwError = ERROR_SUCCESS;
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    ULONG RequestSize;
    PKERB_RETRIEVE_TKT_REQUEST pTicketRequest = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
    ULONG ResponseSize;
    krb5_error_code kret;

    RequestSize = sizeof(*pTicketRequest) + MAX_MSPRINC_SIZE;

    pTicketRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LMEM_ZEROINIT, RequestSize);
    if (!pTicketRequest) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromMITCred LocalAlloc failed\n");
#endif /* NODEBUG */
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto _exit;
    }
    pTicketRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pTicketRequest->LogonId.LowPart = 0;
    pTicketRequest->LogonId.HighPart = 0;

    pTicketRequest->TargetName.Length = 0;
    pTicketRequest->TargetName.MaximumLength = MAX_MSPRINC_SIZE;
    pTicketRequest->TargetName.Buffer = (PWSTR) (pTicketRequest + 1);
    MITPrincToMSPrinc(context, creds->server, &pTicketRequest->TargetName);
    pTicketRequest->CacheOptions = 0;
    if ( does_retrieve_ticket_cache_ticket() )
        pTicketRequest->CacheOptions |= KERB_RETRIEVE_TICKET_CACHE_TICKET;
    pTicketRequest->TicketFlags = creds->ticket_flags;
    pTicketRequest->EncryptionType = creds->keyblock.enctype;

    Status = LsaCallAuthenticationPackage( LogonHandle,
                                           PackageId,
                                           pTicketRequest,
                                           RequestSize,
                                           &pTicketResponse,
                                           &ResponseSize,
                                           &SubStatus
                                           );

    LocalFree(pTicketRequest);

    if (FAILED(Status))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromMITCred KerbRetrieveEncodedTicketMessage Status", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromMITCred KerbRetrieveEncodedTicketMessage failed (1)\n");
#endif /* NODEBUG */
        dwError = LsaNtStatusToWinError(Status);
        goto _exit;
    }

    if (FAILED(SubStatus))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromMITCred KerbRetrieveEncodedTicketMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromMITCred KerbRetrieveEncodedTicketMessage failed (2)\n");
#endif /* NODEBUG */
        dwError = LsaNtStatusToWinError(SubStatus);
        goto _exit;
    }

    if (IsMSSessionKeyNull(&pTicketResponse->Ticket.SessionKey) && is_process_uac_limited()) {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromMITCred KerbRetrieveEncodedTicketMessage SubStatus", TRUE, STATUS_ACCESS_DENIED);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromMITCred KerbRetrieveEncodedTicketMessage failed (Access Denied)\n");
#endif /* NODEBUG */
        LsaFreeReturnBuffer(pTicketResponse);
        dwError = ERROR_ACCESS_DENIED;
        goto _exit;
    }

    /* otherwise return ticket */
    *ticket = &(pTicketResponse->Ticket);

  _exit:
    switch (dwError) {
    case ERROR_SUCCESS:
        kret = KRB5_OK;
        break;
    case ERROR_OUTOFMEMORY:
        kret = KRB5_FCC_INTERNAL;
        break;
    case ERROR_ACCESS_DENIED:
        kret = KRB5_FCC_PERM;
        break;
    case SEC_E_TIME_SKEW:
        kret = KRB5KRB_AP_ERR_SKEW;
        break;
    case SEC_E_NO_IP_ADDRESSES:
        kret = KRB5KRB_AP_ERR_BADADDR;
        break;
    case SEC_E_KDC_INVALID_REQUEST:
        kret = KRB5KRB_ERR_GENERIC;
        break;
    case SEC_E_UNSUPPORTED_PREAUTH:
        kret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
        break;
    case SEC_E_KDC_UNKNOWN_ETYPE:
        kret = KRB5KDC_ERR_ETYPE_NOSUPP;
        break;
    default:
        kret = KRB5_CC_NOTFOUND;
    }
    return kret;
}

static BOOL
GetMSCacheTicketFromCacheInfoW2K( HANDLE LogonHandle, ULONG PackageId,
                                  krb5_context context,
                                  PKERB_TICKET_CACHE_INFO tktinfo, PKERB_EXTERNAL_TICKET *ticket)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    ULONG RequestSize;
    PKERB_RETRIEVE_TKT_REQUEST pTicketRequest = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
    ULONG ResponseSize;

    RequestSize = sizeof(*pTicketRequest) + tktinfo->ServerName.Length;

    pTicketRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LMEM_ZEROINIT, RequestSize);
    if (!pTicketRequest) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoW2K LocalAlloc failed (1)\n");
#endif /* NODEBUG */
        return FALSE;
    }
    pTicketRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pTicketRequest->LogonId.LowPart = 0;
    pTicketRequest->LogonId.HighPart = 0;
    pTicketRequest->TargetName.Length = tktinfo->ServerName.Length;
    pTicketRequest->TargetName.MaximumLength = tktinfo->ServerName.Length;
    pTicketRequest->TargetName.Buffer = (PWSTR) (pTicketRequest + 1);
    memcpy(pTicketRequest->TargetName.Buffer,tktinfo->ServerName.Buffer, tktinfo->ServerName.Length);
    pTicketRequest->CacheOptions = 0;
    if ( does_retrieve_ticket_cache_ticket() )
        pTicketRequest->CacheOptions |= KERB_RETRIEVE_TICKET_CACHE_TICKET;
    pTicketRequest->EncryptionType = tktinfo->EncryptionType;
    pTicketRequest->TicketFlags = 0;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_forwardable )
        pTicketRequest->TicketFlags |= KDC_OPT_FORWARDABLE;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_forwarded )
        pTicketRequest->TicketFlags |= KDC_OPT_FORWARDED;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_proxiable )
        pTicketRequest->TicketFlags |= KDC_OPT_PROXIABLE;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_renewable )
        pTicketRequest->TicketFlags |= KDC_OPT_RENEWABLE;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        pTicketRequest,
        RequestSize,
        &pTicketResponse,
        &ResponseSize,
        &SubStatus
        );

    LocalFree(pTicketRequest);

    if (FAILED(Status))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromCacheInfoW2K KerbRetrieveEncodedTicketMessage Status", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoW2K KerbRetrieveEncodedTicketMessage failed (1)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    if (FAILED(SubStatus))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromCacheInfoW2K KerbRetrieveEncodedTicketMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoW2K KerbRetrieveEncodedTicketMessage failed (2)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    /* otherwise return ticket */
    *ticket = &(pTicketResponse->Ticket);

    /* set the initial flag if we were attempting to retrieve one
     * because Windows won't necessarily return the initial ticket
     * to us.
     */
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_initial )
        (*ticket)->TicketFlags |= KERB_TICKET_FLAGS_initial;

    return(TRUE);
}

static BOOL
GetMSCacheTicketFromCacheInfoXP( HANDLE LogonHandle, ULONG PackageId,
                                 krb5_context context,
                                 PKERB_TICKET_CACHE_INFO_EX tktinfo, PKERB_EXTERNAL_TICKET *ticket)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    ULONG RequestSize;
    PKERB_RETRIEVE_TKT_REQUEST pTicketRequest = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
    ULONG ResponseSize;

    RequestSize = sizeof(*pTicketRequest) + tktinfo->ServerName.Length;

    pTicketRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LMEM_ZEROINIT, RequestSize);
    if (!pTicketRequest) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoXP LocalAlloc failed\n");
#endif /* NODEBUG */
        return FALSE;
    }
    pTicketRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pTicketRequest->LogonId.LowPart = 0;
    pTicketRequest->LogonId.HighPart = 0;
    pTicketRequest->TargetName.Length = tktinfo->ServerName.Length;
    pTicketRequest->TargetName.MaximumLength = tktinfo->ServerName.Length;
    pTicketRequest->TargetName.Buffer = (PWSTR) (pTicketRequest + 1);
    memcpy(pTicketRequest->TargetName.Buffer,tktinfo->ServerName.Buffer, tktinfo->ServerName.Length);
    pTicketRequest->CacheOptions = 0;
    pTicketRequest->EncryptionType = tktinfo->EncryptionType;
    pTicketRequest->TicketFlags = 0;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_forwardable )
        pTicketRequest->TicketFlags |= KDC_OPT_FORWARDABLE;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_forwarded )
        pTicketRequest->TicketFlags |= KDC_OPT_FORWARDED;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_proxiable )
        pTicketRequest->TicketFlags |= KDC_OPT_PROXIABLE;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_renewable )
        pTicketRequest->TicketFlags |= KDC_OPT_RENEWABLE;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        pTicketRequest,
        RequestSize,
        &pTicketResponse,
        &ResponseSize,
        &SubStatus
        );

    LocalFree(pTicketRequest);

    if (FAILED(Status))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromCacheInfoXP KerbRetrieveEncodedTicketMessage Status", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoXP KerbRetrieveEncodedTicketMessage failed (1)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    if (FAILED(SubStatus))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromCacheInfoXP KerbRetrieveEncodedTicketMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoXP KerbRetrieveEncodedTicketMessage failed (2)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    /* otherwise return ticket */
    *ticket = &(pTicketResponse->Ticket);

    /* set the initial flag if we were attempting to retrieve one
     * because Windows won't necessarily return the initial ticket
     * to us.
     */
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_initial )
        (*ticket)->TicketFlags |= KERB_TICKET_FLAGS_initial;

    return(TRUE);
}

#ifdef HAVE_CACHE_INFO_EX2
static BOOL
GetMSCacheTicketFromCacheInfoEX2( HANDLE LogonHandle, ULONG PackageId,
                                  krb5_context context,
                                  PKERB_TICKET_CACHE_INFO_EX2 tktinfo, PKERB_EXTERNAL_TICKET *ticket)
{
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;
    ULONG RequestSize;
    PKERB_RETRIEVE_TKT_REQUEST pTicketRequest = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
    ULONG ResponseSize;

    RequestSize = sizeof(*pTicketRequest) + tktinfo->ServerName.Length;

    pTicketRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LMEM_ZEROINIT, RequestSize);
    if (!pTicketRequest) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoEX2 LocalAlloc failed\n");
#endif /* NODEBUG */
        return FALSE;
    }
    pTicketRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pTicketRequest->LogonId.LowPart = 0;
    pTicketRequest->LogonId.HighPart = 0;
    pTicketRequest->TargetName.Length = tktinfo->ServerName.Length;
    pTicketRequest->TargetName.MaximumLength = tktinfo->ServerName.Length;
    pTicketRequest->TargetName.Buffer = (PWSTR) (pTicketRequest + 1);
    memcpy(pTicketRequest->TargetName.Buffer,tktinfo->ServerName.Buffer, tktinfo->ServerName.Length);
    pTicketRequest->CacheOptions = KERB_RETRIEVE_TICKET_CACHE_TICKET;
    pTicketRequest->EncryptionType = tktinfo->SessionKeyType;
    pTicketRequest->TicketFlags = 0;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_forwardable )
        pTicketRequest->TicketFlags |= KDC_OPT_FORWARDABLE;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_forwarded )
        pTicketRequest->TicketFlags |= KDC_OPT_FORWARDED;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_proxiable )
        pTicketRequest->TicketFlags |= KDC_OPT_PROXIABLE;
    if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_renewable )
        pTicketRequest->TicketFlags |= KDC_OPT_RENEWABLE;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        pTicketRequest,
        RequestSize,
        &pTicketResponse,
        &ResponseSize,
        &SubStatus
        );

    LocalFree(pTicketRequest);

    if (FAILED(Status))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromCacheInfoEX2 KerbRetrieveEncodedTicketMessage Status", TRUE, Status);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoEX2 KerbRetrieveEncodedTicketMessage failed (1)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    if (FAILED(SubStatus))
    {
        if ( context )
            ReportWinError(context, "GetMSCacheTicketFromCacheInfoEX2 KerbRetrieveEncodedTicketMessage SubStatus", TRUE, SubStatus);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: GetMSCacheTicketFromCacheInfoEX2 KerbRetrieveEncodedTicketMessage failed (2)\n");
#endif /* NODEBUG */
        return FALSE;
    }

    /* otherwise return ticket */
    *ticket = &(pTicketResponse->Ticket);


    /* set the initial flag if we were attempting to retrieve one
    * because Windows won't necessarily return the initial ticket
    * to us.
    */
   if ( tktinfo->TicketFlags & KERB_TICKET_FLAGS_initial )
       (*ticket)->TicketFlags |= KERB_TICKET_FLAGS_initial;

    return(TRUE);
}
#endif /* HAVE_CACHE_INFO_EX2 */

static krb5_error_code KRB5_CALLCONV krb5_lcc_close
        (krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_lcc_destroy
        (krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_lcc_end_seq_get
        (krb5_context, krb5_ccache id, krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV krb5_lcc_generate_new
        (krb5_context, krb5_ccache *id);

static const char * KRB5_CALLCONV krb5_lcc_get_name
        (krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_lcc_get_principal
        (krb5_context, krb5_ccache id, krb5_principal *princ);

static krb5_error_code KRB5_CALLCONV krb5_lcc_initialize
        (krb5_context, krb5_ccache id, krb5_principal princ);

static krb5_error_code KRB5_CALLCONV krb5_lcc_next_cred
        (krb5_context, krb5_ccache id, krb5_cc_cursor *cursor,
	 krb5_creds *creds);

static krb5_error_code KRB5_CALLCONV krb5_lcc_remove_cred
        (krb5_context context, krb5_ccache id, krb5_flags flags,
         krb5_creds *creds);

static krb5_error_code KRB5_CALLCONV krb5_lcc_resolve
        (krb5_context, krb5_ccache *id, const char *residual);

static krb5_error_code KRB5_CALLCONV krb5_lcc_retrieve
        (krb5_context, krb5_ccache id, krb5_flags whichfields,
	 krb5_creds *mcreds, krb5_creds *creds);

static krb5_error_code KRB5_CALLCONV krb5_lcc_start_seq_get
        (krb5_context, krb5_ccache id, krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV krb5_lcc_store
        (krb5_context, krb5_ccache id, krb5_creds *creds);

static krb5_error_code KRB5_CALLCONV krb5_lcc_set_flags
        (krb5_context, krb5_ccache id, krb5_flags flags);

static krb5_error_code KRB5_CALLCONV krb5_lcc_get_flags
        (krb5_context, krb5_ccache id, krb5_flags *flags);

extern const krb5_cc_ops krb5_lcc_ops;

krb5_error_code krb5_change_cache (void);

krb5_boolean
krb5int_cc_creds_match_request(krb5_context, krb5_flags whichfields, krb5_creds *mcreds, krb5_creds *creds);

typedef struct _krb5_lcc_data {
    HANDLE LogonHandle;
    ULONG  PackageId;
    char * cc_name;
    krb5_principal princ;
    krb5_flags flags;
} krb5_lcc_data;

typedef struct _krb5_lcc_cursor {
    union {
        PKERB_QUERY_TKT_CACHE_RESPONSE w2k;
        PKERB_QUERY_TKT_CACHE_EX_RESPONSE xp;
#ifdef HAVE_CACHE_INFO_EX2
        PKERB_QUERY_TKT_CACHE_EX2_RESPONSE ex2;
#endif /* HAVE_CACHE_INFO_EX2 */
    } response;
    unsigned int index;
    PKERB_EXTERNAL_TICKET mstgt;
} krb5_lcc_cursor;


/*
 * Requires:
 * residual is ignored
 *
 * Modifies:
 * id
 *
 * Effects:
 * Acccess the MS Kerberos LSA cache in the current logon session
 * Ignore the residual.
 *
 * Returns:
 * A filled in krb5_ccache structure "id".
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 *
 * 		krb5_ccache.  id is undefined.
 * permission errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_resolve (krb5_context context, krb5_ccache *id, const char *residual)
{
    krb5_ccache lid;
    krb5_lcc_data *data;
    HANDLE LogonHandle = 0;
    ULONG  PackageId;
    KERB_EXTERNAL_TICKET *msticket;
    krb5_error_code retval = KRB5_OK;

    *id = NULL;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_resolve MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (!PackageConnectLookup(&LogonHandle, &PackageId, context)) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_resolve PackageConnectLookup failed\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }
    lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
    if (lid == NULL) {
        LsaDeregisterLogonProcess(LogonHandle);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_resolve malloc failed (1)\n");
#endif /* NODEBUG */
        return KRB5_CC_NOMEM;
    }

    lid->ops = &krb5_lcc_ops;

    lid->data = (krb5_pointer) malloc(sizeof(krb5_lcc_data));
    if (lid->data == NULL) {
        krb5_xfree(lid);
        LsaDeregisterLogonProcess(LogonHandle);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_resolve malloc failed (2)\n");
#endif /* NODEBUG */
        return KRB5_CC_NOMEM;
    }

    lid->magic = KV5M_CCACHE;
    data = (krb5_lcc_data *)lid->data;
    data->LogonHandle = LogonHandle;
    data->PackageId = PackageId;
    data->princ = 0;

    data->cc_name = (char *)malloc(strlen(residual)+1);
    if (data->cc_name == NULL) {
        krb5_xfree(lid->data);
        krb5_xfree(lid);
        LsaDeregisterLogonProcess(LogonHandle);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_resolve malloc failed (3)\n");
#endif /* NODEBUG */
        return KRB5_CC_NOMEM;
    }
    strcpy(data->cc_name, residual);

    /*
     * we must obtain a tgt from the cache in order to determine the principal
     */
    if (GetMSTGT(data->LogonHandle, data->PackageId, context, &msticket, FALSE)) {
        /* convert the ticket */
        krb5_creds creds;
        if (!MSCredToMITCred(msticket, msticket->DomainName, context, &creds)) {
            retval = KRB5_FCC_INTERNAL;
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: krb5_lcc_resolve MSCredToMITCred failed\n");
#endif /* NODEBUG */
        }
        LsaFreeReturnBuffer(msticket);

        if (retval == KRB5_OK)
            krb5_copy_principal(context, creds.client, &data->princ);
        krb5_free_cred_contents(context,&creds);

        /*
         * other routines will get errors on open, and callers must expect them,
         * if cache is non-existent/unusable
         */
        *id = lid;
    } else {
        krb5_xfree(data->cc_name);
        krb5_xfree(lid->data);
        krb5_xfree(lid);
        LsaDeregisterLogonProcess(LogonHandle);
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_resolve GetMSTGT failed\n");
#endif /* NODEBUG */
        retval = KRB5_FCC_NOFILE;
    }
    return retval;
}

/*
*  return success although we do not do anything
*  We should delete all tickets belonging to the specified principal
*/

static krb5_error_code KRB5_CALLCONV
krb5_lcc_initialize(krb5_context context, krb5_ccache id, krb5_principal princ)
{
    krb5_cc_cursor cursor;
    krb5_error_code code;
    krb5_creds cred;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_initialize MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_initialize no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    code = krb5_cc_start_seq_get(context, id, &cursor);
    if (code) {
        if (code == KRB5_CC_NOTFOUND)
            return KRB5_OK;
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_initialize krb5_cc_start_seq_get failed\n");
#endif /* NODEBUG */
        return code;
    }

    while ( !(code = krb5_cc_next_cred(context, id, &cursor, &cred)) )
    {
        if ( krb5_principal_compare(context, princ, cred.client) ) {
            code = krb5_lcc_remove_cred(context, id, 0, &cred);
        }
        krb5_free_cred_contents(context, &cred);
    }

    if (code == KRB5_CC_END || code == KRB5_CC_NOTFOUND)
    {
        krb5_cc_end_seq_get(context, id, &cursor);
        return KRB5_OK;
    }
#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: krb5_lcc_initialize krb5_cc_next_cred failed\n");
#endif /* NODEBUG */
    return code;
}

/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the microsoft lsa cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_close(krb5_context context, krb5_ccache id)
{
    register int closeval = KRB5_OK;
    register krb5_lcc_data *data;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_close MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id) {
        data = (krb5_lcc_data *) id->data;

        if (data) {
            free(data->cc_name);
            LsaDeregisterLogonProcess(data->LogonHandle);
            krb5_xfree(data);
        }
        krb5_xfree(id);
    }
    return closeval;
}

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_destroy(krb5_context context, krb5_ccache id)
{
    register krb5_lcc_data *data;
    BOOL bSuccess;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_destroy MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id) {
        data = (krb5_lcc_data *) id->data;

        bSuccess = PurgeAllTickets(data->LogonHandle, data->PackageId, context);
        if (bSuccess)
            return KRB5_OK;

        // setmsg
    }
#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: krb5_lcc_destroy PurgeAllTickets failed\n");
#endif /* NODEBUG */
    return KRB5_FCC_INTERNAL;
}

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns a krb5_cc_cursor to be used with krb5_lcc_next_cred and
 * krb5_lcc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_lcc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * KRB5_FCC_INTERNAL - system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_start_seq_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
    krb5_lcc_cursor *lcursor;
    krb5_lcc_data *data;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_start_seq_get MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_start_seq_get no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    lcursor = (krb5_lcc_cursor *) malloc(sizeof(krb5_lcc_cursor));
    if (lcursor == NULL) {
        *cursor = 0;
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_start_seq_get malloc failed\n");
#endif /* NODEBUG */
        return KRB5_CC_NOMEM;
    }

    data = (krb5_lcc_data *)id->data;

    /*
     * obtain a tgt to refresh the ccache in case the ticket is expired
     */
    if (!GetMSTGT(data->LogonHandle, data->PackageId, context, &lcursor->mstgt, TRUE)) {
        free(lcursor);
        *cursor = 0;
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_start_seq_get GetMSTGT failed\n");
#endif /* NODEBUG */
        return KRB5_CC_NOTFOUND;
    }

#ifdef HAVE_CACHE_INFO_EX2
    if ( does_query_ticket_cache_ex2() ) {
        if ( !GetQueryTktCacheResponseEX2(data->LogonHandle, data->PackageId, context, &lcursor->response.ex2) ) {
            LsaFreeReturnBuffer(lcursor->mstgt);
            free(lcursor);
            *cursor = 0;
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: krb5_lcc_start_seq_get GetQueryTktCacheResponseEX2 failed\n");
#endif /* NODEBUG */
            return KRB5_FCC_INTERNAL;
        }
    } else
#endif /* HAVE_CACHE_INFO_EX2 */
    if ( is_windows_xp() ) {
        if ( !GetQueryTktCacheResponseXP(data->LogonHandle, data->PackageId, context, &lcursor->response.xp) ) {
            LsaFreeReturnBuffer(lcursor->mstgt);
            free(lcursor);
            *cursor = 0;
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: krb5_lcc_start_seq_get GetQueryTktCacheResponseXP failed\n");
#endif /* NODEBUG */
            return KRB5_FCC_INTERNAL;
        }
    } else {
        if ( !GetQueryTktCacheResponseW2K(data->LogonHandle, data->PackageId, context, &lcursor->response.w2k) ) {
            LsaFreeReturnBuffer(lcursor->mstgt);
            free(lcursor);
            *cursor = 0;
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: krb5_lcc_start_seq_get GetQueryTktCacheResponseW2K failed\n");
#endif /* NODEBUG */
            return KRB5_FCC_INTERNAL;
        }
    }
    lcursor->index = 0;
    *cursor = (krb5_cc_cursor) lcursor;
    return KRB5_OK;
}


/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_lcc_start_seq_get.
 *
 * Modifes:
 * cursor
 *
 * Effects:
 * Fills in creds with the TGT obtained from the MS LSA
 *
 * The cursor is updated to indicate TGT retrieval
 *
 * Errors:
 * KRB5_CC_END
 * KRB5_FCC_INTERNAL - system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_next_cred(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor, krb5_creds *creds)
{
    krb5_lcc_cursor *lcursor;
    krb5_lcc_data *data;
    KERB_EXTERNAL_TICKET *msticket;
    krb5_error_code  retval = KRB5_OK;

    if (id == NULL || cursor == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_next_cred no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    lcursor = (krb5_lcc_cursor *) *cursor;
    if (lcursor == NULL)
        return KRB5_CC_END;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_next_cred MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    data = (krb5_lcc_data *)id->data;

    while ( TRUE ) {
        retval = KRB5_OK;

#ifdef HAVE_CACHE_INFO_EX2
        if ( does_query_ticket_cache_ex2() ) {
            if ( lcursor->index >= lcursor->response.ex2->CountOfTickets ) {
                if (retval == KRB5_OK)
                    return KRB5_CC_END;
                else {
                    LsaFreeReturnBuffer(lcursor->mstgt);
                    LsaFreeReturnBuffer(lcursor->response.ex2);
                    free(*cursor);
                    *cursor = 0;
                    return KRB5_CC_END;
                }
            }

            if ( data->flags & KRB5_TC_NOTICKET ) {
                if (!CacheInfoEx2ToMITCred( &lcursor->response.ex2->Tickets[lcursor->index++],
                                            context, creds)) {
                    continue;
                }
                return KRB5_OK;
            } else {
                if (!GetMSCacheTicketFromCacheInfoEX2( data->LogonHandle, data->PackageId, context,
                                                       &lcursor->response.ex2->Tickets[lcursor->index++],&msticket)) {
                    continue;
                }
            }
        } else
#endif /* HAVE_CACHE_INFO_EX2 */
        if ( is_windows_xp() ) {
            if ( lcursor->index >= lcursor->response.xp->CountOfTickets ) {
                if (retval == KRB5_OK)
                    return KRB5_CC_END;
                else {
                    LsaFreeReturnBuffer(lcursor->mstgt);
                    LsaFreeReturnBuffer(lcursor->response.xp);
                    free(*cursor);
                    *cursor = 0;
                    return KRB5_CC_END;
                }
            }

            if (!GetMSCacheTicketFromCacheInfoXP( data->LogonHandle, data->PackageId, context,
                                                  &lcursor->response.xp->Tickets[lcursor->index++],&msticket)) {
                continue;
            }
        } else {
            if ( lcursor->index >= lcursor->response.w2k->CountOfTickets ) {
                if (retval == KRB5_OK)
                    return KRB5_CC_END;
                else {
                    LsaFreeReturnBuffer(lcursor->mstgt);
                    LsaFreeReturnBuffer(lcursor->response.w2k);
                    free(*cursor);
                    *cursor = 0;
                    return KRB5_CC_END;
                }
            }

            if (!GetMSCacheTicketFromCacheInfoW2K( data->LogonHandle, data->PackageId, context,
                                                   &lcursor->response.w2k->Tickets[lcursor->index++],&msticket)) {
                continue;
            }
        }

        /* Don't return tickets with NULL Session Keys */
        if ( IsMSSessionKeyNull(&msticket->SessionKey) ) {
            LsaFreeReturnBuffer(msticket);
            continue;
        }

        /* convert the ticket */
#ifdef HAVE_CACHE_INFO_EX2
        if ( does_query_ticket_cache_ex2() ) {
            if (!MSCredToMITCred(msticket, lcursor->response.ex2->Tickets[lcursor->index-1].ClientRealm, context, creds)) {
                retval = KRB5_FCC_INTERNAL;
#ifndef NODEBUG
                OutputDebugStringA("cc_mslsa: krb5_lcc_next_cred MSCredToMITCred failed (1)\n");
#endif /* NODEBUG */
            }
        } else
#endif /* HAVE_CACHE_INFO_EX2 */
        if ( is_windows_xp() ) {
            if (!MSCredToMITCred(msticket, lcursor->response.xp->Tickets[lcursor->index-1].ClientRealm, context, creds)) {
                retval = KRB5_FCC_INTERNAL;
#ifndef NODEBUG
                OutputDebugStringA("cc_mslsa: krb5_lcc_next_cred MSCredToMITCred failed (2)\n");
#endif /* NODEBUG */
            }
        } else {
            if (!MSCredToMITCred(msticket, lcursor->mstgt->DomainName, context, creds)) {
                retval = KRB5_FCC_INTERNAL;
#ifndef NODEBUG
                OutputDebugStringA("cc_mslsa: krb5_lcc_next_cred MSCredToMITCred failed (3)\n");
#endif /* NODEBUG */
            }
        }
        LsaFreeReturnBuffer(msticket);
        if (retval == KRB5_OK)
            break;
    }

    return retval;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_lcc_start_seq_get.
 *
 * Modifies:
 * id, cursor
 *
 * Effects:
 * Finishes sequential processing of the file credentials ccache id,
 * and invalidates the cursor (it must never be used after this call).
 */
/* ARGSUSED */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_end_seq_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
    krb5_lcc_cursor *lcursor;

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_end_seq_get no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    if (cursor == NULL)
        return KRB5_OK;

    lcursor = (krb5_lcc_cursor *) *cursor;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_end_seq_get MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if ( lcursor ) {
        LsaFreeReturnBuffer(lcursor->mstgt);
#ifdef HAVE_CACHE_INFO_EX2
        if ( does_query_ticket_cache_ex2() )
            LsaFreeReturnBuffer(lcursor->response.ex2);
        else
#endif /* HAVE_CACHE_INFO_EX2 */
        if ( is_windows_xp() )
            LsaFreeReturnBuffer(lcursor->response.xp);
        else
            LsaFreeReturnBuffer(lcursor->response.w2k);
        free(*cursor);
    }
    *cursor = 0;

    return KRB5_OK;
}


/*
 * Errors:
 * KRB5_CC_READONLY - not supported
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_generate_new (krb5_context context, krb5_ccache *id)
{
    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_generate_new MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: krb5_lcc_generate_new readonly cache\n");
#endif /* NODEBUG */
    return KRB5_CC_READONLY;
}

/*
 * Requires:
 * id is a ms lsa credential cache
 *
 * Returns:
 *   The ccname specified during the krb5_lcc_resolve call
 */
static const char * KRB5_CALLCONV
krb5_lcc_get_name (krb5_context context, krb5_ccache id)
{

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
        return "";
    }

    if ( !id )
        return "";

    return (char *) ((krb5_lcc_data *) id->data)->cc_name;
}

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_lcc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOT_KTYPE
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_get_principal(krb5_context context, krb5_ccache id, krb5_principal *princ)
{
    krb5_lcc_data *data;

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_get_principal no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_get_principal MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    data = (krb5_lcc_data *)id->data;

    /* obtain principal */
    if (data->princ)
        return krb5_copy_principal(context, data->princ, princ);
    else {
        /*
         * we must obtain a tgt from the cache in order to determine the principal
         */
        KERB_EXTERNAL_TICKET *msticket;
        if (GetMSTGT(data->LogonHandle, data->PackageId, context, &msticket, FALSE)) {
            /* convert the ticket */
            krb5_creds creds;
            if (!MSCredToMITCred(msticket, msticket->DomainName, context, &creds))
            {
                LsaFreeReturnBuffer(msticket);
#ifndef NODEBUG
                OutputDebugStringA("cc_mslsa: krb5_lcc_get_principal MSCredToMITCred failed\n");
#endif /* NODEBUG */
                return KRB5_FCC_INTERNAL;
            }
            LsaFreeReturnBuffer(msticket);

            krb5_copy_principal(context, creds.client, &data->princ);
            krb5_free_cred_contents(context,&creds);
            return krb5_copy_principal(context, data->princ, princ);
        }
    }
#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: krb5_lcc_get_principal not found\n");
#endif /* NODEBUG */
    return KRB5_CC_NOTFOUND;
}


static krb5_error_code KRB5_CALLCONV
krb5_lcc_retrieve(krb5_context context, krb5_ccache id, krb5_flags whichfields,
                  krb5_creds *mcreds, krb5_creds *creds)
{
    krb5_error_code kret = KRB5_OK;
    krb5_lcc_data *data;
    KERB_EXTERNAL_TICKET *msticket = 0, *mstgt = 0, *mstmp = 0;
    krb5_creds * mcreds_noflags = 0;
    krb5_creds   fetchcreds;
    DWORD dwError;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve MSLSA not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    data = (krb5_lcc_data *)id->data;

    /* first try to find out if we have an existing ticket which meets the requirements */
    kret = krb5_cc_retrieve_cred_default (context, id, whichfields, mcreds, creds);
    if ( !kret )
        return KRB5_OK;

    /* if not, we must try to get a ticket without specifying any flags or etypes */
    kret = krb5_copy_creds(context, mcreds, &mcreds_noflags);
    if (kret) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve krb5_copy_creds failed\n");
#endif /* NODEBUG */
        goto cleanup;
    }
    mcreds_noflags->ticket_flags = 0;
    mcreds_noflags->keyblock.enctype = 0;

    kret = GetMSCacheTicketFromMITCred(data->LogonHandle, data->PackageId, context, mcreds_noflags, &msticket);
    if ( kret ) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve GetMSCacheTicketFromMITCred failed (1)\n");
#endif /* NODEBUG */
        goto cleanup;
    }

    /* Free this ticket as it will not be used */
    if ( msticket ) {
        LsaFreeReturnBuffer(msticket);
        msticket = 0;
    }

    /* try again to find out if we have an existing ticket which meets the requirements */
    kret = krb5_cc_retrieve_cred_default (context, id, whichfields, mcreds, creds);
    if ( !kret ) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve krb5_cc_retrieve_cred_default\n");
#endif /* NODEBUG */
        goto cleanup;
    }
    /* if not, obtain a ticket using the request flags and enctype even though it may not
     * be stored in the LSA cache for future use.
     */
    kret = GetMSCacheTicketFromMITCred(data->LogonHandle, data->PackageId, context, mcreds, &msticket);
    if ( kret ) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve GetMSCacheTicketFromMITCred failed (2)\n");
#endif /* NODEBUG */
        goto cleanup;
    }

    memset(&fetchcreds, 0, sizeof(krb5_creds));

    /* convert the ticket */
    if ( !is_windows_xp() || !does_retrieve_ticket_cache_ticket() ) {
        if ( PreserveInitialTicketIdentity() )
            GetMSTGT(data->LogonHandle, data->PackageId, context, &mstgt, FALSE);

        if (!MSCredToMITCred(msticket, mstgt ? mstgt->DomainName : msticket->DomainName, context, &fetchcreds))
        {
            kret = KRB5_FCC_INTERNAL;
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve MSCredToMITCred failed (1)\n");
#endif /* NODEBUG */
            goto cleanup;
        }
    } else {
        /* We can obtain the correct client realm for a ticket by walking the
         * cache contents until we find the matching service ticket.
         */
        PKERB_QUERY_TKT_CACHE_EX_RESPONSE pResponse = 0;
        unsigned int i;

        if (!GetQueryTktCacheResponseXP( data->LogonHandle, data->PackageId, context, &pResponse)) {
            kret = KRB5_FCC_INTERNAL;
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve GetQueryTktCacheResponseXP failed\n");
#endif /* NODEBUG */
            goto cleanup;
        }

        for ( i=0; i<pResponse->CountOfTickets; i++ ) {
            if (!GetMSCacheTicketFromCacheInfoXP( data->LogonHandle, data->PackageId, context,
                                                  &pResponse->Tickets[i],&mstmp)) {
                continue;
            }

            if ( KerbExternalTicketMatch(msticket,mstmp) )
                break;

            LsaFreeReturnBuffer(mstmp);
            mstmp = 0;
        }

        if (!MSCredToMITCred(msticket, mstmp ? pResponse->Tickets[i].ClientRealm : msticket->DomainName, context, &fetchcreds))
        {
            LsaFreeReturnBuffer(pResponse);
            kret = KRB5_FCC_INTERNAL;
#ifndef NODEBUG
            OutputDebugStringA("cc_mslsa: krb5_lcc_retrieve MSCredToMITCred failed (2)\n");
#endif /* NODEBUG */
            goto cleanup;
        }
        LsaFreeReturnBuffer(pResponse);
    }


    /* check to see if this ticket matches the request using logic from
     * krb5_cc_retrieve_cred_default()
     */
    if ( krb5int_cc_creds_match_request(context, whichfields, mcreds, &fetchcreds) ) {
        *creds = fetchcreds;
        kret = KRB5_OK;
    } else {
        krb5_free_cred_contents(context, &fetchcreds);
        kret = KRB5_CC_NOTFOUND;
    }

  cleanup:
    if ( mstmp )
        LsaFreeReturnBuffer(mstmp);
    if ( mstgt )
        LsaFreeReturnBuffer(mstgt);
    if ( msticket )
        LsaFreeReturnBuffer(msticket);
    if ( mcreds_noflags )
        krb5_free_creds(context, mcreds_noflags);
    return kret;
}


/*
 * We can't write to the MS LSA cache.  So we request the cache to obtain a ticket for the same
 * principal in the hope that next time the application requires a ticket for the service it
 * is attempt to store, the retrieved ticket will be good enough.
 *
 * Errors:
 * KRB5_CC_READONLY - not supported
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_store(krb5_context context, krb5_ccache id, krb5_creds *creds)
{
    krb5_error_code kret = KRB5_OK;
    krb5_lcc_data *data;
    KERB_EXTERNAL_TICKET *msticket = 0, *msticket2 = 0;
    krb5_creds * creds_noflags = 0;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_store MSLSA cache not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_store no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    data = (krb5_lcc_data *)id->data;

#ifdef KERB_SUBMIT_TICKET
    /* we can use the new KerbSubmitTicketMessage to store the ticket */
    if (KerbSubmitTicket( data->LogonHandle, data->PackageId, context, creds ))
        return KRB5_OK;
#endif /* KERB_SUBMIT_TICKET */

    /* If not, lets try to obtain a matching ticket from the KDC */
    if ( creds->ticket_flags != 0 && creds->keyblock.enctype != 0 ) {
        /* if not, we must try to get a ticket without specifying any flags or etypes */
        kret = krb5_copy_creds(context, creds, &creds_noflags);
        if (kret == 0) {
            creds_noflags->ticket_flags = 0;
            creds_noflags->keyblock.enctype = 0;

            GetMSCacheTicketFromMITCred( data->LogonHandle, data->PackageId, context, creds_noflags, &msticket2);
            krb5_free_creds(context, creds_noflags);
        }
    }

    GetMSCacheTicketFromMITCred( data->LogonHandle, data->PackageId, context, creds, &msticket);
    if (msticket || msticket2) {
        if (msticket)
            LsaFreeReturnBuffer(msticket);
        if (msticket2)
            LsaFreeReturnBuffer(msticket2);
        return KRB5_OK;
    }
#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: krb5_lcc_store readonly\n");
#endif /* NODEBUG */
    return KRB5_CC_READONLY;
}

/*
 * Individual credentials can be implemented differently depending
 * on the operating system version.  (undocumented.)
 *
 * Errors:
 *    KRB5_CC_READONLY:
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_remove_cred(krb5_context context, krb5_ccache id, krb5_flags flags,
                     krb5_creds *creds)
{
    krb5_lcc_data *data;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_remove_cred MSLSA not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_remove_cred no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    data = (krb5_lcc_data *)id->data;

    if (!is_windows_xp()) {
        if ( PurgeTicket2000( data->LogonHandle, data->PackageId, context, creds) )
            return KRB5_OK;
    } else {
        if ( PurgeTicketXP( data->LogonHandle, data->PackageId, context, flags, creds) )
            return KRB5_OK;
    }

#ifndef NODEBUG
    OutputDebugStringA("cc_mslsa: krb5_lcc_store readonly\n");
#endif /* NODEBUG */
    return KRB5_CC_READONLY;
}


/*
 * Effects:
 *   Set
 */
static krb5_error_code KRB5_CALLCONV
krb5_lcc_set_flags(krb5_context context, krb5_ccache id, krb5_flags flags)
{
    krb5_lcc_data *data;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_set_flags MSLSA not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    if (id == NULL) {
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_set_flags no cache handle\n");
#endif /* NODEBUG */
        return KRB5_FCC_INTERNAL;
    }
    data = (krb5_lcc_data *)id->data;

    data->flags = flags;
    return KRB5_OK;
}

static krb5_error_code KRB5_CALLCONV
krb5_lcc_get_flags(krb5_context context, krb5_ccache id, krb5_flags *flags)
{
    krb5_lcc_data *data = (krb5_lcc_data *)id->data;

    if (!is_windows_2000() || is_broken_wow64()) {
        krb5_set_error_message( context, KRB5_FCC_NOFILE,
                                "MSLSA cache not supported");
#ifndef NODEBUG
        OutputDebugStringA("cc_mslsa: krb5_lcc_get_flags MSLSA not supported\n");
#endif /* NODEBUG */
        return KRB5_FCC_NOFILE;
    }

    *flags = data->flags;
    return KRB5_OK;
}

const krb5_cc_ops krb5_lcc_ops = {
     0,
     "MSLSA",
     krb5_lcc_get_name,
     krb5_lcc_resolve,
     krb5_lcc_generate_new,
     krb5_lcc_initialize,
     krb5_lcc_destroy,
     krb5_lcc_close,
     krb5_lcc_store,
     krb5_lcc_retrieve,
     krb5_lcc_get_principal,
     krb5_lcc_start_seq_get,
     krb5_lcc_next_cred,
     krb5_lcc_end_seq_get,
     krb5_lcc_remove_cred,
     krb5_lcc_set_flags,
     krb5_lcc_get_flags,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL,
};
#endif /* _WIN32 */
