#ifdef UnifdefRan
/* WARNING: this file is automatically generated; do not edit! */
#endif
/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Configuration definition file.
 */


#ifndef KRB5_CONFIG__
#define KRB5_CONFIG__

#ifdef HasPosixTermiosTrue
#define POSIX_TERMIOS
#endif

#ifdef HasPosixFileLocksTrue
#define POSIX_FILE_LOCKS
#endif

#ifdef HasPosixTypesTrue
#define POSIX_TYPES
#endif

#ifdef HasVoidSignalReturnTrue
#define POSIX_SIGTYPE
#define krb5_sigtype void
#else
typedef int krb5_sigtype;
#endif

#ifdef HasStringHTrue
#define USE_STRING_H
#endif

#ifndef HasStdlibHTrue
#define NO_STDLIB_H
#endif

#ifdef UseNarrowPrototypes
#define NARROW_PROTOTYPES
#endif

#ifdef Bitsize32
#ifdef Bitsize64
 error: only one of BitsizeNN, please.
#endif
#ifdef Bitsize16
 error: only one of BitsizeNN, please.
#endif
#define BITS32
#endif

#ifdef Bitsize16
#ifdef Bitsize64
 error: only one of BitsizeNN, please.
#endif
#ifdef Bitsize32
 error: only one of BitsizeNN, please.
#endif
#define BITS16
#endif

#ifdef Bitsize64
#ifdef Bitsize32
 error: only one of BitsizeNN, please.
#endif
#ifdef Bitsize16
 error: only one of BitsizeNN, please.
#endif
#define BITS64
#endif

/* XXX these should be parameterized soon... */
#define PROVIDE_DES_CBC_CRC
#define PROVIDE_CRC32
#define PROVIDE_DES_CBC_CKSUM
#define PROVIDE_RSA_MD4

#define DEFAULT_PWD_STRING1 "Enter password:"
#define DEFAULT_PWD_STRING2 "Re-enter password for verification:"

#define	KRB5_KDB_MAX_LIFE	(60*60*24) /* one day */
#define	KRB5_KDB_MAX_RLIFE	(60*60*24*7) /* one week */
#define	KRB5_KDB_EXPIRATION	2145830400 /* Thu Jan  1 00:00:00 2038 UTC */

#endif /* KRB5_CONFIG__ */

