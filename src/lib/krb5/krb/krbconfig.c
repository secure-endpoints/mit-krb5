/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Configuration variables for libkrb.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_krbconfig_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

krb5_deltat krb5_clockskew = 5 * 60;	/* five minutes */
