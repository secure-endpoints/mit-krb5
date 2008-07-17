/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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
 */

#ifndef KIM_OS_PRIVATE_H
#define KIM_OS_PRIVATE_H

#include <CoreFoundation/CoreFoundation.h>
#include "kim_private.h"


CFStringEncoding kim_os_string_get_encoding (void);

CFStringRef kim_os_string_get_cfstring_for_key_and_dictionary (CFStringRef in_key,
                                                               CFBundleRef in_bundle);

CFStringRef kim_os_string_get_cfstring_for_key (kim_string in_key_string);

kim_error kim_os_string_create_from_cfstring (kim_string *out_string,
                                                CFStringRef   in_cfstring);

kim_error kim_os_string_create_for_key (kim_string *out_string,
                                          kim_string  in_key_string);

kim_error kim_os_string_get_cfstring (kim_string  in_string,
                                        CFStringRef  *out_cfstring);

kim_error kim_os_string_compare_to_cfstring (kim_string      in_string,
                                               CFStringRef       in_compare_to_cfstring,
                                               kim_comparison *out_comparison);

#endif /* KIM_PRIVATE_H */
