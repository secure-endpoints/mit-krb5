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

#ifndef CCAPI_CREDENTIALS_ITERATOR_H
#define CCAPI_CREDENTIALS_ITERATOR_H

#include "cci_common.h"

cc_int32 cci_credentials_iterator_new (cc_credentials_iterator_t *out_credentials_iterator,
                                       cci_identifier_t           in_identifier);

cc_int32 cci_credentials_iterator_write (cc_credentials_iterator_t in_credentials_iterator,
                                         cci_stream_t              in_stream);

cc_int32 ccapi_credentials_iterator_release (cc_credentials_iterator_t io_credentials_iterator);

cc_int32 ccapi_credentials_iterator_next (cc_credentials_iterator_t  in_credentials_iterator,
                                          cc_credentials_t          *out_credentials);

cc_int32 ccapi_credentials_iterator_clone (cc_credentials_iterator_t  in_credentials_iterator,
                                           cc_credentials_iterator_t *out_credentials_iterator);

#endif /* CCAPI_CREDENTIALS_ITERATOR_H */
