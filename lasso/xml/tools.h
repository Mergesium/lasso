/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_TOOLS_H__
#define __LASSO_TOOLS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <glib-object.h>

#include <libxml/tree.h>
#include <xmlsec/crypto.h>

#include <string.h>

#include <lasso/export.h>
#include <lasso/xml/debug.h>

typedef enum {
  LASSO_SIGNATURE_METHOD_RSA_SHA1 = 1,
  LASSO_SIGNATURE_METHOD_DSA_SHA1
} lassoSignatureMethod;

typedef enum {
  LASSO_PEM_FILE_TYPE_UNKNOWN = 0,
  LASSO_PEM_FILE_TYPE_PUB_KEY,
  LASSO_PEM_FILE_TYPE_PRIVATE_KEY,
  LASSO_PEM_FILE_TYPE_CERT
} lassoPemFileType;

LASSO_EXPORT xmlChar*          lasso_build_random_sequence                (guint8 size);

LASSO_EXPORT xmlChar*          lasso_build_unique_id                      (guint8 size);

LASSO_EXPORT xmlChar*          lasso_g_ptr_array_index                    (GPtrArray *a,
									   guint      i);

LASSO_EXPORT gchar*            lasso_get_current_time                     (void);

LASSO_EXPORT lassoPemFileType  lasso_get_pem_file_type                    (const gchar *pem_file);

LASSO_EXPORT xmlSecKeyPtr      lasso_get_public_key_from_pem_cert_file    (const gchar *pem_cert_file);

LASSO_EXPORT xmlSecKeysMngrPtr lasso_load_certs_from_pem_certs_chain_file (const gchar* pem_certs_chain_file);

LASSO_EXPORT xmlChar* lasso_query_sign(xmlChar *query,
		lassoSignatureMethod sign_method, const char *private_key_file);

LASSO_EXPORT int               lasso_query_verify_signature               (const gchar   *query,
									   const xmlChar *sender_public_key_file);

LASSO_EXPORT xmlChar*          lasso_sha1                                 (xmlChar *str);

char** urlencoded_to_strings(const char *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_TOOLS_H__ */
