/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: See AUTHORS file in top-level directory.
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

#ifndef __LASSO_SAMLP_STATUS_CODE_H__
#define __LASSO_SAMLP_STATUS_CODE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_SAMLP_STATUS_CODE (lasso_samlp_status_code_get_type())
#define LASSO_SAMLP_STATUS_CODE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP_STATUS_CODE, LassoSamlpStatusCode))
#define LASSO_SAMLP_STATUS_CODE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP_STATUS_CODE, LassoSamlpStatusCodeClass))
#define LASSO_IS_SAMLP_STATUS_CODE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP_STATUS_CODE))
#define LASSO_IS_SAMLP_STATUS_CODE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP_STATUS_CODE))
#define LASSO_SAMLP_STATUS_CODE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP_STATUS_CODE, LassoSamlpStatusCodeClass)) 

typedef struct _LassoSamlpStatusCode LassoSamlpStatusCode;
typedef struct _LassoSamlpStatusCodeClass LassoSamlpStatusCodeClass;

struct _LassoSamlpStatusCode {
	LassoNode parent;
	
	/*< public >*/
	/* <element ref="samlp:StatusCode" minOccurs="0"/> */
	LassoSamlpStatusCode *StatusCode;
	/* <attribute name="Value" type="QName" use="required"/> */
	char *Value;
};

struct _LassoSamlpStatusCodeClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_samlp_status_code_get_type(void);
LASSO_EXPORT LassoSamlpStatusCode* lasso_samlp_status_code_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP_STATUS_CODE_H__ */
