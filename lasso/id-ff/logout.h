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

#ifndef __LASSO_LOGOUT_H__
#define __LASSO_LOGOUT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/environs/profile_context.h>

#include <lasso/protocols/logout_request.h>
#include <lasso/protocols/logout_response.h>

#define LASSO_TYPE_LOGOUT (lasso_logout_get_type())
#define LASSO_LOGOUT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGOUT, LassoLogout))
#define LASSO_LOGOUT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LOGOUT, LassoLogoutClass))
#define LASSO_IS_LOGOUT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGOUT))
#define LASSO_IS_LOGOUT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGOUT))
#define LASSO_LOGOUT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LOGOUT, LassoLogoutClass)) 

typedef struct _LassoLogout LassoLogout;
typedef struct _LassoLogoutClass LassoLogoutClass;
typedef struct _LassoLogoutPrivate LassoLogoutPrivate;

struct _LassoLogout {
  LassoProfileContext parent;
  
  /*< public >*/
  LassoNode *first_request;
  LassoNode *first_response;
  gchar     *first_remote_providerID;

  /*< private >*/
  LassoLogoutPrivate *private;
};

struct _LassoLogoutClass {
  LassoNodeClass parent;

};

LASSO_EXPORT GType        lasso_logout_get_type                (void);

LASSO_EXPORT LassoLogout* lasso_logout_new                     (lassoProviderTypes  provider_type,
								LassoServer        *server,
								LassoUser          *user);
 
LASSO_EXPORT gint         lasso_logout_build_request_msg       (LassoLogout *logout);

LASSO_EXPORT gint         lasso_logout_build_response_msg      (LassoLogout *logout);

LASSO_EXPORT void         lasso_logout_destroy                 (LassoLogout *logout);

LASSO_EXPORT gchar*       lasso_logout_get_next_providerID     (LassoLogout *logout);

LASSO_EXPORT gint         lasso_logout_init_request            (LassoLogout *logout,
								gchar       *remote_providerID);

LASSO_EXPORT gint         lasso_logout_load_user_dump          (LassoLogout *logout,
								gchar       *user_dump);

LASSO_EXPORT gint         lasso_logout_load_request_msg        (LassoLogout     *logout,
								gchar           *request_msg,
								lassoHttpMethods request_method);

LASSO_EXPORT gint         lasso_logout_process_request         (LassoLogout *logout);

LASSO_EXPORT gint         lasso_logout_process_request_msg     (LassoLogout      *logout,
								gchar            *request_msg,
								lassoHttpMethods  request_method);

LASSO_EXPORT gint         lasso_logout_process_response_msg    (LassoLogout      *logout,
								gchar            *response_msg,
								lassoHttpMethods  response_method);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LOGOUT_H__ */
