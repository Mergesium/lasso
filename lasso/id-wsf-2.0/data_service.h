/* $Id: idwsf2_data_service.h 2736 2007-05-30 17:59:38Z dlaniel $ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
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

#ifndef __LASSO_IDWSF2_DATA_SERVICE_H__
#define __LASSO_IDWSF2_DATA_SERVICE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/id-wsf-2.0/wsf2_profile.h>

#include <lasso/xml/ws/wsa_endpoint_reference.h>

#include <lasso/xml/xml.h>

#define LASSO_TYPE_IDWSF2_DATA_SERVICE (lasso_idwsf2_data_service_get_type())
#define LASSO_IDWSF2_DATA_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
       LASSO_TYPE_IDWSF2_DATA_SERVICE, LassoIdWsf2DataService))
#define LASSO_IDWSF2_DATA_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
       LASSO_TYPE_IDWSF2_DATA_SERVICE, LassoIdWsf2DataServiceClass))
#define LASSO_IS_IDWSF2_DATA_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
       LASSO_TYPE_IDWSF2_DATA_SERVICE))
#define LASSO_IS_IDWSF2_DATA_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
       LASSO_TYPE_IDWSF2_DATA_SERVICE))
#define LASSO_IDWSF2_DATA_SERVICE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
       LASSO_TYPE_IDWSF2_DATA_SERVICE, LassoIdWsf2DataServiceClass)) 

typedef struct _LassoIdWsf2DataService LassoIdWsf2DataService;
typedef struct _LassoIdWsf2DataServiceClass LassoIdWsf2DataServiceClass;
typedef struct _LassoIdWsf2DataServicePrivate LassoIdWsf2DataServicePrivate;

struct _LassoIdWsf2DataService {
	LassoWsf2Profile parent;

	/*< public >*/
	xmlNode *data;

/* 	gchar *provider_id; */
/* 	gchar *abstract_description; */

	/*< private >*/
	LassoIdWsf2DataServicePrivate *private_data;
};

struct _LassoIdWsf2DataServiceClass {
	LassoWsf2ProfileClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_data_service_get_type(void);

LASSO_EXPORT LassoIdWsf2DataService* lasso_idwsf2_data_service_new();

LASSO_EXPORT LassoIdWsf2DataService* lasso_idwsf2_data_service_new_full(LassoServer *server,
		LassoWsAddrEndpointReference *epr);

/* LASSO_EXPORT gint lasso_idwsf2_data_service_init_query(LassoIdWsf2DataService *service); */

/* LASSO_EXPORT LassoDstQueryItem* lasso_idwsf2_data_service_add_query_item(LassoIdWsf2DataService *service, */
/* 		const char *select, const char *item_id); */

/* LASSO_EXPORT gint lasso_idwsf2_data_service_process_query_msg(LassoIdWsf2DataService *service, */
/* 		const char *message); */

/* LASSO_EXPORT gint lasso_idwsf2_data_service_build_response_msg(LassoIdWsf2DataService *service); */

/* LASSO_EXPORT gint lasso_idwsf2_data_service_process_query_response_msg(LassoIdWsf2DataService *service, */
/* 		const char *message); */

/* LASSO_EXPORT xmlNode* lasso_idwsf2_data_service_get_attribute_node(LassoIdWsf2DataService *service, */
/* 		const char *item_id); */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DATA_SERVICE_H__ */
