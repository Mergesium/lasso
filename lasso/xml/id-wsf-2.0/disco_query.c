/* $Id: disco_query.c,v 1.7 2005/01/22 15:57:55 $ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2007 Entr'ouvert
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

#include <lasso/xml/id-wsf-2.0/disco_query.h>

/*
 * Schema fragments (liberty-idwsf-disco-svc-v2.0.xsd) :
 *
 * <xs:element name="Query" type="QueryType"/>
 *
 * <xs:complexType name="QueryType">
 *   <xs:sequence>
 *     <xs:element name="RequestedService"
 *                 type="RequestedServiceType"
 *                 minOccurs="0" 
 *                 maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 */ 

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
//	{ "ResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoIdwsf2DiscoQuery, ResourceID) },
//	{ "EncryptedResourceID",
//	  SNIPPET_NODE, G_STRUCT_OFFSET(LassoIdwsf2DiscoQuery, EncryptedResourceID) },
//	{ "RequestedServiceType", SNIPPET_LIST_NODES,
//	  G_STRUCT_OFFSET(LassoIdwsf2DiscoQuery, RequestedServiceType) },
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIdwsf2DiscoQuery, id) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdwsf2DiscoQuery *node)
{
//	node->ResourceID = NULL;
//	node->EncryptedResourceID = NULL;
//	node->RequestedServiceType = NULL;
	node->id = NULL;
}

static void
class_init(LassoIdwsf2DiscoQueryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Query");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCO_HREF, LASSO_IDWSF2_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_query_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdwsf2DiscoQueryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdwsf2DiscoQuery),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdwsf2DiscoQuery", &this_info, 0);
	}
	return this_type;
}

LassoIdwsf2DiscoQuery*
lasso_idwsf2_disco_query_new()
{
	LassoIdwsf2DiscoQuery *node;

	node = g_object_new(LASSO_TYPE_IDWSF2_DISCO_QUERY, NULL);

	return node;
}

LassoIdwsf2DiscoQuery*
lasso_idwsf2_disco_query_new_from_message(const gchar *message)
{
	LassoIdwsf2DiscoQuery *node;

	g_return_val_if_fail(message != NULL, NULL);

	node = g_object_new(LASSO_TYPE_IDWSF2_DISCO_QUERY, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), message);

	return node;
}