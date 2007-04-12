/* $Id: util_status.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#include "util_status.h"

/*
 * Schema fragment (liberty-idwsf-utility-v2.0.xsd):
 *
 * <xs:complexType name="StatusType">
 *   <xs:annotation>
 *     <xs:documentation>
 *       A type that may be used for status codes.
 *     </xs:documentation>
 *   </xs:annotation>
 *   <xs:sequence>
 *     <xs:element ref="Status" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="code" type="xs:string" use="required"/>
 *   <xs:attribute name="ref" type="IDReferenceType" use="optional"/>
 *   <xs:attribute name="comment" type="xs:string" use="optional"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, Status) },
	{ "code", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, code) },
	{ "ref", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, ref) },
	{ "comment", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, comment) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2UtilStatus *node)
{
	node->Status = NULL;
	node->code = NULL;
	node->ref = NULL;
	node->comment = NULL;
}

static void
class_init(LassoIdWsf2UtilStatusClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Status"); 
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_UTIL_HREF, LASSO_IDWSF2_UTIL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_util_status_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2UtilStatusClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2UtilStatus),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2UtilStatus", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_util_status_new:
 *
 * Creates a new #LassoIdWsf2UtilStatus object.
 *
 * Return value: a newly created #LassoIdWsf2UtilStatus object
 **/
LassoNode*
lasso_util_status_new()
{
	return g_object_new(LASSO_TYPE_UTIL_STATUS, NULL);
}