/* $Id: sec_transited_provider_path.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "../private.h"
#include "sec_transited_provider_path.h"

/**
 * SECTION:sec_transited_provider_path
 * @short_description: &lt;sec:TransitedProviderPath&gt;
 *
 * <figure><title>Schema fragment for sec:TransitedProviderPath</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="TransitedProviderPathType">
 *   <xs:sequence>
 *     <xs:element ref="sec:TransitedProvider" minOccurs="1"
 *       maxOccurs="unbounded" />
 *     </xs:sequence>
 *   </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "TransitedProvider", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2SecTransitedProviderPath, TransitedProvider), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2SecTransitedProviderPath *node)
{
	node->TransitedProvider = NULL;
}

static void
class_init(LassoIdWsf2SecTransitedProviderPathClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "TransitedProviderPath");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SEC_HREF, LASSO_IDWSF2_SEC_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_sec_transited_provider_path_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2SecTransitedProviderPathClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2SecTransitedProviderPath),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2SecTransitedProviderPath", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_sec_transited_provider_path_new:
 *
 * Creates a new #LassoIdWsf2SecTransitedProviderPath object.
 *
 * Return value: a newly created #LassoIdWsf2SecTransitedProviderPath object
 **/
LassoIdWsf2SecTransitedProviderPath*
lasso_idwsf2_sec_transited_provider_path_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SEC_TRANSITED_PROVIDER_PATH, NULL);
}
