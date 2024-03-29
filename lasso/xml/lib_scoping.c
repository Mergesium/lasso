/* $Id$
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "private.h"
#include "lib_scoping.h"

/**
 * SECTION:lib_scoping
 * @short_description: &lt;lib:Scoping&gt;
 *
 * <figure><title>Schema fragment for lib:Scoping</title>
 * <programlisting><![CDATA[
 * <xs:complexType name="ScopingType">
 *   <xs:sequence>
 *     <xs:element name="ProxyCount" type="xs:nonNegativeInteger" minOccurs="0"/>
 *     <xs:element ref="IDPList" minOccurs="0"/>
 *   </xs:sequence>
 * </xs:complexType>
 * <xs:element name="Scoping" type="ScopingType"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ProxyCount", SNIPPET_CONTENT | SNIPPET_INTEGER | SNIPPET_OPTIONAL_NEG,
		G_STRUCT_OFFSET(LassoLibScoping, ProxyCount), NULL, NULL, NULL},
	{ "IDPList", SNIPPET_NODE, G_STRUCT_OFFSET(LassoLibScoping, IDPList), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibScoping *node, G_GNUC_UNUSED void *unused)
{
	node->ProxyCount = -1;
}

static void
class_init(LassoLibScopingClass *klass, void *unused G_GNUC_UNUSED)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Scoping");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_scoping_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibScopingClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibScoping),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibScoping",
				&this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_scoping_new:
 *
 * Creates a new #LassoLibScoping object.
 *
 * Return value: a newly created #LassoLibScoping object
 **/
LassoLibScoping*
lasso_lib_scoping_new()
{
	return g_object_new(LASSO_TYPE_LIB_SCOPING, NULL);
}
