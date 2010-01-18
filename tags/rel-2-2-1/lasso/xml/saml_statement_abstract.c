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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lasso/xml/saml_statement_abstract.h>

/**
 * SECTION:saml_statement_abstract
 * @short_description: &lt;saml:StatementAbstract&gt;
 *
 * <figure><title>Schema fragment for saml:StatementAbstract</title>
 * <programlisting><![CDATA[
 * <element name="Statement" type="saml:StatementAbstractType"/>
 * <complexType name="StatementAbstractType" abstract="true"/>
 * ]]></programlisting>
 * </figure>
 */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlStatementAbstract *node)
{
}

static void
class_init(LassoSamlStatementAbstractClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "StatementAbstract");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
}

GType
lasso_saml_statement_abstract_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlStatementAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlStatementAbstract),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlStatementAbstract", &this_info, 0);
	}
	return this_type;
}
