/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/lib_request_authn_context.h>

/*
Information describing which authentication context the requester desires the
identity provider to use in authenticating the Principal.

Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="RequestAuthnContext">
  <xs:complexType>
    <xs:sequence>
      <xs:choice>
        <xs:element name="AuthnContextClassRef" type="xs:anyURI" maxOccurs="unbounded"/>
        <xs:element name="AuthnContextStatementRef" type="xs:anyURI" maxOccurs="unbounded"/>
      </xs:choice>
      <xs:element name="AuthnContextComparison" type="AuthnContextComparisonType" minOccurs="0"/>
    </xs:sequence>
  </xs:complexType>
</xs:element>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_request_authn_context_add_authnContextClassRef(LassoLibRequestAuthnContext *node,
							 const xmlChar *authnContextClassRef) {
  g_assert(LASSO_IS_LIB_REQUEST_AUTHN_CONTEXT(node));
  g_assert(authnContextClassRef != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AuthnContextClassRef",
		   authnContextClassRef, TRUE);
}

void
lasso_lib_request_authn_context_add_authnContextStatementRef(LassoLibRequestAuthnContext *node,
							     const xmlChar *authnContextStatementRef) {
  g_assert(LASSO_IS_LIB_REQUEST_AUTHN_CONTEXT(node));
  g_assert(authnContextStatementRef != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AuthnContextStatementRef",
		   authnContextStatementRef, TRUE);
}

void
lasso_lib_request_authn_context_set_authnContextComparison(LassoLibRequestAuthnContext *node,
							   const xmlChar *authnContextComparison) {
  g_assert(LASSO_IS_LIB_REQUEST_AUTHN_CONTEXT(node));
  g_assert(authnContextComparison != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AuthnContextComparison",
		   authnContextComparison, FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_request_authn_context_instance_init(LassoLibRequestAuthnContext *instance)
{
  LassoNode *node = LASSO_NODE(instance);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->new_ns(node, "urn:liberty:iff:2003-08", "lib");
  class->set_name(node, "RequestAuthnContext");
}

static void
lasso_lib_request_authn_context_class_init(LassoLibRequestAuthnContextClass *klass)
{
}

GType lasso_lib_request_authn_context_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibRequestAuthnContextClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_request_authn_context_class_init,
      NULL,
      NULL,
      sizeof(LassoLibRequestAuthnContext),
      0,
      (GInstanceInitFunc) lasso_lib_request_authn_context_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibRequestAuthnContext",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_lib_request_authn_context_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT, NULL));
}
