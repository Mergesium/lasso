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

#include <lasso/xml/lib_name_identifier_mapping_response.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="NameIdentifierMappingResponse" type="NameIdentifierMappingResponseType"/>
<xs:complexType name="NameIdentifierMappingResponseType">
  <xs:complexContent>
    <xs:extension base="samlp:ResponseAbstractType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element ref="ProviderID"/>
        <xs:element ref="samlp:Status"/>
        <xs:element ref="saml:NameIdentifier" minOccurs="0"/>
      </xs:sequence>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void lasso_lib_name_identifier_mapping_response_set_nameIdentifier(LassoLibNameIdentifierMappingResponse *node,
								   LassoSamlNameIdentifier *nameIdentifier)
{
  g_assert(LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(node));
  g_assert(LASSO_IS_SAML_NAME_IDENTIFIER(nameIdentifier));
  
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node),
		   LASSO_NODE (nameIdentifier),
		   FALSE);
}

void
lasso_lib_name_identifier_mapping_response_set_providerID(LassoLibNameIdentifierMappingResponse *node,
							  const xmlChar *providerID)
{
  g_assert(LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(node));
  g_assert(providerID != NULL);
  // FIXME : providerID lenght SHOULD be <= 1024

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderID", providerID, FALSE);
}

void lasso_lib_name_identifier_mapping_response_set_status(LassoLibNameIdentifierMappingResponse *node,
							   LassoSamlpStatus *status)
{
  g_assert(LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(node));
  g_assert(LASSO_IS_SAMLP_STATUS(status));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(status), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_name_identifier_mapping_response_instance_init(LassoLibNameIdentifierMappingResponse *instance)
{
  LassoNode *node = LASSO_NODE(instance);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->new_ns(node, "urn:liberty:iff:2003-08", "lib");
  class->set_name(node, "NameIdentifierMappingResponse");
}

static void
lasso_lib_name_identifier_mapping_response_class_init(LassoLibNameIdentifierMappingResponseClass *klass)
{
}

GType lasso_lib_name_identifier_mapping_response_get_type() {
  static GType name_identifier_mapping_response_type = 0;

  if (!name_identifier_mapping_response_type) {
    static const GTypeInfo name_identifier_mapping_response_info = {
      sizeof (LassoLibNameIdentifierMappingResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_name_identifier_mapping_response_class_init,
      NULL,
      NULL,
      sizeof(LassoLibNameIdentifierMappingResponse),
      0,
      (GInstanceInitFunc) lasso_lib_name_identifier_mapping_response_instance_init,
    };
    
    name_identifier_mapping_response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT,
								   "LassoLibNameIdentifierMappingResponse",
								   &name_identifier_mapping_response_info, 0);
  }
  return name_identifier_mapping_response_type;
}

LassoNode* lasso_lib_name_identifier_mapping_response_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL));
}
