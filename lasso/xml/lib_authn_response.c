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

#include <lasso/xml/lib_authn_response.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="AuthnResponse" type="AuthnResponseType"/>
<xs:complexType name="AuthnResponseType">
  <xs:complexContent>
    <xs:extension base="samlp:ResponseType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
	<xs:element ref="ProviderID"/>
	<xs:element ref="RelayState" minOccurs="0"/>
      </xs:sequence>
      <xs:attribute ref="consent" use="optional"/>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>

<xs:element name="ProviderID" type="md:entityIDType"/>
From liberty-metadata-v1.0.xsd:
<xs:simpleType name="entityIDType">
  <xs:restriction base="xs:anyURI">
    <xs:maxLength value="1024" id="maxlengthid"/>
  </xs:restriction>
</xs:simpleType>
<xs:element name="RelayState" type="xs:string"/>

*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	LassoLibAuthnResponse *response = LASSO_LIB_AUTHN_RESPONSE(node);
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "AuthnResponse");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (response->ProviderID)
		xmlNewTextChild(xmlnode, NULL, "ProviderID", response->ProviderID);

	if (response->RelayState)
		xmlNewTextChild(xmlnode, NULL, "RelayState", response->RelayState);
		
	if (response->consent)
		xmlSetProp(xmlnode, "consent", response->consent);

	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibAuthnResponse *response = LASSO_LIB_AUTHN_RESPONSE(node);
	xmlNode *t;

        parent_class->init_from_xml(node, xmlnode);

	t = xmlnode->children;
	while (t) {
		if (t->type == XML_ELEMENT_NODE && strcmp(t->name, "ProviderID") == 0) {
			response->ProviderID = xmlNodeGetContent(t);
		}
		if (t->type == XML_ELEMENT_NODE && strcmp(t->name, "RelayState") == 0 ) {
			response->RelayState = xmlNodeGetContent(t);
		}
		t = t->next;
	}
	response->consent = xmlGetProp(xmlnode, "consent");
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibAuthnResponse *node)
{
	node->Extension = NULL;
	node->ProviderID = NULL;
	node->RelayState = NULL;
	node->consent = NULL;
}

static void
class_init(LassoLibAuthnResponseClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_authn_response_get_type()
{
	static GType authn_response_type = 0;

	if (!authn_response_type) {
		static const GTypeInfo authn_response_info = {
			sizeof (LassoLibAuthnResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		authn_response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE,
				"LassoLibAuthnResponse", &authn_response_info, 0);
	}
	return authn_response_type;
}

LassoNode*
lasso_lib_authn_response_new(char *providerID, LassoLibAuthnRequest *request)
{
	LassoSamlpResponseAbstract *response;

	response = g_object_new(LASSO_TYPE_LIB_AUTHN_RESPONSE, NULL);
 
	if (providerID) {
		response->ResponseID = lasso_build_unique_id(32);
		response->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
		response->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
		response->IssueInstant = lasso_get_current_time();

		LASSO_LIB_AUTHN_RESPONSE(response)->ProviderID = g_strdup(providerID);

		LASSO_LIB_AUTHN_RESPONSE(response)->RelayState = g_strdup(
				request->RelayState);
	}

	return LASSO_NODE(response);
}

