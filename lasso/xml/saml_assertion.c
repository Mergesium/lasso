/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
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

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

#include <lasso/xml/saml_assertion.h>

/*
 * Schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):
 * 
 * <element name="Assertion" type="saml:AssertionType"/>
 * <complexType name="AssertionType">
 *   <sequence>
 *     <element ref="saml:Conditions" minOccurs="0"/>
 *     <element ref="saml:Advice" minOccurs="0"/>
 *     <choice maxOccurs="unbounded">
 *       <element ref="saml:Statement"/>
 *       <element ref="saml:SubjectStatement"/>
 *       <element ref="saml:AuthenticationStatement"/>
 *       <element ref="saml:AuthorizationDecisionStatement"/>
 *       <element ref="saml:AttributeStatement"/>
 *     </choice>
 *     <element ref="ds:Signature" minOccurs="0"/>
 *   </sequence>
 *   <attribute name="MajorVersion" type="integer" use="required"/>
 *   <attribute name="MinorVersion" type="integer" use="required"/>
 *   <attribute name="AssertionID" type="saml:IDType" use="required"/>
 *   <attribute name="Issuer" type="string" use="required"/>
 *   <attribute name="IssueInstant" type="dateTime" use="required"/>
 * </complexType>
 * 
 * From oasis-sstc-saml-schema-assertion-1.0.xsd:
 * <simpleType name="IDType">
 *   <restriction base="string"/>
 * </simpleType>
 */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Conditions", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlAssertion, Conditions) },
	{ "Advice", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlAssertion, Advice) },
	{ "SubjectStatement", SNIPPET_NODE,G_STRUCT_OFFSET(LassoSamlAssertion, SubjectStatement) },
	{ "AuthenticationStatement", SNIPPET_NODE, 
		G_STRUCT_OFFSET(LassoSamlAssertion, AuthenticationStatement) },
	{ "AttributeStatement", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlAssertion, AttributeStatement) },
	{ "Signature", SNIPPET_SIGNATURE,
		G_STRUCT_OFFSET(LassoSamlAssertion, AssertionID) },
	{ "MajorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlAssertion, MajorVersion) },
	{ "MinorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlAssertion, MinorVersion) },
	{ "AssertionID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlAssertion, AssertionID) },
	{ "Issuer", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlAssertion, Issuer) },
	{ "IssueInstant", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlAssertion, IssueInstant) },

	/* hidden fields; use in lasso dumps */
	{ "SignType", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, sign_type) },
	{ "SignMethod", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, sign_method) },
	{ "PrivateKeyFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, private_key_file) },
	{ "CertificateFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, certificate_file) },

	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	/* insure children are kept in saml namespace */
	char *typename;
	xmlNode *t;
	xmlNs *xsi_ns;

	xsi_ns = xmlNewNs(xmlnode, LASSO_XSI_HREF, LASSO_XSI_PREFIX);

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		
		if (xmlnode->ns && strcmp(xmlnode->ns->href, LASSO_LIB_HREF) == 0) {
			typename = g_strdup_printf("lib:%sType", xmlnode->name);
			xmlSetNs(xmlnode, ns);
			if (xmlHasNsProp(t, "type", LASSO_XSI_HREF) == NULL) {
				xmlNewNsProp(xmlnode, xsi_ns, "type", typename);
			}
			g_free(typename);
		}

		insure_namespace(t, ns);

		t = t->next;
	}
}


static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoSamlAssertion *assertion = LASSO_SAML_ASSERTION(node);
	xmlNode *xmlnode;
	xmlNs *ns;
	
	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	ns = xmlSearchNs(NULL, xmlnode, "saml");
	insure_namespace(xmlnode, ns);

	if (lasso_dump == FALSE && assertion->sign_type) {
		/* sign assertion now */
		/* code could be refactored with lasso_node_export_to_signed_xmlnode */
		xmlDoc *doc;
		xmlNode *sign_tmpl;
		xmlSecDSigCtx *dsig_ctx;
		char *id_value;
		xmlAttr *id_attr;

		sign_tmpl = xmlSecFindNode(xmlnode, xmlSecNodeSignature, xmlSecDSigNs);
		if (sign_tmpl == NULL)
			return xmlnode;

		doc = xmlNewDoc("1.0");
		xmlDocSetRootElement(doc, xmlnode);
		xmlSetTreeDoc(sign_tmpl, doc);

		id_value = xmlGetProp(xmlnode, "AssertionID");
		id_attr = xmlHasProp(xmlnode, "AssertionID");
		if (id_value) {
			xmlAddID(NULL, doc, id_value, id_attr);
			xmlFree(id_value);
		}

		dsig_ctx = xmlSecDSigCtxCreate(NULL);
		dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(assertion->private_key_file,
				xmlSecKeyDataFormatPem,
				NULL, NULL, NULL);
		if (dsig_ctx->signKey == NULL) {
			/* XXX: file existence should actually be tested on
			 * LassoServer creation */
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED),
					assertion->private_key_file);
			xmlSecDSigCtxDestroy(dsig_ctx);
			return NULL;
		}
		if (assertion->certificate_file != NULL && assertion->certificate_file[0] != 0) {
			if (xmlSecCryptoAppKeyCertLoad(dsig_ctx->signKey,
						assertion->certificate_file,
						xmlSecKeyDataFormatPem) < 0) {
				message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED),
					assertion->certificate_file);
				xmlSecDSigCtxDestroy(dsig_ctx);
				return NULL;
			}
		}
		if (xmlSecDSigCtxSign(dsig_ctx, sign_tmpl) < 0) {
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_SIGNATURE_FAILED),
					xmlnode->name);
			xmlSecDSigCtxDestroy(dsig_ctx);
			return NULL;
		}
		xmlSecDSigCtxDestroy(dsig_ctx);
		xmlUnlinkNode(xmlnode);
		xmlFreeDoc(doc);
	}

	return xmlnode;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlAssertion *assertion)
{
}

static void
class_init(LassoSamlAssertionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);
	
	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Assertion");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	nclass->node_data->sign_type_offset = G_STRUCT_OFFSET(LassoSamlAssertion, sign_type);
	nclass->node_data->sign_method_offset = G_STRUCT_OFFSET(LassoSamlAssertion, sign_method);
}

GType
lasso_saml_assertion_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAssertionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAssertion),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlAssertion", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_assertion_new:
 * 
 * Creates a new <saml:Assertion> node object.
 * 
 * Return value: the new @LassoSamlAssertion
 **/
LassoNode*
lasso_saml_assertion_new()
{
	return g_object_new(LASSO_TYPE_SAML_ASSERTION, NULL);
}

