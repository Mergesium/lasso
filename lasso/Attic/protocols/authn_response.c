/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/protocols/authn_response.h>
#include <lasso/protocols/authn_request.h>
                                                                                          
static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_authn_response_add_assertion(LassoAuthnResponse *response,
				   LassoAssertion     *assertion,
				   const xmlChar      *private_key_file,
				   const xmlChar      *certificate_file)
{
  xmlDocPtr doc;
  LassoNode *signature;

  /* FIXME : Signature */
  doc = xmlNewDoc("1.0"); // <---
  xmlAddChild((xmlNodePtr)doc,
  	      LASSO_NODE_GET_CLASS(assertion)->get_xmlNode(LASSO_NODE(assertion)));

  signature = lasso_ds_signature_new(doc, xmlSecTransformRsaSha1Id);
  lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
				     LASSO_DS_SIGNATURE(signature)); 
  lasso_ds_signature_sign(LASSO_DS_SIGNATURE(signature),
			  private_key_file,
			  certificate_file);
  lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(response),
				     LASSO_LIB_ASSERTION(assertion));
}

void
lasso_authn_response_get_requestID(LassoAuthnResponse *response)
{

}

gboolean
lasso_authn_response_must_authenticate(LassoAuthnResponse *response,
				       gboolean            is_authenticated)
{
  GData    *gd;
  gboolean  must_authenticate = FALSE;
  /* default values for ForceAuthn and IsPassive */
  gboolean forceAuthn = FALSE;
  gboolean isPassive  = TRUE;
 
  gd = lasso_query_to_dict(LASSO_AUTHN_RESPONSE(response)->query);
  /* Get ForceAuthn and IsPassive */
  if (xmlStrEqual(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0), "true")) {
    forceAuthn = TRUE;
  }
  if (xmlStrEqual((xmlChar *)lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0), "false")) {
    isPassive = FALSE;
  }
 
  if ((forceAuthn == TRUE || is_authenticated == FALSE) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
                                                                                                                          
  g_datalist_clear(&gd);
  return (must_authenticate);
}

void
lasso_authn_response_process_authentication_result(LassoAuthnResponse *response,
						   gboolean            authentication_result)
{
  LassoNode *status, *status_code;

  if (authentication_result == FALSE) {
    status = lasso_samlp_status_new();
    status_code = lasso_samlp_status_code_new();
    lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				      lassoLibStatusCodeUnknownPrincipal);
    lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				      LASSO_SAMLP_STATUS_CODE(status_code));
    lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				    LASSO_SAMLP_STATUS(status));
  }
}

gboolean
lasso_authn_response_verify_signature(LassoAuthnResponse *response,
				      xmlChar            *public_key_file,
				      xmlChar            *private_key_file)
{
  g_return_val_if_fail(LASSO_IS_AUTHN_RESPONSE(response), FALSE);

  LassoNode *status, *status_code;
  gboolean signature_status;

  signature_status = lasso_query_verify_signature(LASSO_AUTHN_RESPONSE(response)->query,
						  public_key_file,
						  private_key_file);

  /* Status & StatusCode */
  if (signature_status == 0 || signature_status == 2) {
    status = lasso_samlp_status_new();
    status_code = lasso_samlp_status_code_new();
    switch (signature_status) {
    case 0:
      lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
					lassoLibStatusCodeInvalidSignature);
      break;
    case 2:
      lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
					lassoLibStatusCodeUnsignedAuthnRequest);
      break;
    }
    lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				      LASSO_SAMLP_STATUS_CODE(status_code));
    lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				    LASSO_SAMLP_STATUS(status));
  }

  if (signature_status == 1)
    return (TRUE);
  else
    return (FALSE);
}

/*****************************************************************************/
/* overrided parent classes methods                                          */
/*****************************************************************************/

static void
lasso_authn_response_dispose(LassoAuthnResponse *response)
{
  parent_class->dispose(G_OBJECT(response));
}

/* override lasso_node_dump() method */
static xmlChar *
lasso_authn_response_dump(LassoAuthnResponse *response,
			  const xmlChar      *encoding,
			  int                 format)
{
  LassoNode *response_dump;
  xmlChar   *dump;

  response_dump = lasso_node_new();
  LASSO_NODE_GET_CLASS(response_dump)->set_name(response_dump, "LassoDumpAuthnResponse");
  LASSO_NODE_GET_CLASS(response_dump)->add_child(response_dump,
						 lasso_node_copy(LASSO_NODE(response)), 0);
  if (response->query != NULL)
    LASSO_NODE_GET_CLASS(response_dump)->add_child(response_dump,
						   lasso_authn_request_new_from_query(response->query), 0);
  else
    LASSO_NODE_GET_CLASS(response_dump)->add_child(response_dump,
						   lasso_node_copy(response->request), 0);
  dump = lasso_node_dump(response_dump, encoding, format);
  g_object_unref(G_OBJECT (response_dump));

  return (dump);
}

static void
lasso_authn_response_finalize(LassoAuthnResponse *response)
{
  if (response->query != NULL)
    g_free(response->query);
  if (response->request != NULL)
    g_object_unref(response->request);
  parent_class->finalize(G_OBJECT(response));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_response_instance_init(LassoAuthnResponse *response)
{
}

static void
lasso_authn_response_class_init(LassoAuthnResponseClass *class)
{
  GObjectClass   *gobject_class = G_OBJECT_CLASS(class);
  LassoNodeClass *lasso_node_class = LASSO_NODE_CLASS(class);

  parent_class = g_type_class_peek_parent(class);
  /* override parent classes methods */
  gobject_class->dispose  = (void *)lasso_authn_response_dispose;
  gobject_class->finalize = (void *)lasso_authn_response_finalize;
  lasso_node_class->dump  = (xmlChar *)lasso_authn_response_dump;
}

GType lasso_authn_response_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_response_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnResponse),
      0,
      (GInstanceInitFunc) lasso_authn_response_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_AUTHN_RESPONSE,
				       "LassoAuthnResponse",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_authn_response_new_from_dump(xmlChar *buffer)
{
  LassoNode *response, *request, *node_dump;
  xmlNodePtr xmlNode_response, xmlNode_request;

  g_return_val_if_fail(buffer != NULL, NULL);

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE, NULL));
  request  = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_REQUEST, NULL));

  node_dump = lasso_node_new_from_dump(buffer);
  /* get xmlNodes */
  xmlNode_response = xmlCopyNode(LASSO_NODE_GET_CLASS(response)->get_xmlNode(lasso_node_get_child(node_dump, "AuthnResponse")), 1);
  xmlNode_request = xmlCopyNode(LASSO_NODE_GET_CLASS(response)->get_xmlNode(lasso_node_get_child(node_dump, "AuthnRequest")), 1);

  /* put xmlNodes in LassoNodes */
  LASSO_NODE_GET_CLASS(response)->set_xmlNode(response, xmlNode_response);
  LASSO_NODE_GET_CLASS(request)->set_xmlNode(request, xmlNode_request);

  LASSO_AUTHN_RESPONSE(response)->request = request;
  LASSO_AUTHN_RESPONSE(response)->query = NULL;
  g_object_unref(node_dump);

  return (response);
}

LassoNode*
lasso_authn_response_new_from_request_query(gchar         *query,
					    const xmlChar *providerID)
{
  GData      *gd;
  LassoNode  *response, *status, *status_code;

  g_return_val_if_fail(query != NULL, NULL);
  g_return_val_if_fail(providerID != NULL, NULL);

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE, NULL));

  gd = lasso_query_to_dict(query);
  /* store query - need to verify signature */
  LASSO_AUTHN_RESPONSE(response)->query   = g_strdup(query);
  LASSO_AUTHN_RESPONSE(response)->request = NULL;

  /* ResponseID */
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					       (const xmlChar *)lasso_build_unique_id(32));
  /* MajorVersion */
  lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lassoLibMajorVersion);     
  /* MinorVersion */
  lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response), 
						 lassoLibMinorVersion);
  /* IssueInstance */
  lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  lasso_get_current_time());

  /* ProviderID */
  lasso_lib_authn_response_set_providerID(LASSO_LIB_AUTHN_RESPONSE(response),
					  providerID);

  /* RelayState */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0) != NULL) {
    lasso_lib_authn_response_set_relayState(LASSO_LIB_AUTHN_RESPONSE(response),
					    lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0));
  }
  /* InResponseTo */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0) != NULL) {
    lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0));
  }

  /* consent */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0) != NULL) {
    lasso_lib_authn_response_set_consent(LASSO_LIB_AUTHN_RESPONSE(response),
					 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0));
  }  

  /* Recipient */
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0));

  /* Status & StatusCode */
  status = lasso_samlp_status_new();
  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				    lassoSamlStatusCodeSuccess);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				    LASSO_SAMLP_STATUS_CODE(status_code));
  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				  LASSO_SAMLP_STATUS(status));

  g_datalist_clear(&gd);

  return (response);
}

LassoNode*
lasso_authn_response_new_from_lareq(xmlChar       *lareq,
				    const xmlChar *providerID)
{
  
}
