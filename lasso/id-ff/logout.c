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

#include <lasso/environs/logout.h>
#include <lasso/xml/errors.h>
#include <string.h>

#define LASSO_LOGOUT_NODE            "LassoLogout"
#define LASSO_REMOTE_PROVIDERID_NODE "RemoteProviderID"

static GObjectClass *parent_class = NULL;

struct _LassoLogoutPrivate
{
  gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_logout_dump:
 * @logout: the logout object
 * 
 * This method dumps the logout object in string xml form.
 * 
 * Return value: a newly allocated string or NULL
 **/
gchar *
lasso_logout_dump(LassoLogout *logout)
{
  gchar          *dump = NULL;
  LassoNode      *logout_node = NULL;
  LassoNodeClass *logout_class = NULL;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);

  logout_node = lasso_node_new();
  logout_class = LASSO_NODE_GET_CLASS(logout_node);
  logout_class->set_name(logout_node, LASSO_LOGOUT_NODE);

  return(dump);
}

/**
 * lasso_logout_build_request_msg:
 * @logout: the logout object
 * 
 * This method builds the logout request message.
 *
 * It gets the single logout protocol profile of the remote provider and :
 *    if it is a SOAP method, then it builds the logout request SOAP message,
 *    set the msg_body attribute, get the single logout service url
 *    and set the msg_url attribute of the logout object.
 *
 *    if it is a HTTP-Redirect method, then it builds the logout request QUERY message,
 *    builds the logout request url, set the msg_url to the logout request url,
 *    set the msg_body to NULL
 *
 *    HTTP-GET : TODO
 * 
 * Return value: a newly allocated string or NULL
 **/
gint
lasso_logout_build_request_msg(LassoLogout *logout)
{
  LassoProfile     *profile;
  LassoProvider    *provider;
  xmlChar          *protocolProfile = NULL;
  GError           *err = NULL;
  lassoProviderType remote_provider_type;
  gint              ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  
  profile = LASSO_PROFILE(logout);

  /* set the remote provider type and get the remote provider object */
  if (profile->provider_type == lassoProviderTypeSp) {
    remote_provider_type = lassoProviderTypeIdp;
  }
  else if (profile->provider_type == lassoProviderTypeIdp) {
    remote_provider_type = lassoProviderTypeSp;
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }
  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, &err);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  /* get the prototocol profile of the logout request */
  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider,
								   remote_provider_type,
								   NULL);
  if (protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Single logout protocol profile not found\n");
    ret = -1;
    goto done;
  }
  
  /* build the logout request message */
  if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
      xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    /* sign the request message */
    lasso_samlp_request_abstract_sign_signature_tmpl(LASSO_SAMLP_REQUEST_ABSTRACT(profile->request),
						     profile->server->private_key,
						     profile->server->certificate);

    /* build the logout request message */
    profile->msg_url  = lasso_provider_get_soapEndpoint(provider,
							remote_provider_type,
							NULL);
    profile->msg_body = lasso_node_export_to_soap(profile->request);
    
    if (profile->msg_url == NULL || profile->msg_body == NULL ) {
      message(G_LOG_LEVEL_CRITICAL, "Error while setting msg_url and msg_body\n");
      ret = -1;
      goto done;
    }
  }
  else if (xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	   xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    /* temporary vars */
    gchar *url, *query;

    /* build and optionaly sign the logout request QUERY message */
    url = lasso_provider_get_singleLogoutServiceURL(provider, remote_provider_type, NULL);
    query = lasso_node_export_to_query(profile->request,
				       profile->server->signature_method,
				       profile->server->private_key);
    profile->msg_url = g_new(gchar, strlen(url)+strlen(query)+1+1);
    g_sprintf(profile->msg_url, "%s?%s", url, query);
    profile->msg_body = NULL;

    if (profile->msg_url == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Error while setting msg_url\n");
      ret = -1;
      goto done;
    }

    xmlFree(url);
    xmlFree(query);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid logout protocol profile\n");
    ret = -1;
    goto done;
  }

  done:
  debug("Build request msg done\n");
  if (protocolProfile != NULL) {
    xmlFree(protocolProfile);
  }

  return(ret);
}

/**
 * lasso_logout_build_response_msg:
 * @logout: the logout object
 * 
 * This method builds the logout response message.
 *
 * It gets the request message method and :
 *    if it is a SOAP method, then it builds the logout response SOAP message,
 *    set the msg_body attribute, get the single logout service return url
 *    and set the msg_url attribute of the logout object.
 *
 *    if it is a HTTP-Redirect method, then it builds the logout response QUERY message,
 *    builds the logout response url, set the msg_url to the logout response url,
 *    set the msg_body to NULL
 *
 *    HTTP-GET : TODO
 * 
 * Return value: 
 **/
gint
lasso_logout_build_response_msg(LassoLogout *logout)
{
  LassoProfile  *profile;
  LassoProvider *provider;
  gchar         *url, *query;
  const gchar   *separator = "?";
  GError        *err = NULL;
  gint           ret = 0;

  if (LASSO_IS_LOGOUT(logout) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Not a Logout object\n");
    ret = -1;
    goto done;
  }
  
  profile = LASSO_PROFILE(logout);

  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, &err);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  /* build a SOAP or HTTP-Redirect logout response message */
  switch (profile->http_request_method) {
  case lassoHttpMethodSoap:
    /* optionaly sign the response message */
    if (profile->server->private_key) {
      lasso_samlp_response_abstract_set_signature(LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response),
						  profile->server->signature_method,
						  profile->server->private_key,
						  profile->server->certificate);
    }
    
    /* build the logout response messsage */
    profile->msg_url = NULL;
    profile->msg_body = lasso_node_export_to_soap(profile->response);
    break;
  case lassoHttpMethodRedirect:
    url = lasso_provider_get_singleLogoutServiceReturnURL(provider, profile->provider_type, NULL);
    query = lasso_node_export_to_query(profile->response,
				       profile->server->signature_method,
				       profile->server->private_key);
    profile->msg_url = g_strjoin(separator, url, query);
    profile->msg_body = NULL;
    xmlFree(url);
    xmlFree(query);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method\n");
    ret = -1;
    goto done;
  }

  done:

  return(ret);
}

/**
 * lasso_logout_destroy:
 * @logout: the logout object
 *
 * destroy the logout object
 * 
 **/
void
lasso_logout_destroy(LassoLogout *logout)
{
  g_object_unref(G_OBJECT(logout));
}

/**
 * lasso_logout_get_next_providerID:
 * @logout: the logout object
 * 
 * This method returns the next logout request service provider id
 * excepted the initial service provider id.
 * 
 * Return value: a newly allocated string or NULL
 **/
gchar*
lasso_logout_get_next_providerID(LassoLogout *logout)
{
  LassoProfile *profile;
  gchar        *current_provider_id;
  int           i;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);

  profile = LASSO_PROFILE(logout);

  if (profile->session == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Session not found\n");
    return(NULL);
  }

  /* if a ProviderID from a SP request, pass it and return the next provider id found */
  for (i = 0; i < profile->session->providerIDs->len; i++) {
    current_provider_id = g_strdup(g_ptr_array_index(profile->session->providerIDs, i));

    /* if logout request from SP at IDP, verify not to return the ProviderID of the initial SP requester */
    if (logout->initial_remote_providerID != NULL) {
      if (xmlStrEqual(current_provider_id, logout->initial_remote_providerID)) {
	debug("It's the ProviderID of the SP requester (%s) : %s, pass it\n",
	      logout->initial_remote_providerID,
	      current_provider_id);
	xmlFree(current_provider_id);
	continue;
      }
    }
    return(current_provider_id);
  }

  return(NULL);
}

/**
 * lasso_logout_init_request:
 * @logout: the logout object
 * @remote_providerID: The provider id of the logout requested provider.
 *     If it is set to NULL, then gets the default first remote provider id.
 * 
 * It sets a new logout request to the remote provider id 
 * with the provider id of the requester (from the server object )
 * and name identifier of the federated principal
 * 
 * Return value: 0 if OK else < 0
 **/
gint
lasso_logout_init_request(LassoLogout    *logout,
			  gchar          *remote_providerID)
{
  LassoProfile      *profile        = NULL;
  LassoProvider     *provider       = NULL;
  LassoNode         *nameIdentifier = NULL;
  LassoFederation   *federation     = NULL;
  xmlChar           *content        = NULL, *nameQualifier = NULL, *format = NULL;
  xmlChar           *singleLogoutProtocolProfile = NULL;
  GError            *err = NULL;
  lassoSignatureType signature_type = lassoSignatureTypeNone;
  gint               ret = 0;

  gboolean           http_redirect_get_type = FALSE; /* tell if the logout protocol profile is HTTP Redirect / GET */

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

  profile = LASSO_PROFILE(logout);

  /* verify if the identity and session exist */
  if (profile->identity == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Identity not found\n");
    ret = -1;
    goto done;
  }

  if (profile->session == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Session not found\n");
    ret = -1;
    goto done;
  }

  /* get the remote provider id */
  if (remote_providerID == NULL) {
    debug("No remote provider id, get the next assertion peer provider id\n");
    profile->remote_providerID = lasso_session_get_next_assertion_remote_providerID(profile->session);
  }
  else {
    debug("A remote provider id for logout request : %s\n", remote_providerID);
    profile->remote_providerID = g_strdup(remote_providerID);
  }

  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No remote provider id to send the logout request\n");
    ret = -1;
    goto done;
  }

  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Federation not found\n");
    ret = -1;
    goto done;
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch (profile->provider_type) {
  case lassoProviderTypeSp:
    nameIdentifier = lasso_federation_get_local_nameIdentifier(federation);
    if (nameIdentifier == NULL) {
      nameIdentifier = lasso_federation_get_remote_nameIdentifier(federation);
    }
    break;
  case lassoProviderTypeIdp:
    nameIdentifier = lasso_federation_get_remote_nameIdentifier(federation);
    if (nameIdentifier == NULL) {
      nameIdentifier = lasso_federation_get_local_nameIdentifier(federation);
    }
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }

  if (nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found for %s\n",
	    profile->remote_providerID);
    ret = -1;
    goto done;
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier, NULL);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  
  /* get the single logout protocol profile and set a new logout request object */
  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, &err);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  if (profile->provider_type == lassoProviderTypeIdp) {
    singleLogoutProtocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider, lassoProviderTypeSp, NULL);
  }
  else if (profile->provider_type == lassoProviderTypeSp) {
    singleLogoutProtocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider, lassoProviderTypeIdp, NULL);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }

  if (singleLogoutProtocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Single logout protocol profile not found\n");
    ret = -1;
    goto done;
  }

  if (xmlStrEqual(singleLogoutProtocolProfile, lassoLibProtocolProfileSloSpSoap) || \
      xmlStrEqual(singleLogoutProtocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    profile->request = lasso_logout_request_new(profile->server->providerID,
						content,
						nameQualifier,
						format,
						lassoSignatureTypeWithX509,
						lassoSignatureMethodRsaSha1);
  }
  else if (xmlStrEqual(singleLogoutProtocolProfile, lassoLibProtocolProfileSloSpHttp) || \
	   xmlStrEqual(singleLogoutProtocolProfile, lassoLibProtocolProfileSloIdpHttp)) {
    /* later tell it is a HTTP Redirect / GET method */
    http_redirect_get_type = TRUE;
    profile->request = lasso_logout_request_new(profile->server->providerID,
						content,
						nameQualifier,
						format,
						lassoSignatureTypeNone,
						0);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid single logout protocol profile : %s\n", singleLogoutProtocolProfile);
    ret = -1;
    goto done;
  }
  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the request\n");
    ret = -1;
    goto done;
  }

  /* set the name identifier in logout object */
  profile->nameIdentifier = content;

  /* if logout request from a SP and if an HTTP Redirect / GET method, then remove assertion */
  if (profile->provider_type == lassoProviderTypeSp) {
    if (http_redirect_get_type == TRUE) {
      lasso_session_remove_assertion(profile->session, profile->remote_providerID);
    }
  }

  done:
  debug("Init request done\n");
  if (federation != NULL) {
    lasso_federation_destroy(federation);
  }
  if (nameIdentifier != NULL ) {
    lasso_node_destroy(nameIdentifier);
  }
  if (nameQualifier != NULL) {
    xmlFree(nameQualifier);
  }
  if (format != NULL) {
    xmlFree(format);
  }
  if (singleLogoutProtocolProfile != NULL) {
    xmlFree(singleLogoutProtocolProfile);
  }

  return(ret);
}

/**
 * lasso_logout_process_request_msg:
 * @logout: the logout object
 * @request_msg: the logout request message
 * @request_method: the logout request method
 * 
 * Process a logout request.
 *    if it is a SOAP request method then it builds the logout request object
 *    from the SOAP message and optionaly verify the signature of the logout request.
 * 
 *    if it is a HTTP-Redirect request method then it builds the logout request object
 *    from the QUERY message and verify the signature
 *
 * Set the msg_nameIdentifier attribute with the NameIdentifier content of the logout object and
 * optionaly set the msg_relayState attribute with the RelayState of the logout request
 *
 * Return value: 0 if OK else < 0
 **/
gint lasso_logout_process_request_msg(LassoLogout     *logout,
				      gchar           *request_msg,
				      lassoHttpMethod  request_method)
{
  LassoProfile  *profile;
  LassoProvider *provider;
  gchar         *remote_providerID = NULL;
  gint           ret = 0;
  GError        *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  g_return_val_if_fail(request_msg != NULL, -1);

  profile = LASSO_PROFILE(logout);

  /* build and process the logout request depending on the logout request type and optionaly verify the signature */
  switch (request_method) {
  case lassoHttpMethodSoap:
    profile->request = lasso_logout_request_new_from_export(request_msg,
							    lassoNodeExportTypeSoap);

    /* verify requets is a LogoutRequest */
    if (LASSO_IS_LOGOUT_REQUEST(profile->request) == FALSE) {
      message(G_LOG_LEVEL_CRITICAL, "Message is not a LogoutRequest\n");
      ret = -1;
      goto done;
    }

    /* signature verification */
    remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID", NULL, NULL);
    if (remote_providerID == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "ProviderID not found\n");
      ret = -1;
      goto done;
    }

    provider = lasso_server_get_provider_ref(profile->server, remote_providerID, &err);
    if (provider == NULL) {
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_error_free(err);
      goto done;
    }

    if (provider->ca_certificate != NULL) {
      ret = lasso_node_verify_x509_signature(profile->request, provider->ca_certificate);
      /* ret = lasso_node_verify_signature(profile->request, provider->public_key); */
    }
    break;
  case lassoHttpMethodRedirect:
    debug("Build a logout request from query msg\n");
    profile->request = lasso_logout_request_new_from_export(request_msg,
							    lassoNodeExportTypeQuery);

    /* verify the message is a LogoutRequest */
    if (LASSO_IS_LOGOUT_REQUEST(profile->request) == FALSE) {
      message(G_LOG_LEVEL_CRITICAL, "Message is not a LogoutRequest\n");
      ret = -1;
      goto done;
    }

    break;
  case lassoHttpMethodGet:
    debug("TODO, implement the get method\n");
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid request method\n");
    ret = -1;
    goto done;
  }
  if(profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the request from msg\n");
    ret = -1;
    goto done;
  }

  /* set the http request method */
  profile->http_request_method = request_method;

  /* Set the NameIdentifier */
  profile->nameIdentifier = lasso_node_get_child_content(profile->request,
							 "NameIdentifier",
							 NULL, NULL);

  /* Set the RelayState */
  profile->msg_relayState = lasso_node_get_child_content(profile->request,
							 "RelayState",
							 NULL, NULL);

  done:
  if (remote_providerID != NULL ) {
    xmlFree(remote_providerID);
  }

  return(ret);
}

/**
 * lasso_logout_validate_request:
 * @logout: the logout object
 * 
 * Validate the logout request :
 *    sets the logout response
 *    verifies the ProviderID
 *    verifies the federation with the NameIdentifier
 *    verifies the authentication with the NameIdentifier
 *    if SOAP method at identity provider, verify all the remote service providers support SOAP method.
 *
 * Return value: O if OK else < 0
 **/
gint
lasso_logout_validate_request(LassoLogout *logout)
{
  LassoProfile    *profile;
  LassoFederation *federation;
  LassoNode       *nameIdentifier, *assertion;
  LassoNode       *statusCode;
  LassoNodeClass  *statusCode_class;
  xmlChar         *remote_providerID;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

  profile = LASSO_PROFILE(logout);

  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "LogoutRequest not found\n");
    ret = -1;
    goto done;
  }

  /* Set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);
  if (remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "ProviderID in LogoutRequest not found\n");
    ret = -1;
    goto done;
  }
  profile->remote_providerID = remote_providerID;

  /* Set LogoutResponse */
  profile->response = lasso_logout_response_new(profile->server->providerID,
						lassoSamlStatusCodeSuccess,
						profile->request,
						lassoSignatureTypeWithX509,
						lassoSignatureMethodRsaSha1);
  if (profile->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building response\n");
    ret = -1;
    goto done;
  }

  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profile->request, "NameIdentifier",
					NULL, NULL);
  if (nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found in logout request\n");
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }

  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);
  if (remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider id not found in logout request\n");
    ret = -1;
    goto done;
  }

  /* verify authentication */
  if (profile->identity == NULL) {
    message(G_LOG_LEVEL_WARNING, "Identity not found\n");
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    ret = -1;
    goto done;
  }

  assertion = lasso_session_get_assertion(profile->session, remote_providerID);
  if (assertion == NULL) {
    message(G_LOG_LEVEL_WARNING, "%s has no assertion\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    ret = -1;
    goto done;
  }
  lasso_node_destroy(assertion);

  /* Verify federation */
  federation = lasso_identity_get_federation(profile->identity, remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_WARNING, "No federation for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }

  if (lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }

  /* if SOAP request method at IDP then verify all the remote service providers support SOAP protocol profile.
     If one remote authenticated principal service provider doesn't support SOAP
     then return UnsupportedProfile to original service provider */
  if (profile->provider_type==lassoProviderTypeIdp && profile->http_request_method==lassoHttpMethodSoap) {
    gboolean all_http_soap;
    LassoProvider *provider;
    gchar *providerID, *protocolProfile;
    int i;
    
    all_http_soap = TRUE;

    for (i = 0; i<profile->server->providers->len; i++) {
      provider = g_ptr_array_index(profile->server->providers, i);
      providerID = lasso_provider_get_providerID(provider);

      /* if the original service provider then continue */
      if (xmlStrEqual(remote_providerID, providerID)) {
	continue;
      }

      /* if principal is not authenticated with this remote service provider, continue */
      assertion = lasso_session_get_assertion(profile->session, providerID);
      if (assertion == NULL) {
	continue;
      }

      /* if protocolProfile is SOAP continue else break */
      protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider, lassoProviderTypeIdp, NULL);
      if (protocolProfile == NULL || !xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap)) {
	all_http_soap = FALSE;
	break;
      }

      if (protocolProfile != NULL) {
	xmlFree(protocolProfile);
      }

      if (providerID != NULL) {
	xmlFree(providerID);
      }
    }

    if (all_http_soap==FALSE) {
      statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeUnsupportedProfile);
      ret = -1;
      goto done;
    }
  }

  lasso_federation_destroy(federation);

  /* authentication is ok, federation is ok, propagation support is ok, remove federation */
  /* verification is ok, save name identifier in logout object */
  lasso_session_remove_assertion(profile->session, profile->remote_providerID);
  if (profile->provider_type == lassoProviderTypeIdp) {
    logout->initial_remote_providerID = g_strdup(profile->remote_providerID);
    if (profile->session->providerIDs->len>1) {
      logout->initial_request = profile->request;
      profile->request = NULL;
      logout->initial_response = profile->response;
      profile->response = NULL;
      profile->remote_providerID = NULL;    
    }
  }

  done:

  return(ret);
}

/**
 * lasso_logout_process_response_msg:
 * @logout: the logout object
 * @response_msg: the response message
 * @response_method: the response method
 * 
 * Process the response method :
 *    build the logout response object
 *    verify the status code value
 * 
 * Return value: 0 if OK else < 0
 **/
gint
lasso_logout_process_response_msg(LassoLogout     *logout,
				  gchar           *response_msg,
				  lassoHttpMethod  response_method)
{
  LassoProfile *profile;
  xmlChar      *statusCodeValue;
  LassoNode    *statusCode;
  GError       *err = NULL;
  gint          ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  g_return_val_if_fail(response_msg != NULL, -1);

  profile = LASSO_PROFILE(logout);

  /* build logout response object */
  switch (response_method) {
  case lassoHttpMethodSoap:
    profile->response = lasso_logout_response_new_from_export(response_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    profile->response = lasso_logout_response_new_from_export(response_msg, lassoNodeExportTypeQuery);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid response method\n");
    ret = -1;
    goto done;
  }
  if (LASSO_IS_LOGOUT_RESPONSE(profile->response) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Message is not a LogoutResponse\n");
    ret = -1;
    goto done;
  }

  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  if (statusCode == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "StatusCode node not found\n");
    ret = -1;
    goto done;
  }

  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value", NULL);

  if (!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)) {
    /* At SP, if the request method was a SOAP type, if at IDP, then rebuild the request message with HTTP method */
    if (profile->provider_type == lassoProviderTypeSp && profile->http_request_method == lassoHttpMethodSoap) {
      /* temporary vars */
      LassoProvider *provider;
      gchar *url, *query;

      provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, &err);
      if (provider == NULL) {
	message(G_LOG_LEVEL_CRITICAL, err->message);
	ret = err->code;
	g_error_free(err);
	goto done;
      }

      /* FIXME : verify the IDP support a HTTP method */

      /* Build and optionaly sign the logout request QUERY message */
      url = lasso_provider_get_singleLogoutServiceURL(provider, lassoProviderTypeIdp, NULL);
      query = lasso_node_export_to_query(profile->request,
					 profile->server->signature_method,
					 profile->server->private_key);
      profile->msg_url = g_new(gchar, strlen(url)+strlen(query)+1+1);
      g_sprintf(profile->msg_url, "%s?%s", url, query);
      profile->msg_body = NULL;

      /* send a HTTP Redirect / GET method, so first remove session */
      lasso_session_remove_assertion(profile->session, profile->remote_providerID);
    }

    message(G_LOG_LEVEL_WARNING, "Status code value is not Success\n");
    ret = LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
    goto done;
  }

  /* LogoutResponse status code value is ok, so remove assertion */

  profile->remote_providerID = lasso_node_get_child_content(profile->response, "ProviderID",
							    NULL, NULL);

  /* response os ok, delete the assertion */
  lasso_session_remove_assertion(profile->session, profile->remote_providerID);

  /* response is ok, so delete the assertion */
  switch (profile->provider_type) {
  case lassoProviderTypeSp:
    /* */
    break;
  case lassoProviderTypeIdp:
    /* if no more assertion for other providers and if initial remote provider id is set,
       then remove his assertion and restore his original requester infos */
    if(profile->session->providerIDs->len == 1 && logout->initial_remote_providerID){
      lasso_session_remove_assertion(profile->session, logout->initial_remote_providerID);
      
      profile->remote_providerID = logout->initial_remote_providerID;
      profile->request = logout->initial_request;
      profile->response = logout->initial_response;
    }
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
  }

  done:

  return(ret);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_logout_dispose(LassoLogout *logout)
{
  if (logout->private->dispose_has_run) {
    return;
  }
  logout->private->dispose_has_run = TRUE;

  debug("Logout object 0x%x disposed ...\n", logout);

  /* unref reference counted objects */
  lasso_node_destroy(logout->initial_request);
  lasso_node_destroy(logout->initial_response);

  parent_class->dispose(G_OBJECT(logout));
}

static void
lasso_logout_finalize(LassoLogout *logout)
{  
  debug("Logout object 0x%x finalized ...\n", logout);

  g_free(logout->initial_remote_providerID);

  g_free(logout->private);

  parent_class->finalize(G_OBJECT(logout));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_instance_init(GTypeInstance   *instance,
			   gpointer         g_class)
{
  LassoLogout *logout = LASSO_LOGOUT(instance);

  logout->private = g_new (LassoLogoutPrivate, 1);
  logout->private->dispose_has_run = FALSE;

  logout->initial_request = NULL;
  logout->initial_response = NULL;
  logout->initial_remote_providerID = NULL;
}

static void
lasso_logout_class_init(LassoLogoutClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_logout_dispose;
  gobject_class->finalize = (void *)lasso_logout_finalize;
}

GType lasso_logout_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLogoutClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_logout_class_init,
      NULL,
      NULL,
      sizeof(LassoLogout),
      0,
      (GInstanceInitFunc) lasso_logout_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoLogout",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_logout_new:
 * @server: the logout object
 * @provider_type: the provider type (service provider or identity provider)
 * 
 * initialises a new logout object
 * 
 * Return value: a new instance of logout object or NULL
 **/
LassoLogout*
lasso_logout_new(LassoServer       *server,
		 lassoProviderType  provider_type)
{
  LassoLogout *logout;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the logout object */
  logout = g_object_new(LASSO_TYPE_LOGOUT,
			"server", lasso_server_copy(server),
			"provider_type", provider_type,
			NULL);

  return(logout);
}
