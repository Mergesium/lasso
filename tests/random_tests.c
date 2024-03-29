/*
 * Lasso library C unit tests
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

#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "../lasso/lasso.h"

#include "../lasso/xml/lib_assertion.h"
#include "../lasso/xml/lib_authentication_statement.h"
#include "../lasso/xml/saml_name_identifier.h"
#include "../lasso/xml/samlp_response.h"
#include "../lasso/utils.h"
#include "../lasso/key.h"


Suite* random_suite();

START_TEST(test01_provider_new)
{
	LassoProvider *provider;
	char *dump;

	provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");
	ck_assert(LASSO_IS_PROVIDER(provider));

	dump = lasso_node_dump(LASSO_NODE(provider));
	ck_assert(dump != NULL);
	g_object_unref(provider);
	lasso_release_string(dump);
}
END_TEST

START_TEST(test02_provider_new_from_dump)
{
	LassoProvider *provider1, *provider2;
	char *dump;

	provider1 = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");
	ck_assert(LASSO_IS_PROVIDER(provider1));

	dump = lasso_node_dump(LASSO_NODE(provider1));
	ck_assert(dump != NULL);
	provider2 = lasso_provider_new_from_dump(dump);
	ck_assert(LASSO_IS_PROVIDER(provider2));
	lasso_release_string(dump);
	dump = lasso_node_dump(LASSO_NODE(provider2));
	ck_assert(dump != NULL);
	g_object_unref(provider1);
	g_object_unref(provider2);
	lasso_release_string(dump);
}
END_TEST

START_TEST(test01_server_new)
{
	LassoServer *server;
	LassoProvider *provider;
	char *dump;
	char *content = NULL;
	size_t len;

	server = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");
	ck_assert(LASSO_IS_SERVER(server));
	provider = LASSO_PROVIDER(server);
	ck_assert(server->private_key != NULL);
	ck_assert(server->private_key_password == NULL);
	ck_assert(server->certificate != NULL);
	ck_assert(server->signature_method == lasso_get_default_signature_method());
	ck_assert(provider->ProviderID != NULL);
	ck_assert(provider->role == 0);
	ck_assert(g_file_get_contents(TESTSDATADIR "/idp1-la/metadata.xml", &content, &len, NULL));
	ck_assert(strcmp(provider->metadata_filename, content) == 0);
	g_free(content);
	ck_assert(provider->public_key == NULL);
	ck_assert(provider->ca_cert_chain == NULL);

	dump = lasso_node_dump(LASSO_NODE(server));
	ck_assert(dump != NULL);
	g_object_unref(server);
	server = lasso_server_new_from_dump(dump);
	ck_assert(LASSO_IS_SERVER(server));
	provider = LASSO_PROVIDER(server);
	ck_assert(server->private_key != NULL);
	ck_assert(server->private_key_password == NULL);
	ck_assert(server->certificate != NULL);
	ck_assert(server->signature_method == lasso_get_default_signature_method());
	ck_assert(server->providers != NULL);
	ck_assert(provider->ProviderID != NULL);
	ck_assert_msg(provider->role == 0, "provider->role != 0 => provider :=  %d", provider->role);
	ck_assert(g_file_get_contents(TESTSDATADIR "/idp1-la/metadata.xml", &content, &len, NULL));
	ck_assert(strcmp(provider->metadata_filename, content) == 0);
	ck_assert(provider->public_key == NULL);
	ck_assert(provider->ca_cert_chain == NULL);
	g_object_unref(server);
	lasso_release_string(dump);
	lasso_release_string(content);
}
END_TEST

START_TEST(test02_server_add_provider)
{
	LassoServer *server;
	char *dump;

	server = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");
	ck_assert(LASSO_IS_SERVER(server));
	ck_assert(server->private_key != NULL);
	ck_assert(! server->private_key_password);
	ck_assert(server->certificate != NULL);
	ck_assert(server->signature_method == lasso_get_default_signature_method());
	ck_assert(server->providers != NULL);
	lasso_server_add_provider(
			server,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");
	ck_assert(g_hash_table_size(server->providers) == 1);


	dump = lasso_node_dump(LASSO_NODE(server));
	g_object_unref(server);
	lasso_release_string(dump);
}
END_TEST

START_TEST(test03_server_new_from_dump)
{
	LassoServer *server1, *server2;
	char *dump;

	server1 = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");
	lasso_server_add_provider(
			server1,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");

	dump = lasso_node_dump(LASSO_NODE(server1));

	server2 = lasso_server_new_from_dump(dump);
	g_free(dump);
	dump = lasso_node_dump(LASSO_NODE(server2));
	g_object_unref(server1);
	g_object_unref(server2);
	g_free(dump);
}
END_TEST

START_TEST(test04_node_new_from_dump)
{
	LassoNode *node;

	char *msg = \
	  "<lib:LogoutRequest xmlns:lib=\"urn:liberty:iff:2003-08\" "\
	  "xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" "\
	  "RequestID=\"_52EDD5A8A0BF74977C0A16B827CA4229\" MajorVersion=\"1\" "\
	  "MinorVersion=\"2\" IssueInstant=\"2004-12-04T11:05:26Z\">" \
	  "<lib:ProviderID>https://idp1/metadata</lib:ProviderID>" \
	  "<saml:NameIdentifier xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" "\
	  "NameQualifier=\"https://idp1/metadata\" "\
	  "Format=\"urn:liberty:iff:nameid:federated\">_AF452F97C9E1590DDEB91D5BA6AA48ED"\
	  "</saml:NameIdentifier>"\
	  "</lib:LogoutRequest>";
	char *dump;

	node = lasso_node_new_from_dump(msg);
	ck_assert_msg(node != NULL, "new_from_dump failed");
	dump = lasso_node_dump(node);
	ck_assert_msg(dump != NULL, "node_dump failed");
	g_object_unref(node);
	g_free(dump);
}
END_TEST

START_TEST(test05_xsi_type)
{
	/* check lib:AuthnContext element is not converted to
	 * saml:AuthnContext xsi:type="lib:AuthnContextType" and
	 * lib:AuthenticationStatement is converted to
	 * saml:AuthenticationStatement * xsi:type="lib:AuthenticationStatementType"
	 */

	LassoSamlAssertion *assertion;
	LassoLibAuthenticationStatement *stmt;
	LassoSamlNameIdentifier *name_identifier;
	char *dump;

	name_identifier = lasso_saml_name_identifier_new();
	assertion = LASSO_SAML_ASSERTION(lasso_lib_assertion_new_full("", "", "", "", ""));

	assertion->AuthenticationStatement = LASSO_SAML_AUTHENTICATION_STATEMENT(
			lasso_lib_authentication_statement_new_full(
			"toto", "toto", "toto",
			NULL,
			name_identifier));
	g_object_unref(name_identifier);
	stmt = LASSO_LIB_AUTHENTICATION_STATEMENT(assertion->AuthenticationStatement);
	stmt->AuthnContext = LASSO_LIB_AUTHN_CONTEXT(lasso_lib_authn_context_new());
	stmt->AuthnContext->AuthnContextClassRef = g_strdup("urn:toto");

	dump = lasso_node_dump(LASSO_NODE(assertion));
	ck_assert_msg(strstr(dump, "xsi:type=\"lib:AuthnContextType\"") == NULL,
			"AuthnContext got a xsi:type");
	g_free(dump);
	dump = lasso_node_dump(LASSO_NODE(assertion));
	ck_assert_msg(strstr(dump, "xsi:type=\"lib:AuthenticationStatementType\"") != NULL,
			"AuthenticationStatement didn't get a xsi:type");
	g_free(dump);
	g_object_unref(assertion);
}
END_TEST

START_TEST(test06_lib_statuscode)
{
	/* check status code value in samlp:Response; it is a QName, if it
	 * starts with lib:, that namespace must be defined.  (was bug#416)
	 */
	LassoSamlpResponse *response = LASSO_SAMLP_RESPONSE(lasso_samlp_response_new());
	char *dump = NULL;

	lasso_assign_string(response->Status->StatusCode->Value, LASSO_SAML_STATUS_CODE_SUCCESS);
	dump = lasso_node_dump(LASSO_NODE(response));
	ck_assert_msg(strstr(dump, "xmlns:lib=") == NULL,
			"liberty namespace should not be defined");
	lasso_release_string(dump);

	lasso_assign_string(response->Status->StatusCode->Value, LASSO_SAML_STATUS_CODE_RESPONDER);
	response->Status->StatusCode->StatusCode = lasso_samlp_status_code_new();
	response->Status->StatusCode->StatusCode->Value = g_strdup(
			LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL);
	dump = lasso_node_dump(LASSO_NODE(response));
	ck_assert_msg(strstr(dump, "xmlns:lib=") != NULL,
			"liberty namespace should be defined");
	lasso_release_string(dump);
	g_object_unref(response);
}
END_TEST

extern xmlSecKey* lasso_xmlsec_load_private_key_from_buffer(const char *buffer, size_t length, const
		char *password, LassoSignatureMethod method, const char *certificate);

extern int lasso_saml2_query_verify_signature(const char *query, const xmlSecKey *sender_public_key);


START_TEST(test07_saml2_query_verify_signature)
{
	/* normal query as produces by Lasso */
	const char query1[] = "SAMLRequest=fVHJasMwEP0Vo3tqRXY2YRvcOIFAl9CUHnopwpkkAllyNeMuf1%2FZaSG95PrmLfNmMlSNaWXZ0ck%2BwXsHSNFXYyzKYZCzzlvpFGqUVjWAkmq5K%2B%2FvpLjhsvWOXO0Mu5BcVyhE8KSdZdGmytnbNEmTBV%2Bli9ulKMt5KlbVfDkbizWfcVEmUxa9gMfAz1mQBxFiBxuLpCwFiIvxiE9H48mz4FJMZJq8sqgKHbRVNKhORK2MY71vJzFqezSw00f7GPLXztcw9M7ZQRmE3n0bFtQf8IcUWV9JDqm%2B%2BPXCYNUAqb0ilcWXhOx8zIdQe1NtndH1dx%2FTKLp%2BlR7R%2B9FhoMq2b4wEllhUGuM%2Blx4UhZ3Id8Di4pz5%2F2fFDw%3D%3D&RelayState=fake&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=Zfz3DE1VMV3thaV4FWpH0fkWsBMzAFJcfvVWAbo0a3cY48Et%2BXUcbr1nvOJUJmhGoie0pQ4%2BcD9ToQlSk7BbJSBCct%2FQQgn2QNkX%2F1lk4v8RU8p5ptJRJ2iPLb8nC6WZhs81HoihQePSuj7Qe5bRUsDKvnWMq6OkD%2Fe6YO77dMXregTcfmnkrXqRb2T6TFfqyOz9i0%2FjmISsmj%2F3kEEfUzVA4LEbeEgiJDj1hec4XW26gQTih53v0sYukq4Eyb4zS2jVd3apUUxUrjn1NUpr7Z7dZ7w5MQlgZ8aw1xFDE8BkxymvIjwf8ciyx6sfTKbCRsoS9E0pQB1vxvh6OMt1Ww%3D%3D";
	/* SAMLRequest field was moved in the middle, Signature to the beginning and all & were
	 * changed to ; */
	const char query2[] = "Signature=Zfz3DE1VMV3thaV4FWpH0fkWsBMzAFJcfvVWAbo0a3cY48Et%2BXUcbr1nvOJUJmhGoie0pQ4%2BcD9ToQlSk7BbJSBCct%2FQQgn2QNkX%2F1lk4v8RU8p5ptJRJ2iPLb8nC6WZhs81HoihQePSuj7Qe5bRUsDKvnWMq6OkD%2Fe6YO77dMXregTcfmnkrXqRb2T6TFfqyOz9i0%2FjmISsmj%2F3kEEfUzVA4LEbeEgiJDj1hec4XW26gQTih53v0sYukq4Eyb4zS2jVd3apUUxUrjn1NUpr7Z7dZ7w5MQlgZ8aw1xFDE8BkxymvIjwf8ciyx6sfTKbCRsoS9E0pQB1vxvh6OMt1Ww%3D%3D;SAMLRequest=fVHJasMwEP0Vo3tqRXY2YRvcOIFAl9CUHnopwpkkAllyNeMuf1%2FZaSG95PrmLfNmMlSNaWXZ0ck%2BwXsHSNFXYyzKYZCzzlvpFGqUVjWAkmq5K%2B%2FvpLjhsvWOXO0Mu5BcVyhE8KSdZdGmytnbNEmTBV%2Bli9ulKMt5KlbVfDkbizWfcVEmUxa9gMfAz1mQBxFiBxuLpCwFiIvxiE9H48mz4FJMZJq8sqgKHbRVNKhORK2MY71vJzFqezSw00f7GPLXztcw9M7ZQRmE3n0bFtQf8IcUWV9JDqm%2B%2BPXCYNUAqb0ilcWXhOx8zIdQe1NtndH1dx%2FTKLp%2BlR7R%2B9FhoMq2b4wEllhUGuM%2Blx4UhZ3Id8Di4pz5%2F2fFDw%3D%3D;RelayState=fake;SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
	const char query3[] = "SAMLRequest=fVHJasMwEP0Vo3tqRXY2YRvcOIFAl9CUHnopwpkkAllyNeMuf1%2FZaSG95PrmLfNmMlSNaWXZ0ck%2BwXsHSNFXYyzKYZCzzlvpFGqUVjWAkmq5K%2B%2FvpLjhsvWOXO0Mu5BcVyhE8KSdZdGmytnbNEmTBV%2Bli9ulKMt5KlbVfDkbizWfcVEmUxa9gMfAz1mQBxFiBxuLpCwFiIvxiE9H48mz4FJMZJq8sqgKHbRVNKhORK2MY71vJzFqezSw00f7GPLXztcw9M7ZQRmE3n0bFtQf8IcUWV9JDqm%2B%2BPXCYNUAqb0ilcWXhOx8zIdQe1NtndH1dx%2FTKLp%2BlR7R%2B9FhoMq2b4wEllhUGuM%2Blx4UhZ3Id8Di4pz5%2F2fFDw%3D%3D&RelayState=fake&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=rUJ%2B9wVSvdGSmZWGuGXgudAPV5KBxRfxRKraBWGIslBz2XreyNbQjSA47DhIfi%2Bxf0awIIGkKcieN3Qd5sqVn4wvFU8fsmfqrdtouYi46aKsj4W91N19TxJ%2BCgrP7ygVEGDaGdc%2BrCQC3%2FuoYTELXq0gYP7tHaXA%2FCaZHfx5Z159crpRxS6eabZ6BGf4ImxiKhE1FuYzKHeISEV1iSyvgx5%2FE8ydSO%2FSP6yA5Rck4JxVJWH6ImbswCVQ80qfqR4NoJ%2BxiZqilbDJnQaSKZggx%2FgjNVoX%2FMVW1FqEmgJNcZpSjNUQqy9u4veSllpxPc2aB%2FpiUjzpbq9XzyFDOQfkUQ%3D%3D";
	/* sp5-saml2 key */
	const char pkey[] = "-----BEGIN CERTIFICATE-----\n\
MIIDnjCCAoagAwIBAgIBATANBgkqhkiG9w0BAQUFADBUMQswCQYDVQQGEwJGUjEP\n\
MA0GA1UECBMGRnJhbmNlMQ4wDAYDVQQHEwVQYXJpczETMBEGA1UEChMKRW50cm91\n\
dmVydDEPMA0GA1UEAxMGRGFtaWVuMB4XDTA2MTAyNzA5MDc1NFoXDTExMTAyNjA5\n\
MDc1NFowVDELMAkGA1UEBhMCRlIxDzANBgNVBAgTBkZyYW5jZTEOMAwGA1UEBxMF\n\
UGFyaXMxEzARBgNVBAoTCkVudHJvdXZlcnQxDzANBgNVBAMTBkRhbWllbjCCASIw\n\
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM06Hx6VgHYR9wUf/tZVVTRkVWNq\n\
h9x+PvHA2qH4OYMuqGs4Af6lU2YsZvnrmRdcFWv0+UkdAgXhReCWAZgtB1pd/W9m\n\
6qDRldCCyysow6xPPKRz/pOTwRXm/fM0QGPeXzwzj34BXOIOuFu+n764vKn18d+u\n\
uVAEzk1576pxTp4pQPzJfdNLrLeQ8vyCshoFU+MYJtp1UA+h2JoO0Y8oGvywbUxH\n\
ioHN5PvnzObfAM4XaDQohmfxM9Uc7Wp4xKAc1nUq5hwBrHpjFMRSz6UCfMoJSGIi\n\
+3xJMkNCjL0XEw5NKVc5jRKkzSkN5j8KTM/k1jPPsDHPRYzbWWhnNtd6JlkCAwEA\n\
AaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0\n\
ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFP2WWMDShux3iF74+SoO1xf6qhqaMB8G\n\
A1UdIwQYMBaAFGjl6TRXbQDHzSlZu+e8VeBaZMB5MA0GCSqGSIb3DQEBBQUAA4IB\n\
AQAZ/imK7UMognXbs5RfSB8cMW6iNAI+JZqe9XWjvtmLfIIPbHM96o953SiFvrvQ\n\
BZjGmmPMK3UH29cjzDx1R/RQaYTyMrHyTePLh3BMd5mpJ/9eeJCSxPzE2ECqWRUa\n\
pkjukecFXqmRItwgTxSIUE9QkpzvuQRb268PwmgroE0mwtiREADnvTFkLkdiEMew\n\
fiYxZfJJLPBqwlkw/7f1SyzXoPXnz5QbNwDmrHelga6rKSprYKb3pueqaIe8j/AP\n\
NC1/bzp8cGOcJ88BD5+Ny6qgPVCrMLE5twQumJ12V3SvjGNtzFBvg2c/9S5OmVqR\n\
LlTxKnCrWAXftSm1rNtewTsF\n\
-----END CERTIFICATE-----";

	xmlSecKeyPtr key = lasso_xmlsec_load_private_key_from_buffer(pkey, sizeof(pkey)-1, NULL,
			LASSO_SIGNATURE_METHOD_RSA_SHA256, NULL);

	ck_assert_msg(key != NULL, "Cannot load public key");
	ck_assert_msg(lasso_saml2_query_verify_signature(query1, key) == 0, "Signature was not validated");
	/* test reordering and semi-colon separator support */
	ck_assert_msg(lasso_saml2_query_verify_signature(query2, key) == 0, "Disordered signature was not validated");
	ck_assert_msg(lasso_saml2_query_verify_signature(query3, key) != 0, "Altered signature was validated");
	xmlSecKeyDestroy(key);
}
END_TEST


START_TEST(test08_lasso_key)
{
	/* normal query as produces by Lasso */
	const char query1[] = "SAMLRequest=fVHJasMwEP0Vo3tqRXY2YRvcOIFAl9CUHnopwpkkAllyNeMuf1%2FZaSG95PrmLfNmMlSNaWXZ0ck%2BwXsHSNFXYyzKYZCzzlvpFGqUVjWAkmq5K%2B%2FvpLjhsvWOXO0Mu5BcVyhE8KSdZdGmytnbNEmTBV%2Bli9ulKMt5KlbVfDkbizWfcVEmUxa9gMfAz1mQBxFiBxuLpCwFiIvxiE9H48mz4FJMZJq8sqgKHbRVNKhORK2MY71vJzFqezSw00f7GPLXztcw9M7ZQRmE3n0bFtQf8IcUWV9JDqm%2B%2BPXCYNUAqb0ilcWXhOx8zIdQe1NtndH1dx%2FTKLp%2BlR7R%2B9FhoMq2b4wEllhUGuM%2Blx4UhZ3Id8Di4pz5%2F2fFDw%3D%3D&RelayState=fake&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=Zfz3DE1VMV3thaV4FWpH0fkWsBMzAFJcfvVWAbo0a3cY48Et%2BXUcbr1nvOJUJmhGoie0pQ4%2BcD9ToQlSk7BbJSBCct%2FQQgn2QNkX%2F1lk4v8RU8p5ptJRJ2iPLb8nC6WZhs81HoihQePSuj7Qe5bRUsDKvnWMq6OkD%2Fe6YO77dMXregTcfmnkrXqRb2T6TFfqyOz9i0%2FjmISsmj%2F3kEEfUzVA4LEbeEgiJDj1hec4XW26gQTih53v0sYukq4Eyb4zS2jVd3apUUxUrjn1NUpr7Z7dZ7w5MQlgZ8aw1xFDE8BkxymvIjwf8ciyx6sfTKbCRsoS9E0pQB1vxvh6OMt1Ww%3D%3D";
	/* SAMLRequest field was moved in the middle, Signature to the beginning and all & were
	 * changed to ; */
	const char query2[] = "Signature=Zfz3DE1VMV3thaV4FWpH0fkWsBMzAFJcfvVWAbo0a3cY48Et%2BXUcbr1nvOJUJmhGoie0pQ4%2BcD9ToQlSk7BbJSBCct%2FQQgn2QNkX%2F1lk4v8RU8p5ptJRJ2iPLb8nC6WZhs81HoihQePSuj7Qe5bRUsDKvnWMq6OkD%2Fe6YO77dMXregTcfmnkrXqRb2T6TFfqyOz9i0%2FjmISsmj%2F3kEEfUzVA4LEbeEgiJDj1hec4XW26gQTih53v0sYukq4Eyb4zS2jVd3apUUxUrjn1NUpr7Z7dZ7w5MQlgZ8aw1xFDE8BkxymvIjwf8ciyx6sfTKbCRsoS9E0pQB1vxvh6OMt1Ww%3D%3D;SAMLRequest=fVHJasMwEP0Vo3tqRXY2YRvcOIFAl9CUHnopwpkkAllyNeMuf1%2FZaSG95PrmLfNmMlSNaWXZ0ck%2BwXsHSNFXYyzKYZCzzlvpFGqUVjWAkmq5K%2B%2FvpLjhsvWOXO0Mu5BcVyhE8KSdZdGmytnbNEmTBV%2Bli9ulKMt5KlbVfDkbizWfcVEmUxa9gMfAz1mQBxFiBxuLpCwFiIvxiE9H48mz4FJMZJq8sqgKHbRVNKhORK2MY71vJzFqezSw00f7GPLXztcw9M7ZQRmE3n0bFtQf8IcUWV9JDqm%2B%2BPXCYNUAqb0ilcWXhOx8zIdQe1NtndH1dx%2FTKLp%2BlR7R%2B9FhoMq2b4wEllhUGuM%2Blx4UhZ3Id8Di4pz5%2F2fFDw%3D%3D;RelayState=fake;SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
	const char query3[] = "SAMLRequest=fVHJasMwEP0Vo3tqRXY2YRvcOIFAl9CUHnopwpkkAllyNeMuf1%2FZaSG95PrmLfNmMlSNaWXZ0ck%2BwXsHSNFXYyzKYZCzzlvpFGqUVjWAkmq5K%2B%2FvpLjhsvWOXO0Mu5BcVyhE8KSdZdGmytnbNEmTBV%2Bli9ulKMt5KlbVfDkbizWfcVEmUxa9gMfAz1mQBxFiBxuLpCwFiIvxiE9H48mz4FJMZJq8sqgKHbRVNKhORK2MY71vJzFqezSw00f7GPLXztcw9M7ZQRmE3n0bFtQf8IcUWV9JDqm%2B%2BPXCYNUAqb0ilcWXhOx8zIdQe1NtndH1dx%2FTKLp%2BlR7R%2B9FhoMq2b4wEllhUGuM%2Blx4UhZ3Id8Di4pz5%2F2fFDw%3D%3D&RelayState=fake&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=rUJ%2B9wVSvdGSmZWGuGXgudAPV5KBxRfxRKraBWGIslBz2XreyNbQjSA47DhIfi%2Bxf0awIIGkKcieN3Qd5sqVn4wvFU8fsmfqrdtouYi46aKsj4W91N19TxJ%2BCgrP7ygVEGDaGdc%2BrCQC3%2FuoYTELXq0gYP7tHaXA%2FCaZHfx5Z159crpRxS6eabZ6BGf4ImxiKhE1FuYzKHeISEV1iSyvgx5%2FE8ydSO%2FSP6yA5Rck4JxVJWH6ImbswCVQ80qfqR4NoJ%2BxiZqilbDJnQaSKZggx%2FgjNVoX%2FMVW1FqEmgJNcZpSjNUQqy9u4veSllpxPc2aB%2FpiUjzpbq9XzyFDOQfkUQ%3D%3D";
	/* sp5-saml2 key */
	const char pkey[] = "-----BEGIN CERTIFICATE-----\n\
MIIDnjCCAoagAwIBAgIBATANBgkqhkiG9w0BAQUFADBUMQswCQYDVQQGEwJGUjEP\n\
MA0GA1UECBMGRnJhbmNlMQ4wDAYDVQQHEwVQYXJpczETMBEGA1UEChMKRW50cm91\n\
dmVydDEPMA0GA1UEAxMGRGFtaWVuMB4XDTA2MTAyNzA5MDc1NFoXDTExMTAyNjA5\n\
MDc1NFowVDELMAkGA1UEBhMCRlIxDzANBgNVBAgTBkZyYW5jZTEOMAwGA1UEBxMF\n\
UGFyaXMxEzARBgNVBAoTCkVudHJvdXZlcnQxDzANBgNVBAMTBkRhbWllbjCCASIw\n\
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM06Hx6VgHYR9wUf/tZVVTRkVWNq\n\
h9x+PvHA2qH4OYMuqGs4Af6lU2YsZvnrmRdcFWv0+UkdAgXhReCWAZgtB1pd/W9m\n\
6qDRldCCyysow6xPPKRz/pOTwRXm/fM0QGPeXzwzj34BXOIOuFu+n764vKn18d+u\n\
uVAEzk1576pxTp4pQPzJfdNLrLeQ8vyCshoFU+MYJtp1UA+h2JoO0Y8oGvywbUxH\n\
ioHN5PvnzObfAM4XaDQohmfxM9Uc7Wp4xKAc1nUq5hwBrHpjFMRSz6UCfMoJSGIi\n\
+3xJMkNCjL0XEw5NKVc5jRKkzSkN5j8KTM/k1jPPsDHPRYzbWWhnNtd6JlkCAwEA\n\
AaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0\n\
ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFP2WWMDShux3iF74+SoO1xf6qhqaMB8G\n\
A1UdIwQYMBaAFGjl6TRXbQDHzSlZu+e8VeBaZMB5MA0GCSqGSIb3DQEBBQUAA4IB\n\
AQAZ/imK7UMognXbs5RfSB8cMW6iNAI+JZqe9XWjvtmLfIIPbHM96o953SiFvrvQ\n\
BZjGmmPMK3UH29cjzDx1R/RQaYTyMrHyTePLh3BMd5mpJ/9eeJCSxPzE2ECqWRUa\n\
pkjukecFXqmRItwgTxSIUE9QkpzvuQRb268PwmgroE0mwtiREADnvTFkLkdiEMew\n\
fiYxZfJJLPBqwlkw/7f1SyzXoPXnz5QbNwDmrHelga6rKSprYKb3pueqaIe8j/AP\n\
NC1/bzp8cGOcJ88BD5+Ny6qgPVCrMLE5twQumJ12V3SvjGNtzFBvg2c/9S5OmVqR\n\
LlTxKnCrWAXftSm1rNtewTsF\n\
-----END CERTIFICATE-----";
	LassoKey *key = lasso_key_new_for_signature_from_memory(pkey, strlen(pkey), NULL,
			LASSO_SIGNATURE_METHOD_RSA_SHA256, NULL);
	LassoKey *key2 = lasso_key_new_for_signature_from_file(
			TESTSDATADIR "/sp5-saml2/private-key.pem", NULL,
			LASSO_SIGNATURE_METHOD_RSA_SHA256, NULL);
	char *message = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><s:Body><samlp:ArtifactResolve ID=\"_5E4DB038BC15C020CE085F743D485443\" Version=\"2.0\" IssueInstant=\"2021-06-18T16:07:49Z\" Destination=\"http://idp5/artifact\"><saml:Issuer>http://sp5/metadata</saml:Issuer><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n\
<SignedInfo>\n\
<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n\
<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n\
<Reference URI=\"#_5E4DB038BC15C020CE085F743D485443\">\n\
<Transforms>\n\
<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n\
<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n\
</Transforms>\n\
<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n\
<DigestValue>1Xy/VevGqojdKIvLzkczdd9Mp3AFYvZfsakldADTuO4=</DigestValue>\n\
</Reference>\n\
</SignedInfo>\n\
<SignatureValue>R5unK5JQ8no8VCokUKKw8zXglIsjggH16cQxnqKl2GpFeeFh8Tzi4KRXTzVNXi9c\n\
dID0FTAsFM2Ol5Sqg/j2TVasR93PyIg2pUOb00tNwx8D81xEi1lXdWThHfiinYI0\n\
2qJSFj1H8wt/ceULmnvC0F01ga78LQervkjMaSpqlvyKYrNNOEJEYo0SJSUnUE5p\n\
wlv30BjnUCyXWQl9i03MvpPSOTJkXrFLqbJB8rB/HNdS71lWAU3k8r56OAxzTXUn\n\
WXr73mrQrLGJzbofDjO1Lfz8JpZXRzsffAsMCxKfoL+VzrElPNW5aklrFm603w2w\n\
6/xQk0BsHvPP8k6V32RuXQ==</SignatureValue>\n\
<KeyInfo>\n\
<KeyValue>\n\
<RSAKeyValue>\n\
<Modulus>\n\
zTofHpWAdhH3BR/+1lVVNGRVY2qH3H4+8cDaofg5gy6oazgB/qVTZixm+euZF1wV\n\
a/T5SR0CBeFF4JYBmC0HWl39b2bqoNGV0ILLKyjDrE88pHP+k5PBFeb98zRAY95f\n\
PDOPfgFc4g64W76fvri8qfXx3665UATOTXnvqnFOnilA/Ml900ust5Dy/IKyGgVT\n\
4xgm2nVQD6HYmg7Rjyga/LBtTEeKgc3k++fM5t8AzhdoNCiGZ/Ez1RztanjEoBzW\n\
dSrmHAGsemMUxFLPpQJ8yglIYiL7fEkyQ0KMvRcTDk0pVzmNEqTNKQ3mPwpMz+TW\n\
M8+wMc9FjNtZaGc213omWQ==\n\
</Modulus>\n\
<Exponent>\n\
AQAB\n\
</Exponent>\n\
</RSAKeyValue>\n\
</KeyValue>\n\
</KeyInfo>\n\
</Signature><samlp:Artifact>AAQAALQUO+cobSry7mQpUjWDhKkaePFoNDRBMDY3RDY3QjNFM0QzQzA1NzQ=</samlp:Artifact></samlp:ArtifactResolve></s:Body></s:Envelope>";
	xmlDoc *doc;

	doc = xmlParseDoc(BAD_CAST message);
	ck_assert_msg(key != NULL, "Cannot load public key");
	ck_assert_msg(lasso_key_query_verify(key, query1) == 0, "Signature was not validated");
	/* test reordering and semi-colon separator support */
	ck_assert_msg(lasso_key_query_verify(key, query2) == 0, "Disordered signature was not validated");
	ck_assert_msg(lasso_key_query_verify(key, query3) != 0, "Altered signature was validated");
	ck_assert_msg(lasso_key_saml2_xml_verify(key,
		"_5E4DB038BC15C020CE085F743D485443", xmlDocGetRootElement(doc)) == 0,
		"XML Signature is not validated");
	g_object_unref(key);
	ck_assert_msg(key2 != NULL, "Cannot load public key2");
	ck_assert_msg(lasso_key_query_verify(key2, query1) == 0, "Signature was not validated");
	/* test reordering and semi-colon separator support */
	ck_assert_msg(lasso_key_query_verify(key2, query2) == 0, "Disordered signature was not validated");
	ck_assert_msg(lasso_key_query_verify(key2, query3) != 0, "Altered signature was validated");
	ck_assert_msg(lasso_key_saml2_xml_verify(key2,
		"_5E4DB038BC15C020CE085F743D485443", xmlDocGetRootElement(doc)) == 0,
		"XML Signature is not validated");
	g_object_unref(key2);
	lasso_release_doc(doc);
}
END_TEST

Suite*
random_suite()
{
	Suite *s = suite_create("Random tests");
	TCase *tc_providers = tcase_create("Provider stuffs");
	TCase *tc_servers = tcase_create("Server stuffs");
	TCase *tc_node = tcase_create("Node stuff");
	TCase *tc_keys = tcase_create("Lasso keys");

	suite_add_tcase(s, tc_providers);
	tcase_add_test(tc_providers, test01_provider_new);
	tcase_add_test(tc_providers, test02_provider_new_from_dump);

	suite_add_tcase(s, tc_servers);
	tcase_add_test(tc_servers, test01_server_new);
	tcase_add_test(tc_servers, test02_server_add_provider);
	tcase_add_test(tc_servers, test03_server_new_from_dump);

	suite_add_tcase(s, tc_node);
	tcase_add_test(tc_node, test04_node_new_from_dump);
	tcase_add_test(tc_node, test05_xsi_type);
	tcase_add_test(tc_node, test06_lib_statuscode);
	tcase_add_test(tc_node, test07_saml2_query_verify_signature);

	suite_add_tcase(s, tc_keys);
	tcase_add_test(tc_keys, test08_lasso_key);

	return s;
}

