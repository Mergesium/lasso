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
#include "../lasso/xml/strings.h"
#include "../lasso/xml/xml_idff.h"
#include "../lasso/xml/saml-2.0/xml_saml2.h"
#include "../lasso/xml/soap-1.1/xml_soap11.h"
#include "../lasso/utils.h"
#include "../lasso/xml/private.h"
#include <libxml/tree.h>
#include "tests.h"

START_TEST(test01_server_load_dump_empty_string)
{
	LassoServer *serverContext;
	serverContext = lasso_server_new_from_dump("");
	ck_assert_msg(serverContext == NULL,
			"serverContext was created from an empty string dump");
}
END_TEST

START_TEST(test02_server_load_dump_random_string)
{
	LassoServer *serverContext;
	begin_check_do_log("libxml2", G_LOG_LEVEL_DEBUG, "libxml2: Start tag expected, '<' not found\n", FALSE);
	serverContext = lasso_server_new_from_dump("foo");
	end_check_do_log("libxml2");
	ck_assert_msg(serverContext == NULL,
			"serverContext was created from a fake dump");
}
END_TEST

START_TEST(test03_server_load_dump_random_xml)
{
	LassoServer *serverContext;
	begin_check_do_log(NULL, G_LOG_LEVEL_CRITICAL, " Unable to build a LassoNode from a xmlNode", TRUE);
	serverContext = lasso_server_new_from_dump("<?xml version=\"1.0\"?><foo/>");
	end_check_do_log(NULL);
	ck_assert_msg(serverContext == NULL,
			"serverContext was created from fake (but valid XML) dump");
}
END_TEST


START_TEST(test04_identity_load_dump_null)
{
	LassoIdentity *identity;

	identity = lasso_identity_new_from_dump(NULL);
	ck_assert_msg(identity == NULL, "identity was created from NULL dump");
}
END_TEST

START_TEST(test05_identity_load_dump_empty)
{
	LassoIdentity *identity;

	identity = lasso_identity_new_from_dump("");
	ck_assert_msg(identity == NULL, "identity was created from empty dump");
}
END_TEST

#include "../lasso/registry.h"

START_TEST(test06_registry_direct_mapping)
{
	const char *name;
	gint r;

	r = lasso_registry_default_add_direct_mapping(LASSO_LIB_HREF, "test", LASSO_LASSO_HREF,
			"LassoTestClass");
	ck_assert_msg(r == 0, "lasso_registry_default_add_direct_mapping should return 0 for new mappings");
	name = lasso_registry_default_get_mapping(LASSO_LIB_HREF, "test", LASSO_LASSO_HREF);
	ck_assert_msg(name != NULL, "lasso_registry_default_get_mapping should return the recent mapping");
	ck_assert_msg(strcmp(name, "LassoTestClass") == 0, "lasso_registry_default_get_mapping should return LassoTestClass");
	r = lasso_registry_default_add_direct_mapping(LASSO_LIB_HREF, "test", LASSO_LASSO_HREF,
			"LassoTestClass");
	ck_assert_msg(r == LASSO_REGISTRY_ERROR_KEY_EXISTS, "lasso_registry_default_add_direct_mapping should return LASSO_REGISTRY_KEY_EXISTS when done two times");
}
END_TEST

const char *trad(const char *from_namespace, const char *from_name, const char* to_namespace)
{
	if (strcmp(from_namespace, "coin") == 0 &&
			strcmp(to_namespace, LASSO_LASSO_HREF) == 0)
	{
		char *temp = g_strconcat("Lasso", from_name, NULL);
		const char *ret = g_intern_string(temp);
		g_free(temp);
		return ret;
	}
	return NULL;
}


START_TEST(test07_registry_functional_mapping)
{
	const char *name;
	gint r;

	r = lasso_registry_default_add_functional_mapping("coin", LASSO_LASSO_HREF, trad);
	ck_assert_msg(r == 0, "lasso_registry_default_add_functional mapping should return 0 for new mapping");
	name = lasso_registry_default_get_mapping("coin", "Assertion", LASSO_LASSO_HREF);
	ck_assert_msg(name != NULL, "lasso_registry_default_get_mapping should return the recent mapping");
	ck_assert_msg(strcmp(name, "LassoAssertion") == 0, "lasso_registry_default_get_mapping should return LassoAssertion");
	r = lasso_registry_default_add_functional_mapping("coin", LASSO_LASSO_HREF, trad);
	ck_assert_msg(r == LASSO_REGISTRY_ERROR_KEY_EXISTS, "lasso_registry_default_add_functional_mapping should return LASSO_REGISTRY_KEY_EXISTS when done two times");
}
END_TEST

static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
};

static void
class_init(LassoNodeClass *klass, gpointer class_data G_GNUC_UNUSED)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Assertion");
	lasso_node_class_set_ns(nclass,LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

}

START_TEST(test08_test_new_from_xmlNode)
{
	gint r;
	LassoNode *node = NULL;

	static const GTypeInfo this_info = {
		sizeof (LassoNodeClass),
		NULL,
		NULL,
		(GClassInitFunc) class_init,
		NULL,
		NULL,
		sizeof(LassoNode),
		0,
		NULL,
		NULL
	};

	g_type_register_static(LASSO_TYPE_NODE,
			"LassoTest", &this_info, 0);
	r = lasso_registry_default_add_direct_mapping("http://example.com", "Test1", LASSO_LASSO_HREF, "LassoTest");
	ck_assert_msg(r == 0, "no mapping for http://example.com:Test1 should exist");
	begin_check_do_log(NULL, G_LOG_LEVEL_WARNING, "	Class LassoTest has no node_data so no initialization is possible", TRUE);
	node = lasso_node_new_from_dump("<Test1 xmlns=\"http://example.com\"></Test1>");
	end_check_do_log(NULL);
	ck_assert_msg(node != NULL, "parsing <Test1/> should return an object");
	ck_assert_msg(strcmp(G_OBJECT_TYPE_NAME(node), "LassoTest") == 0, "node classname should be LassoTest");
	g_object_unref(node);
}
END_TEST

START_TEST(test09_test_deserialization)
{
	char *content = NULL;
	size_t len = 0;
	LassoNode *node;

	g_file_get_contents(TESTSDATADIR "/response-1", &content, &len, NULL);

	ck_assert_msg(content != NULL, "content should be read");
	node = lasso_node_new_from_dump(content);
	ck_assert_msg(node != NULL, "node should be parsed");
	g_object_unref(node);
	g_free(content);
}
END_TEST

/* try to test all new functions and their associated deserialization codes */
START_TEST(test10_test_alldumps)
{
	LassoNode *node, *node2;
	char *node_dump;

	node = LASSO_NODE(lasso_identity_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_identity_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_session_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_session_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_ds_key_info_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_ds_key_info_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_ds_key_value_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_ds_key_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_ds_rsa_key_value_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_ds_rsa_key_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* ID-FF 1.2 */
	node = LASSO_NODE(lasso_lib_assertion_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_assertion_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_authn_context_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_authn_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_authn_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_authn_request_envelope_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_authn_request_envelope_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_federation_termination_notification_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_federation_termination_notification_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_idp_entries_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_idp_entries_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_idp_entry_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_idp_entry_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_idp_list_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_idp_list_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_logout_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_logout_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_logout_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_logout_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_name_identifier_mapping_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_name_identifier_mapping_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_name_identifier_mapping_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_name_identifier_mapping_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_register_name_identifier_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_register_name_identifier_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_register_name_identifier_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_register_name_identifier_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_request_authn_context_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_request_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_scoping_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_scoping_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_subject_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_subject_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_misc_text_node_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg(node_dump && strcmp(node_dump, "<XXX/>") == 0, "LassoMiscTextNode dump failed");
	lasso_release_string(node_dump);
	lasso_release_gobject(node);
	/* SAML 2.0 */
	node = LASSO_NODE(lasso_saml2_action_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_action_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_advice_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_advice_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_assertion_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_assertion_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_attribute_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_attribute_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_attribute_statement_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_attribute_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_attribute_value_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_attribute_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_audience_restriction_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_audience_restriction_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_authn_context_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_authn_statement_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_authn_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_authz_decision_statement_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_authz_decision_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_base_idabstract_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_base_idabstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_condition_abstract_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_condition_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_conditions_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_conditions_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_encrypted_element_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_encrypted_element_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_evidence_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_evidence_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_key_info_confirmation_data_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_key_info_confirmation_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_name_id_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_name_id_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_one_time_use_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_one_time_use_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_proxy_restriction_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_proxy_restriction_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_statement_abstract_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_statement_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_confirmation_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_confirmation_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_confirmation_data_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_confirmation_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_locality_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_locality_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_artifact_resolve_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_artifact_resolve_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_artifact_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_artifact_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_assertion_id_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_assertion_id_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_attribute_query_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_attribute_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_authn_query_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_authn_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_authn_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_authn_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_authz_decision_query_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_authz_decision_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_extensions_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_extensions_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_idp_entry_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_idp_entry_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_idp_list_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_idp_list_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
/*	node = LASSO_NODE(lasso_samlp2_logout_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_logout_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node); */
	node = LASSO_NODE(lasso_samlp2_logout_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_logout_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
/*	node = LASSO_NODE(lasso_samlp2_manage_name_id_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_manage_name_id_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node); */
	node = LASSO_NODE(lasso_samlp2_manage_name_id_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_manage_name_id_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_name_id_mapping_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_name_id_mapping_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_name_id_mapping_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_name_id_mapping_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_name_id_policy_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_name_id_policy_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_request_abstract_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_request_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_requested_authn_context_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_requested_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_scoping_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_scoping_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_code_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_code_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_detail_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_detail_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_subject_query_abstract_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_subject_query_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_terminate_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_terminate_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* SAML 1.0 */
	node = LASSO_NODE(lasso_saml_advice_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_advice_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_assertion_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_assertion_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_designator_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_designator_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_statement_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_value_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_audience_restriction_condition_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_audience_restriction_condition_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_authentication_statement_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_authentication_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_authority_binding_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_authority_binding_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_conditions_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_conditions_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_name_identifier_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_name_identifier_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_subject_confirmation_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_subject_confirmation_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_subject_statement_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_subject_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_request_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_response_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_status_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_status_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_status_code_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_status_code_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* SOAP */
	node = LASSO_NODE(lasso_soap_body_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_body_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_detail_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_detail_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_fault_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_fault_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_header_new());
	node_dump = lasso_node_dump(node);
	ck_assert_msg((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_header_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* test deserialization of saml2:EncryptedAssertion" */
	const char *encrypted_element_xml[] = {
	"<EncryptedAssertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</EncryptedAssertion>",
	"<EncryptedID xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</EncryptedID>",
	"<EncryptedAttribute xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</EncryptedAttribute>",
	"<NewEncryptedID xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</NewEncryptedID>", NULL };
	const char **iter = encrypted_element_xml;
	while (*iter) {
		xmlDoc *xmldoc;
		LassoNode *node;

		xmldoc = xmlParseDoc (BAD_CAST (*iter));
		ck_assert_msg(xmldoc != NULL, "Failed to parse %s: no xmldoc", *iter);
		ck_assert_msg(xmlDocGetRootElement (xmldoc) != NULL, "Failed to parse %s: no root node element", *iter);
		node = lasso_node_new_from_xmlNode(xmlDocGetRootElement(xmldoc));
		ck_assert_msg(LASSO_IS_SAML2_ENCRYPTED_ELEMENT (node), "Parsing of %s did not return a saml2:EncryptedElement, %s", (char*)*iter, g_type_name(G_TYPE_FROM_INSTANCE(node)));
		g_object_unref(node);
		lasso_release_doc(xmldoc);
		++iter;
	}
}
END_TEST

/* test NameIDFormat extraction */
START_TEST(test11_get_default_name_id_format)
{
	LassoProvider *provider;
	char *name_id_format;
	const GList *name_id_formats;

	provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP, TESTSDATADIR "/sp5-saml2/metadata.xml", NULL, NULL);
	ck_assert_msg(provider != NULL, "lasso_provider_new failed on metadata file: %s", TESTSDATADIR "/sp5-saml2/metadata.xml");
	name_id_format = lasso_provider_get_default_name_id_format(provider);
	ck_assert_msg(name_id_format != NULL, "no default name id format found!");
	ck_assert_msg(strcmp(name_id_format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL) == 0, "default name id format is not email, it is: %s", name_id_format);
	lasso_release_string(name_id_format);
	name_id_formats = lasso_provider_get_metadata_list(provider, "NameIDFormat");
	ck_assert_msg(g_list_length((GList*)name_id_formats) == 1, "lasso_provider_get_metadata_list returned more or less than 1 NameIDFormat: %u", g_list_length((GList*)name_id_formats));
	ck_assert_msg(name_id_formats->data != NULL, "first name id format is NULL");
	ck_assert_msg(strcmp((char*)name_id_formats->data, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL) == 0, "first name id format is not email, it is %s", (char*)name_id_formats->data);
	/* cleanup */
	lasso_release_gobject(provider);
}
END_TEST

#include <stdio.h>

/* test load federation */
START_TEST(test13_test_lasso_server_load_metadata)
{
	LassoServer *server = NULL;
	GList *loaded_entity_ids = NULL;
	GList blacklisted_1 = { .data = "https://identities.univ-jfc.fr/idp/prod", .next = NULL };
	const gchar *trusted_roots = TESTSDATADIR "/rootCA.crt";

	/* The IDP metadata file is signed with rsa-sha1, so verifying it would
	 * fail incase sha1 is not available
	 */
	if (lasso_get_default_signature_method() != LASSO_SIGNATURE_METHOD_RSA_SHA1) {
		trusted_roots = NULL;
	}

	check_not_null(server = lasso_server_new(
			TESTSDATADIR "/idp5-saml2/metadata.xml",
			TESTSDATADIR "/idp5-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL));
	block_lasso_logs;
	check_good_rc(lasso_server_load_metadata(server, LASSO_PROVIDER_ROLE_IDP,
				TESTSDATADIR "/metadata/renater-metadata.xml",
				trusted_roots,
				&blacklisted_1, &loaded_entity_ids,
				LASSO_SERVER_LOAD_METADATA_FLAG_DEFAULT));
	unblock_lasso_logs;
	check_equals(g_hash_table_size(server->providers), 110);
	check_equals(g_list_length(loaded_entity_ids), 110);

	lasso_release_list_of_strings(loaded_entity_ids);

	lasso_release_gobject(server);
}
END_TEST

#include "../lasso/key.h"

/* test load federation */
START_TEST(test14_lasso_key)
{
	LassoKey *key;
	char *buffer;
	gsize length;
	char *base64_encoded;

	check_true(g_file_get_contents(TESTSDATADIR "sp1-la/private-key-raw.pem", &buffer, &length, NULL));
	check_not_null(key = lasso_key_new_for_signature_from_memory(buffer,
				length, NULL, lasso_get_default_signature_method(),
				NULL));
	lasso_release_gobject(key);
	check_not_null(key = lasso_key_new_for_signature_from_file(TESTSDATADIR
				"sp1-la/private-key-raw.pem", NULL, lasso_get_default_signature_method(),
				NULL));
	lasso_release_gobject(key);
	base64_encoded = g_base64_encode(BAD_CAST buffer, length);
	check_not_null(key = lasso_key_new_for_signature_from_base64_string(base64_encoded, NULL,
				lasso_get_default_signature_method(), NULL));
	lasso_release_string(base64_encoded);
	lasso_release_string(buffer);
	lasso_release_gobject(key);
}
END_TEST

/* test load federation */
START_TEST(test15_ds_key_info)
{
	LassoDsKeyInfo *ds_key_info = lasso_ds_key_info_new();
	LassoDsKeyValue *ds_key_value = lasso_ds_key_value_new();
	LassoDsX509Data *x509_data = lasso_ds_x509_data_new();
	char *dump;
	GList list;
	LassoNode *node;

	lasso_ds_x509_data_set_certificate(x509_data, "coucou");
	lasso_ds_key_value_set_x509_data(ds_key_value, x509_data);
	ds_key_info->KeyValue = g_object_ref(ds_key_value);
	dump = lasso_node_debug((LassoNode*)ds_key_info, 10);
	lasso_release_gobject(ds_key_info);
	lasso_release_gobject(ds_key_value);
	lasso_release_gobject(x509_data);
	ds_key_info = (LassoDsKeyInfo*)lasso_node_new_from_dump(dump);
	lasso_release_string(dump);
	check_not_null(ds_key_info);
	check_true(LASSO_IS_DS_KEY_INFO(ds_key_info));
	check_not_null(ds_key_info->KeyValue);
	check_true(LASSO_IS_DS_KEY_VALUE(ds_key_info->KeyValue));
	x509_data = lasso_ds_key_value_get_x509_data(ds_key_info->KeyValue);
	check_not_null(x509_data);
	check_true(LASSO_IS_DS_X509_DATA(x509_data));
	check_str_equals(lasso_ds_x509_data_get_certificate(x509_data), "coucou");
	/* LassoSaml2SubjectConfirmation */
	LassoSaml2SubjectConfirmation *sc = (LassoSaml2SubjectConfirmation*) \
			lasso_saml2_subject_confirmation_new();
	LassoSaml2KeyInfoConfirmationDataType *kicdt = (LassoSaml2KeyInfoConfirmationDataType*) \
			lasso_saml2_key_info_confirmation_data_type_new();
	lasso_assign_string(sc->Method, LASSO_SAML2_CONFIRMATION_METHOD_HOLDER_OF_KEY);
	lasso_assign_new_gobject(sc->SubjectConfirmationData, &kicdt->parent);
	list = (GList){ .data = ds_key_info, .next = NULL, .prev = NULL };
	lasso_saml2_key_info_confirmation_data_type_set_key_info(kicdt, &list);
	dump = lasso_node_debug((LassoNode*)sc, 10);
	lasso_release_gobject(sc);
	lasso_release_gobject(ds_key_info);
	node = lasso_node_new_from_dump(dump);
	lasso_release_string(dump);
	dump = lasso_node_debug(node, 10);
	lasso_release_string(dump);
	lasso_release_gobject(node);
}
END_TEST

/* test get issuer */
START_TEST(test16_test_get_issuer)
{
	char *content = NULL;
	size_t len = 0;
	char *issuer = NULL;
	char *in_response_to = NULL;
	LassoServer *spServerContext = NULL;
	LassoServer *idpServerContext = NULL;
	LassoLogin *spLoginContext = NULL;
	LassoLogin *idpLoginContext = NULL;
	LassoSamlp2AuthnRequest *request = NULL;
	char *authnRequestUrl = NULL;
	char *qs = NULL;

	g_file_get_contents(TESTSDATADIR "/response-1", &content, &len, NULL);
	issuer = lasso_profile_get_issuer(content);
	check_str_equals(issuer, "gefssstg");
	lasso_release_string(issuer);
	in_response_to = lasso_profile_get_in_response_to(content);
	check_str_equals(in_response_to, "xx");
	lasso_release_string(in_response_to);
	lasso_release_string(content);

	spServerContext = lasso_server_new(
			TESTSDATADIR "/sp5-saml2/metadata.xml",
			TESTSDATADIR "/sp5-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			spServerContext,
			LASSO_PROVIDER_ROLE_IDP,
			TESTSDATADIR "/idp5-saml2/metadata.xml",
			NULL,
			NULL);
	idpServerContext = lasso_server_new(
			TESTSDATADIR "/idp5-saml2/metadata.xml",
			TESTSDATADIR "/idp5-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			idpServerContext,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp5-saml2/metadata.xml",
			NULL,
			NULL);
	spLoginContext = lasso_login_new(spServerContext);
	check_good_rc(lasso_login_init_authn_request(spLoginContext, "http://idp5/metadata",
			LASSO_HTTP_METHOD_REDIRECT));
	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(spLoginContext)->request);
	request->IsPassive = 0;
	lasso_assign_string(request->NameIDPolicy->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	request->NameIDPolicy->AllowCreate = 1;
	lasso_assign_string(request->ProtocolBinding, LASSO_SAML2_METADATA_BINDING_POST);
	check_good_rc(lasso_login_build_authn_request_msg(spLoginContext));
	authnRequestUrl = LASSO_PROFILE(spLoginContext)->msg_url;
	qs = strchr(authnRequestUrl, '?') + 1;
	issuer = lasso_profile_get_issuer(qs);
	check_true(lasso_strisequal(issuer, "http://sp5/metadata"));
	lasso_release_string(issuer);

	idpLoginContext = lasso_login_new(idpServerContext);
	
	check_good_rc(lasso_login_process_authn_request_msg(idpLoginContext, qs));
	check_good_rc(lasso_login_validate_request_msg(idpLoginContext, 1, 0));
	check_good_rc(lasso_login_build_assertion(idpLoginContext,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	check_good_rc(lasso_login_build_authn_response_msg(idpLoginContext));
	check_not_null(idpLoginContext->parent.msg_body);
	check_not_null(idpLoginContext->parent.msg_url);

	issuer = lasso_profile_get_issuer(idpLoginContext->parent.msg_body);
	in_response_to = lasso_profile_get_in_response_to(idpLoginContext->parent.msg_body);
	check_not_null(in_response_to);
	check_str_equals(issuer, "http://idp5/metadata");
	check_str_equals(in_response_to, request->parent.ID);
	lasso_release_string(issuer);

	lasso_release_gobject(idpLoginContext);
	lasso_release_gobject(idpServerContext);
	lasso_release_gobject(spLoginContext);
	lasso_release_gobject(spServerContext);

	begin_check_do_log("Lasso", G_LOG_LEVEL_DEBUG, "could not decode POST SAML message", TRUE);
	check_null(lasso_profile_get_issuer(""));
	end_check_do_log("Lasso");
	begin_check_do_log("Lasso", G_LOG_LEVEL_DEBUG, "message is not base64", TRUE);
	check_null(lasso_profile_get_issuer("SAMLRequest=!!hello!!"));
	end_check_do_log("Lasso");
}
END_TEST

Suite*
basic_suite()
{
	Suite *s = suite_create("Basic");
	TCase *tc_server_load_dump_empty_string = tcase_create("Create server from empty string");
	TCase *tc_server_load_dump_random_string = tcase_create("Create server from random string");
	TCase *tc_server_load_dump_random_xml = tcase_create("Create server from random XML");
	TCase *tc_identity_load_dump_null = tcase_create("Create identity from NULL");
	TCase *tc_identity_load_dump_empty = tcase_create("Create identity from empty string");
	TCase *tc_registry_direct_mapping = tcase_create("Test QName registry with direct mapping");
	TCase *tc_registry_functional_mapping = tcase_create("Test QName registry with functional mapping");
	TCase *tc_registry_new_from_xmlNode = tcase_create("Test parsing a node that has a mapping to Lasso Object in the registry");
	TCase *tc_response_new_from_xmlNode = tcase_create("Test parsing a message from Ping Federate");
	TCase *tc_all_dumps = tcase_create("Test dumping all kind of nodes");
	TCase *tc_get_default_name_id_format = tcase_create("Test getting default name id format");
	TCase *tc_custom_namespace = tcase_create("Test custom namespace handling");
	TCase *tc_load_metadata = tcase_create("Test loading a federation metadata file");
	TCase *tc_key = tcase_create("Test loading and manipulating LassoKey objects");
	TCase *tc_key_info = tcase_create("Test creating and dumping ds:KeyInfo nodes");
	TCase *tc_get_issuer = tcase_create("Test get_issuer and get_request_id");

	suite_add_tcase(s, tc_server_load_dump_empty_string);
	suite_add_tcase(s, tc_server_load_dump_random_string);
	suite_add_tcase(s, tc_server_load_dump_random_xml);
	suite_add_tcase(s, tc_identity_load_dump_null);
	suite_add_tcase(s, tc_identity_load_dump_empty);
	suite_add_tcase(s, tc_registry_direct_mapping);
	suite_add_tcase(s, tc_registry_functional_mapping);
	suite_add_tcase(s, tc_registry_new_from_xmlNode);
	suite_add_tcase(s, tc_response_new_from_xmlNode);
	suite_add_tcase(s, tc_all_dumps);
	suite_add_tcase(s, tc_get_default_name_id_format);
	suite_add_tcase(s, tc_custom_namespace);
	suite_add_tcase(s, tc_load_metadata);
	suite_add_tcase(s, tc_key);
	suite_add_tcase(s, tc_key_info);
	suite_add_tcase(s, tc_get_issuer);

	tcase_add_test(tc_server_load_dump_empty_string, test01_server_load_dump_empty_string);
	tcase_add_test(tc_server_load_dump_random_string, test02_server_load_dump_random_string);
	tcase_add_test(tc_server_load_dump_random_xml, test03_server_load_dump_random_xml);
	tcase_add_test(tc_identity_load_dump_null, test04_identity_load_dump_null);
	tcase_add_test(tc_identity_load_dump_empty, test05_identity_load_dump_empty);
	tcase_add_test(tc_registry_direct_mapping, test06_registry_direct_mapping);
	tcase_add_test(tc_registry_functional_mapping, test07_registry_functional_mapping);
	tcase_add_test(tc_registry_new_from_xmlNode, test08_test_new_from_xmlNode);
	tcase_add_test(tc_response_new_from_xmlNode, test09_test_deserialization);
	tcase_add_test(tc_all_dumps, test10_test_alldumps);
	tcase_add_test(tc_get_default_name_id_format, test11_get_default_name_id_format);
	tcase_add_test(tc_load_metadata, test13_test_lasso_server_load_metadata);
	tcase_add_test(tc_key, test14_lasso_key);
	tcase_add_test(tc_key_info, test15_ds_key_info);
	tcase_add_test(tc_get_issuer, test16_test_get_issuer);
	tcase_set_timeout(tc_load_metadata, 10);
	return s;
}

