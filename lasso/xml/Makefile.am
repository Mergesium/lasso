MAINTAINERCLEANFILES = Makefile.in
SUBDIRS = saml-2.0 soap-1.1 dsig ecp

liblassoincludedir = $(includedir)/lasso/xml

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml.la

liblasso_xml_la_SOURCES = \
	tools.c \
	xml.c \
	lib_assertion.c	\
	lib_authentication_statement.c \
	lib_authn_context.c	\
	lib_authn_request.c	\
	lib_authn_request_envelope.c	\
	lib_authn_response.c \
	lib_authn_response_envelope.c \
	lib_federation_termination_notification.c \
	lib_idp_entries.c	\
	lib_idp_entry.c	\
	lib_idp_list.c	\
	lib_logout_request.c \
	lib_logout_response.c \
	lib_name_identifier_mapping_request.c \
	lib_name_identifier_mapping_response.c \
	lib_register_name_identifier_request.c \
	lib_register_name_identifier_response.c \
	lib_request_authn_context.c	\
	lib_scoping.c \
	lib_status_response.c \
	lib_subject.c \
	misc_text_node.c \
	paos_request.c \
	paos_response.c \
	saml_advice.c \
	saml_assertion.c \
	saml_attribute.c \
	saml_attribute_designator.c \
	saml_attribute_statement.c \
	saml_attribute_value.c \
	saml_audience_restriction_condition.c \
	saml_authentication_statement.c \
	saml_authority_binding.c \
	saml_condition_abstract.c \
	saml_conditions.c \
	saml_name_identifier.c \
	saml_statement_abstract.c \
	saml_subject.c \
	saml_subject_confirmation.c \
	saml_subject_locality.c \
	saml_subject_statement.c \
	saml_subject_statement_abstract.c \
	samlp_request.c \
	samlp_request_abstract.c \
	samlp_response.c \
	samlp_response_abstract.c \
	samlp_status.c \
	samlp_status_code.c

liblassoinclude_HEADERS = \
	strings.h \
	xml.h \
	lib_assertion.h	\
	lib_authentication_statement.h \
	lib_authn_context.h	\
	lib_authn_request.h	\
	lib_authn_request_envelope.h	\
	lib_authn_response.h \
	lib_authn_response_envelope.h \
	lib_federation_termination_notification.h \
	lib_idp_entries.h	\
	lib_idp_entry.h	\
	lib_idp_list.h	\
	lib_logout_request.h \
	lib_logout_response.h \
	lib_name_identifier_mapping_request.h \
	lib_name_identifier_mapping_response.h \
	lib_register_name_identifier_request.h \
	lib_register_name_identifier_response.h \
	lib_request_authn_context.h	\
	lib_scoping.h \
	lib_status_response.h \
	lib_subject.h \
	misc_text_node.h \
	paos_request.h \
	paos_response.h \
	saml_advice.h \
	saml_assertion.h \
	saml_attribute.h \
	saml_attribute_designator.h \
	saml_attribute_statement.h \
	saml_attribute_value.h \
	saml_audience_restriction_condition.h \
	saml_authentication_statement.h \
	saml_authority_binding.h \
	saml_condition_abstract.h \
	saml_conditions.h \
	saml_name_identifier.h \
	saml_statement_abstract.h \
	saml_subject.h \
	saml_subject_confirmation.h \
	saml_subject_locality.h \
	saml_subject_statement.h \
	saml_subject_statement_abstract.h \
	samlp_request.h \
	samlp_request_abstract.h \
	samlp_response.h \
	samlp_response_abstract.h \
	samlp_status.h \
	samlp_status_code.h \
	xml_enc.h \
	tools.h

lasso_private_h_sources = \
	private.h

EXTRA_DIST = $(lasso_private_h_sources) xml_idff.h
