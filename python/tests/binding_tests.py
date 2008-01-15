#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# $Id$
#
# Python unit tests for Lasso library
#
# Copyright (C) 2004-2007 Entr'ouvert
# http://lasso.entrouvert.org
#
# Authors: See AUTHORS file in top-level directory.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import unittest
import sys

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso


class BindingTestCase(unittest.TestCase):
    def test01(self):
        """Create and delete nodes."""

        authnRequest = lasso.LibAuthnRequest()
        del authnRequest

    def test02(self):
        """Get & set simple attributes of nodes."""

        authnRequest = lasso.LibAuthnRequest()

        # Test a string attribute.
        self.failUnlessEqual(authnRequest.consent, None)
        authnRequest.consent = lasso.LIB_CONSENT_OBTAINED
        self.failUnlessEqual(authnRequest.consent, lasso.LIB_CONSENT_OBTAINED)
        authnRequest.consent = None
        self.failUnlessEqual(authnRequest.consent, None)

        # Test a renamed string attribute.
        self.failUnlessEqual(authnRequest.relayState, None)
        authnRequest.relayState = 'Hello World!'
        self.failUnlessEqual(authnRequest.relayState, 'Hello World!')
        authnRequest.relayState = None
        self.failUnlessEqual(authnRequest.relayState, None)

        # Test an integer attribute.
        self.failUnlessEqual(authnRequest.majorVersion, 0)
        authnRequest.majorVersion = 314
        self.failUnlessEqual(authnRequest.majorVersion, 314)

        del authnRequest

    def test03(self):
        """Get & set attributes of nodes of type string list."""

        authnRequest = lasso.LibAuthnRequest()

        self.failUnlessEqual(authnRequest.respondWith, None)

        respondWith = lasso.StringList()
        self.failUnlessEqual(len(respondWith), 0)
        respondWith.append('first string')
        self.failUnlessEqual(len(respondWith), 1)
        self.failUnlessEqual(respondWith[0], 'first string')
        respondWith.append('second string')
        self.failUnlessEqual(len(respondWith), 2)
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        respondWith.append('third string')
        self.failUnlessEqual(len(respondWith), 3)
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        self.failUnlessEqual(respondWith[2], 'third string')
        authnRequest.respondWith = respondWith
        self.failUnlessEqual(authnRequest.respondWith[0], 'first string')
        self.failUnlessEqual(authnRequest.respondWith[1], 'second string')
        self.failUnlessEqual(authnRequest.respondWith[2], 'third string')
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        self.failUnlessEqual(respondWith[2], 'third string')
        del respondWith
        self.failUnlessEqual(authnRequest.respondWith[0], 'first string')
        self.failUnlessEqual(authnRequest.respondWith[1], 'second string')
        self.failUnlessEqual(authnRequest.respondWith[2], 'third string')
        respondWith = authnRequest.respondWith
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        self.failUnlessEqual(respondWith[2], 'third string')
        del respondWith
        self.failUnlessEqual(authnRequest.respondWith[0], 'first string')
        self.failUnlessEqual(authnRequest.respondWith[1], 'second string')
        self.failUnlessEqual(authnRequest.respondWith[2], 'third string')
        authnRequest.respondWith = None
        self.failUnlessEqual(authnRequest.respondWith, None)

        del authnRequest

    def test04(self):
        """Get & set attributes of nodes of type node list."""

        response = lasso.SamlpResponse()

        self.failUnlessEqual(response.assertion, None)

        assertions = lasso.NodeList()
        self.failUnlessEqual(len(assertions), 0)
        assertion1 = lasso.SamlAssertion()
        assertion1.assertionId = 'assertion 1'
        assertions.append(assertion1)
        self.failUnlessEqual(len(assertions), 1)
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        assertion2 = lasso.SamlAssertion()
        assertion2.assertionId = 'assertion 2'
        assertions.append(assertion2)
        self.failUnlessEqual(len(assertions), 2)
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        assertion3 = lasso.SamlAssertion()
        assertion3.assertionId = 'assertion 3'
        assertions.append(assertion3)
        self.failUnlessEqual(len(assertions), 3)
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        self.failUnlessEqual(assertions[2].assertionId, 'assertion 3')
        response.assertion = assertions
        self.failUnlessEqual(response.assertion[0].assertionId, 'assertion 1')
        self.failUnlessEqual(response.assertion[1].assertionId, 'assertion 2')
        self.failUnlessEqual(response.assertion[2].assertionId, 'assertion 3')
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        self.failUnlessEqual(assertions[2].assertionId, 'assertion 3')
        del assertions
        self.failUnlessEqual(response.assertion[0].assertionId, 'assertion 1')
        self.failUnlessEqual(response.assertion[1].assertionId, 'assertion 2')
        self.failUnlessEqual(response.assertion[2].assertionId, 'assertion 3')
        assertions = response.assertion
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        self.failUnlessEqual(assertions[2].assertionId, 'assertion 3')
        del assertions
        self.failUnlessEqual(response.assertion[0].assertionId, 'assertion 1')
        self.failUnlessEqual(response.assertion[1].assertionId, 'assertion 2')
        self.failUnlessEqual(response.assertion[2].assertionId, 'assertion 3')
        response.assertion = None
        self.failUnlessEqual(response.assertion, None)

        del response

    def test05(self):
        """Get & set attributes of nodes of type XML list."""

        authnRequest = lasso.LibAuthnRequest()

        self.failUnlessEqual(authnRequest.extension, None)

        actionString1 = """\
<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 1</action>
</lib:Extension>"""
        actionString2 = """\
<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 2</action>
</lib:Extension>"""
        actionString3 = """\
<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 3</action>
</lib:Extension>"""
        extension = lasso.StringList()
        self.failUnlessEqual(len(extension), 0)
        extension.append(actionString1)
        self.failUnlessEqual(len(extension), 1)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[0], actionString1)
        extension.append(actionString2)
        self.failUnlessEqual(len(extension), 2)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        extension.append(actionString3)
        self.failUnlessEqual(len(extension), 3)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        self.failUnlessEqual(extension[2], actionString3)
        authnRequest.extension = extension
        self.failUnlessEqual(authnRequest.extension[0], actionString1)
        self.failUnlessEqual(authnRequest.extension[1], actionString2)
        self.failUnlessEqual(authnRequest.extension[2], actionString3)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        self.failUnlessEqual(extension[2], actionString3)
        del extension
        self.failUnlessEqual(authnRequest.extension[0], actionString1)
        self.failUnlessEqual(authnRequest.extension[1], actionString2)
        self.failUnlessEqual(authnRequest.extension[2], actionString3)
        extension = authnRequest.extension
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        self.failUnlessEqual(extension[2], actionString3)
        del extension
        self.failUnlessEqual(authnRequest.extension[0], actionString1)
        self.failUnlessEqual(authnRequest.extension[1], actionString2)
        self.failUnlessEqual(authnRequest.extension[2], actionString3)
        authnRequest.extension = None
        self.failUnlessEqual(authnRequest.extension, None)

        del authnRequest

    def test06(self):
        """Get & set attributes of nodes of type node."""

        login = lasso.Login(lasso.Server())

        self.failUnlessEqual(login.request, None)
        login.request = lasso.LibAuthnRequest()
        login.request.consent = lasso.LIB_CONSENT_OBTAINED
        self.failUnlessEqual(login.request.consent, lasso.LIB_CONSENT_OBTAINED)
        login.request = None
        self.failUnlessEqual(login.request, None)

        del login

    def test07(self):
        """Get & set SAML 2.0 assertion attribute values"""

        attribute1_name = 'first attribute'
        attribute1_string = 'first string'
        attribute2_name = 'second attribute'
        attribute2_string = 'second string'
        attribute3_string = 'third string'

        expected_assertion_dump = '''\
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" SignType="0" SignMethod="0" EncryptionActivated="false" EncryptionSymKeyType="0">
  <saml:AttributeStatement>
    <saml:Attribute Name="first attribute">
      <saml:AttributeValue>
        <XXX>first string</XXX>
      </saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="second attribute">
      <saml:AttributeValue>
        <XXX>second string</XXX>
      </saml:AttributeValue>
      <saml:AttributeValue>
        <XXX>third string</XXX>
      </saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>'''

        text_node1 = lasso.MiscTextNode()
        text_node1.content = attribute1_string
        any1 = lasso.NodeList()
        any1.append(text_node1)
        attribute_value1 = lasso.Saml2AttributeValue()
        attribute_value1.any = any1
        attribute_values1 = lasso.NodeList()
        attribute_values1.append(attribute_value1)
        attribute1 = lasso.Saml2Attribute()
        attribute1.name = attribute1_name
        attribute1.attributeValue = attribute_values1

        text_node2 = lasso.MiscTextNode()
        text_node2.content = attribute2_string
        any2 = lasso.NodeList()
        any2.append(text_node2)
        attribute_value2 = lasso.Saml2AttributeValue()
        attribute_value2.any = any2

        text_node3 = lasso.MiscTextNode()
        text_node3.content = attribute3_string
        any3 = lasso.NodeList()
        any3.append(text_node3)
        attribute_value3 = lasso.Saml2AttributeValue()
        attribute_value3.any = any3

        attribute_values2 = lasso.NodeList()
        attribute_values2.append(attribute_value2)
        attribute_values2.append(attribute_value3)

        attribute2 = lasso.Saml2Attribute()
        attribute2.name = attribute2_name
        attribute2.attributeValue = attribute_values2

        attributes = lasso.NodeList()
        attributes.append(attribute1)
        attributes.append(attribute2)

        attributeStatement = lasso.Saml2AttributeStatement()
        attributeStatement.attribute = attributes
        attributeStatements = lasso.NodeList()
        attributeStatements.append(attributeStatement)

        assertion = lasso.Saml2Assertion()
        assertion.attributeStatement = attributeStatements

        self.failUnlessEqual(assertion.dump(), expected_assertion_dump, 'resulting assertion dump is not as expected')


bindingSuite = unittest.makeSuite(BindingTestCase, 'test')

allTests = unittest.TestSuite((bindingSuite, ))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

