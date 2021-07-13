#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# $Id: binding_tests.py 3283 2007-06-11 09:10:18Z dlaniel $
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.


import unittest
import sys
import os
import logging

logging.basicConfig()

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso

try:
    dataDir
except NameError:
    srcdir = os.environ.get('TOP_SRCDIR', '.')
    dataDir = '%s/tests/data' % srcdir


class BindingTestCase(unittest.TestCase):
    def test01(self):
        """Create and delete nodes."""

        authnRequest = lasso.LibAuthnRequest()
        del authnRequest

    def test02(self):
        """Get & set simple attributes of nodes."""

        authnRequest = lasso.LibAuthnRequest()

        # Test a string attribute.
        self.assertEqual(authnRequest.consent, None)
        authnRequest.consent = lasso.LIB_CONSENT_OBTAINED
        self.assertEqual(authnRequest.consent, lasso.LIB_CONSENT_OBTAINED)
        authnRequest.consent = None
        self.assertEqual(authnRequest.consent, None)

        # Test a renamed string attribute.
        self.assertEqual(authnRequest.relayState, None)
        authnRequest.relayState = 'Hello World!'
        self.assertEqual(authnRequest.relayState, 'Hello World!')
        authnRequest.relayState = None
        self.assertEqual(authnRequest.relayState, None)

        # Test an integer attribute.
        self.assertEqual(authnRequest.majorVersion, 0)
        authnRequest.majorVersion = 314
        self.assertEqual(authnRequest.majorVersion, 314)

        del authnRequest

    def test03(self):
        """Get & set attributes of nodes of type string list."""

        authnRequest = lasso.LibAuthnRequest()

        self.assertEqual(authnRequest.respondWith, ())

        respondWith = []
        self.assertEqual(len(respondWith), 0)
        respondWith.append('first string')
        self.assertEqual(len(respondWith), 1)
        self.assertEqual(respondWith[0], 'first string')
        respondWith.append('second string')
        self.assertEqual(len(respondWith), 2)
        self.assertEqual(respondWith[0], 'first string')
        self.assertEqual(respondWith[1], 'second string')
        respondWith.append('third string')
        self.assertEqual(len(respondWith), 3)
        self.assertEqual(respondWith[0], 'first string')
        self.assertEqual(respondWith[1], 'second string')
        self.assertEqual(respondWith[2], 'third string')
        authnRequest.respondWith = tuple(respondWith)
        self.assertEqual(authnRequest.respondWith[0], 'first string')
        self.assertEqual(authnRequest.respondWith[1], 'second string')
        self.assertEqual(authnRequest.respondWith[2], 'third string')
        self.assertEqual(respondWith[0], 'first string')
        self.assertEqual(respondWith[1], 'second string')
        self.assertEqual(respondWith[2], 'third string')
        del respondWith
        self.assertEqual(authnRequest.respondWith[0], 'first string')
        self.assertEqual(authnRequest.respondWith[1], 'second string')
        self.assertEqual(authnRequest.respondWith[2], 'third string')
        respondWith = authnRequest.respondWith
        self.assertEqual(respondWith[0], 'first string')
        self.assertEqual(respondWith[1], 'second string')
        self.assertEqual(respondWith[2], 'third string')
        del respondWith
        self.assertEqual(authnRequest.respondWith[0], 'first string')
        self.assertEqual(authnRequest.respondWith[1], 'second string')
        self.assertEqual(authnRequest.respondWith[2], 'third string')
        authnRequest.respondWith = None
        self.assertEqual(authnRequest.respondWith, ())

        del authnRequest

    def test04(self):
        """Get & set attributes of nodes of type node list."""

        response = lasso.SamlpResponse()

        self.assertEqual(response.assertion, ())

        assertions = []
        self.assertEqual(len(assertions), 0)
        assertion1 = lasso.SamlAssertion()
        assertion1.assertionId = 'assertion 1'
        assertions.append(assertion1)
        self.assertEqual(len(assertions), 1)
        self.assertEqual(assertions[0].assertionId, 'assertion 1')
        self.assertEqual(assertions[0].assertionId, 'assertion 1')
        assertion2 = lasso.SamlAssertion()
        assertion2.assertionId = 'assertion 2'
        assertions.append(assertion2)
        self.assertEqual(len(assertions), 2)
        self.assertEqual(assertions[0].assertionId, 'assertion 1')
        self.assertEqual(assertions[1].assertionId, 'assertion 2')
        assertion3 = lasso.SamlAssertion()
        assertion3.assertionId = 'assertion 3'
        assertions.append(assertion3)
        self.assertEqual(len(assertions), 3)
        self.assertEqual(assertions[0].assertionId, 'assertion 1')
        self.assertEqual(assertions[1].assertionId, 'assertion 2')
        self.assertEqual(assertions[2].assertionId, 'assertion 3')
        response.assertion = tuple(assertions)
        self.assertEqual(response.assertion[0].assertionId, 'assertion 1')
        self.assertEqual(response.assertion[1].assertionId, 'assertion 2')
        self.assertEqual(response.assertion[2].assertionId, 'assertion 3')
        self.assertEqual(assertions[0].assertionId, 'assertion 1')
        self.assertEqual(assertions[1].assertionId, 'assertion 2')
        self.assertEqual(assertions[2].assertionId, 'assertion 3')
        del assertions
        self.assertEqual(response.assertion[0].assertionId, 'assertion 1')
        self.assertEqual(response.assertion[1].assertionId, 'assertion 2')
        self.assertEqual(response.assertion[2].assertionId, 'assertion 3')
        assertions = response.assertion
        self.assertEqual(assertions[0].assertionId, 'assertion 1')
        self.assertEqual(assertions[1].assertionId, 'assertion 2')
        self.assertEqual(assertions[2].assertionId, 'assertion 3')
        del assertions
        self.assertEqual(response.assertion[0].assertionId, 'assertion 1')
        self.assertEqual(response.assertion[1].assertionId, 'assertion 2')
        self.assertEqual(response.assertion[2].assertionId, 'assertion 3')
        response.assertion = None
        self.assertEqual(response.assertion, ())

        del response

    def test05(self):
        """Get & set attributes of nodes of type XML list."""

        authnRequest = lasso.LibAuthnRequest()

        self.assertEqual(authnRequest.extension, ())

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
        extension = []
        self.assertEqual(len(extension), 0)
        extension.append(actionString1)
        self.assertEqual(len(extension), 1)
        self.assertEqual(extension[0], actionString1)
        self.assertEqual(extension[0], actionString1)
        extension.append(actionString2)
        self.assertEqual(len(extension), 2)
        self.assertEqual(extension[0], actionString1)
        self.assertEqual(extension[1], actionString2)
        extension.append(actionString3)
        self.assertEqual(len(extension), 3)
        self.assertEqual(extension[0], actionString1)
        self.assertEqual(extension[1], actionString2)
        self.assertEqual(extension[2], actionString3)
        authnRequest.extension = tuple(extension)
        self.assertEqual(authnRequest.extension[0], actionString1)
        self.assertEqual(authnRequest.extension[1], actionString2)
        self.assertEqual(authnRequest.extension[2], actionString3)
        self.assertEqual(extension[0], actionString1)
        self.assertEqual(extension[1], actionString2)
        self.assertEqual(extension[2], actionString3)
        del extension
        self.assertEqual(authnRequest.extension[0], actionString1)
        self.assertEqual(authnRequest.extension[1], actionString2)
        self.assertEqual(authnRequest.extension[2], actionString3)
        extension = authnRequest.extension
        self.assertEqual(extension[0], actionString1)
        self.assertEqual(extension[1], actionString2)
        self.assertEqual(extension[2], actionString3)
        del extension
        self.assertEqual(authnRequest.extension[0], actionString1)
        self.assertEqual(authnRequest.extension[1], actionString2)
        self.assertEqual(authnRequest.extension[2], actionString3)
        authnRequest.extension = None
        self.assertEqual(authnRequest.extension, ())

        del authnRequest

    def test06(self):
        """Get & set attributes of nodes of type node."""

        login = lasso.Login(lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem')))

        self.assertEqual(login.request, None)
        login.request = lasso.LibAuthnRequest()
        login.request.consent = lasso.LIB_CONSENT_OBTAINED
        self.assertEqual(login.request.consent, lasso.LIB_CONSENT_OBTAINED)
        login.request = None
        self.assertEqual(login.request, None)

        del login

    def test07(self):
        '''Check reference counting'''
        s = lasso.Samlp2AuthnRequest()
        cptr = s._cptr
        a = sys.getrefcount(s._cptr)
        del(s)
        b = sys.getrefcount(cptr)
        self.assertEqual(b, a-1)

    def test08(self):
        '''Test an integer attribute'''
        authnRequest = lasso.LibAuthnRequest()
        authnRequest.majorVersion = 314
        self.assertEqual(authnRequest.majorVersion, 314)

    def test09(self):
        '''Test dictionary attributes'''
        identity = lasso.Identity.newFromDump(open(
                    os.path.join(dataDir, 'sample-identity-dump-1.xml')).read())
        self.assertEqual(len(identity.federations.keys()), 2)
        self.assertFalse(not 'http://idp1.lasso.lan' in identity.federations.keys())
        self.assertEqual(
                identity.federations['http://idp1.lasso.lan'].localNameIdentifier.content,
                'first name id')

    def test10(self):
        '''Test Server.setEncryptionPrivateKeyWithPassword'''
        pkey_path = os.path.join(
            dataDir, 'idp5-saml2', 'private-key.pem')
        server = lasso.Server(os.path.join(dataDir, 'idp5-saml2', 'metadata.xml'),
                pkey_path)
        # from file
        server.setEncryptionPrivateKeyWithPassword(pkey_path)
        # from buffer
        server.setEncryptionPrivateKeyWithPassword(open(pkey_path).read())
        # reset
        server.setEncryptionPrivateKeyWithPassword()

    def test11(self):
        '''Test saving and reloading a Server using an encrypted private key'''
        pkey = os.path.join(dataDir, 'sp7-saml2', 'private-key.pem')
        mdata = os.path.join(dataDir, 'sp7-saml2', 'metadata.xml')
        password = open(os.path.join(dataDir, 'sp7-saml2', 'password')).read().strip()
        server = lasso.Server(mdata, pkey, password)
        assert isinstance(server, lasso.Server)
        server_dump = server.dump()
        assert server_dump
        server = lasso.Server.newFromDump(server_dump)
        assert isinstance(server, lasso.Server)

    def test12(self):
        node = lasso.Samlp2Extensions()
        assert not node.any
        content = '''<samlp:Extensions
                        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:eo="https://www.entrouvert.com/" eo:huhu="xxx">
                      <eo:next_url>%s</eo:next_url>
                   </samlp:Extensions>'''
        node = lasso.Node.newFromXmlNode(content)
        assert 'next_url' in node.any[1]
        assert '{https://www.entrouvert.com/}huhu' in node.attributes.keys()
        assert 'xxx' in node.attributes.values()
        node.any = ('<zob>coin</zob>',)
        node.attributes = {'michou': 'zozo'}
        assert '<zob>coin</zob>' in node.dump()
        assert 'michou="zozo"' in node.dump()
        node = lasso.Node.newFromDump(node.dump())
        assert node.any == ('<zob>coin</zob>',)
        # on reparse non namespaces attributes are ignore, they should not exist
        assert node.attributes == {}

    def test13(self):
        node = lasso.Samlp2LogoutRequest()
        node.sessionIndexes = ('1', '2')
        assert node.sessionIndexes == ('1', '2'), node.sessionIndexes
        node.sessionIndexes = ()
        assert node.sessionIndexes == (), node.sessionIndexes

    def test14(self):
        # verify Error implementation
        with self.assertRaises(lasso.Error) as cm:
            lasso.Server('', '', '')
        assert isinstance(str(cm.exception), str)
        with self.assertRaises(lasso.Error) as cm:
            lasso.Error.raise_on_rc(lasso._lasso.XML_ERROR_SCHEMA_INVALID_FRAGMENT)
        self.assertEqual(str(cm.exception),
                         '<lasso.XmlSchemaInvalidFragmentError(17): An XML tree does not respect at least an XML schema of its namespaces.>')

    def test_set_list_of_strings(self):
        node = lasso.Samlp2RequestedAuthnContext()
        with self.assertRaises(TypeError, msg='value should be a tuple of strings'):
            node.authnContextClassRef = [None]

    def test_set_list_of_pygobject(self):
        node = lasso.Saml2Attribute()

        class A:
            _cptr = None
        value = [A()]
        with self.assertRaises(TypeError, msg='value should be a tuple of PyGobject'):
            node.attributeValue = value

bindingSuite = unittest.makeSuite(BindingTestCase, 'test')

allTests = unittest.TestSuite((bindingSuite, ))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

