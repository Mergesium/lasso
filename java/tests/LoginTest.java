/*
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
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

// To run it:
// $ export LD_LIBRARY_PATH=../target/
// $ javac -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest.java
// $ java -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest
// or for gcj:
// $ export LD_LIBRARY_PATH=../target/
// $ gcj -C -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest.java
// $ gij -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.TestSuite;

import com.entrouvert.lasso.*;


public class LoginTest extends TestCase {
    public String generateIdentityProviderContextDump() {
	LassoServer serverContext = new LassoServer(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/idp-private-key.pem",
            "../../examples/data/idp-crt.pem",
           Lasso.signatureMethodRsaSha1);
        serverContext.addProvider(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/ca-crt.pem");
	String serverContextDump = serverContext.dump();
        return serverContextDump;
    }

    public String generateServiceProviderContextDump() {
        LassoServer serverContext = new LassoServer(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/sp-private-key.pem",
            "../../examples/data/sp-crt.pem",
            Lasso.signatureMethodRsaSha1);
        serverContext.addProvider(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/ca-crt.pem");
        String serverContextDump = serverContext.dump();
        return serverContextDump;
    }

    public void test01_generateServersContextDumps() {
        String identityProviderContextDump = generateIdentityProviderContextDump();
        assertNotNull(identityProviderContextDump);
        String serviceProviderContextDump = generateServiceProviderContextDump();
        assertNotNull(serviceProviderContextDump);
    }

    public void test02_serviceProviderLogin() {
	boolean userAuthenticated;
	int method, requestType;
	LassoAuthnRequest authnRequest;
	LassoLogin idpLoginContext, spLoginContext;
	LassoResponse response;
	LassoServer idpContext, spContext;
	String artifact, authenticationMethod, authnRequestQuery, authnRequestUrl, idpContextDump,
	    idpUserContextDump, nameIdentifier, relayState, responseQuery, responseUrl,
	    soapEndpoint, soapResponseMsg, soapRequestMsg, spContextDump, spUserContextDump;

	// Service provider login using HTTP redirect.
        spContextDump = generateServiceProviderContextDump();
	assertNotNull(spContextDump);
        spContext = new LassoServer(spContextDump);
        spLoginContext = new LassoLogin(spContext, null);
        assertEquals(spLoginContext.initAuthnRequest(
	    "https://identity-provider:1998/liberty-alliance/metadata"), 0);
	authnRequest = (LassoAuthnRequest) spLoginContext.getRequest();
        authnRequest.setPassive(false);
        authnRequest.setNameIdPolicy(Lasso.libNameIdPolicyTypeFederated);
        authnRequest.setConsent(Lasso.libConsentObtained);
	relayState = "fake";
        authnRequest.setRelayState(relayState);
        assertEquals(spLoginContext.buildAuthnRequestMsg(), 0);
        authnRequestUrl = spLoginContext.getMsgUrl();
        authnRequestQuery = authnRequestUrl.substring(authnRequestUrl.indexOf("?") + 1);
        method = Lasso.httpMethodRedirect;

	// Identity provider singleSignOn, for a user having no federation.
        idpContextDump = generateIdentityProviderContextDump();
        assertNotNull(idpContextDump);
        idpContext = new LassoServer(idpContextDump);
        idpLoginContext = new LassoLogin(idpContext, null);
        assertEquals(idpLoginContext.initFromAuthnRequestMsg(authnRequestQuery, method), 0);
        assertTrue(idpLoginContext.mustAuthenticate());

        userAuthenticated = true;
        authenticationMethod = Lasso.samlAuthenticationMethodPassword;
        assertEquals(idpLoginContext.getProtocolProfile(), Lasso.loginProtocolProfileBrwsArt);
        assertEquals(idpLoginContext.buildArtifactMsg(
            userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
            Lasso.httpMethodRedirect), 0);
	idpUserContextDump = idpLoginContext.getUser().dump();
        assertNotNull(idpUserContextDump);
        responseUrl = idpLoginContext.getMsgUrl();
        responseQuery = responseUrl.substring(responseUrl.indexOf("?") + 1);
        soapResponseMsg = idpLoginContext.getResponseDump();
        artifact = idpLoginContext.getAssertionArtifact();
	nameIdentifier = idpLoginContext.getNameIdentifier();
        method = Lasso.httpMethodRedirect;

        // Service provider assertion consumer.
        spContextDump = generateServiceProviderContextDump();
	assertNotNull(spContextDump);
        spContext = new LassoServer(spContextDump);
        spLoginContext = new LassoLogin(spContext, null);
        assertEquals(spLoginContext.initRequest(responseQuery, method), 0);
        assertEquals(spLoginContext.buildRequestMsg(), 0);
        soapEndpoint = spLoginContext.getMsgUrl();
	soapRequestMsg = spLoginContext.getMsgBody();

        // Identity provider SOAP endpoint.
        idpContextDump = generateIdentityProviderContextDump();
        assertNotNull(idpContextDump);
        requestType = Lasso.getRequestTypeFromSoapMsg(soapRequestMsg);
        assertEquals(requestType, Lasso.requestTypeLogin);

	    // Service provider assertion consumer (step 2).
        assertEquals(spLoginContext.processResponseMsg(soapResponseMsg), 0);
        assertEquals(spLoginContext.getNameIdentifier(), nameIdentifier);
	// The user doesn't have any federation yet.
        assertEquals(spLoginContext.createUser(null), 0);
        spUserContextDump = spLoginContext.getUser().dump();
        assertNotNull(spUserContextDump);
	response = (LassoResponse) spLoginContext.getResponse();
//         authenticationMethod = response.get_child(
//             "AuthenticationStatement").get_attr_value("AuthenticationMethod")
//         self.failUnlessEqual(authenticationMethod, lasso.samlAuthenticationMethodPassword)
    }

    public static Test suite() { 
	return new TestSuite(LoginTest.class); 
    }

    public static void main(String args[]) { 
	Lasso.init();
	junit.textui.TestRunner.run(suite());
	Lasso.shutdown();
    }
}
