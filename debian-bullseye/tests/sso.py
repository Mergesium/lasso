import os
import lasso

DATA_DIR = 'tests/data'


def server(local_name, remote_role, remote_name):
    pwd = os.path.join(DATA_DIR, local_name, 'password')
    password = None
    if os.path.exists(pwd):
        password = open(pwd).read()
    s = lasso.Server(
        os.path.join(DATA_DIR, local_name, 'metadata.xml'),
        os.path.join(DATA_DIR, local_name, 'private-key.pem'),
        password,
    )
    s.addProvider(remote_role, os.path.join(DATA_DIR, remote_name, 'metadata.xml'))
    return s


sp_server = server('sp7-saml2', lasso.PROVIDER_ROLE_IDP, 'idp7-saml2')
idp_server = server('idp7-saml2', lasso.PROVIDER_ROLE_SP, 'sp7-saml2')

sp_login = lasso.Login(sp_server)
sp_login.initAuthnRequest()
sp_login.request.protocolBinding = lasso.SAML2_METADATA_BINDING_POST
sp_login.buildAuthnRequestMsg()
idp_login = lasso.Login(idp_server)
idp_login.setSignatureVerifyHint(lasso.PROFILE_SIGNATURE_VERIFY_HINT_FORCE)
idp_login.processAuthnRequestMsg(sp_login.msgUrl.split('?')[1])
idp_login.validateRequestMsg(True, True)
idp_login.buildAssertion("None", "None", "None", "None", "None")
idp_login.buildAuthnResponseMsg()
sp_login.setSignatureVerifyHint(lasso.PROFILE_SIGNATURE_VERIFY_HINT_FORCE)
sp_login.processAuthnResponseMsg(idp_login.msgBody)
sp_login.acceptSso()
