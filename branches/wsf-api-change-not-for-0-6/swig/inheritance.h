/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id$
 *
 * SWIG bindings for Lasso Library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


/***********************************************************************
 * Declaration of LassoNode Derivated Classes
 ***********************************************************************/

/* FIXME: May be this file should be automatically generated by a script? */

/* saml prefix */

SET_NODE_INFO(SamlAdvice, Node)
SET_NODE_INFO(SamlAssertion, Node)
SET_NODE_INFO(SamlAttributeDesignator, Node)
SET_NODE_INFO(SamlAuthorityBinding, Node)
SET_NODE_INFO(SamlConditionAbstract, Node)
SET_NODE_INFO(SamlConditions, Node)
SET_NODE_INFO(SamlNameIdentifier, Node)
SET_NODE_INFO(SamlStatementAbstract, Node)
SET_NODE_INFO(SamlSubject, Node)
SET_NODE_INFO(SamlSubjectConfirmation, Node)
SET_NODE_INFO(SamlSubjectLocality, Node)

SET_NODE_INFO(SamlAttribute, SamlAttributeDesignator)
SET_NODE_INFO(SamlAudienceRestrictionCondition, SamlConditionAbstract)
SET_NODE_INFO(SamlSubjectStatementAbstract, SamlStatementAbstract)

SET_NODE_INFO(SamlAttributeStatement, SamlSubjectStatementAbstract)
SET_NODE_INFO(SamlAuthenticationStatement, SamlSubjectStatementAbstract)
SET_NODE_INFO(SamlSubjectStatement, SamlSubjectStatementAbstract)

/* samlp prefix */

SET_NODE_INFO(SamlpRequestAbstract, Node)
SET_NODE_INFO(SamlpResponseAbstract, Node)
SET_NODE_INFO(SamlpStatus, Node)
SET_NODE_INFO(SamlpStatusCode, Node)

SET_NODE_INFO(SamlpRequest, SamlpRequestAbstract)
SET_NODE_INFO(SamlpResponse, SamlpResponseAbstract)

/* lib prefix */

SET_NODE_INFO(LibAssertion, SamlAssertion)
SET_NODE_INFO(LibAuthnRequest, SamlpRequestAbstract)
SET_NODE_INFO(LibAuthnResponse, SamlpResponse)
SET_NODE_INFO(LibFederationTerminationNotification, SamlpRequestAbstract)
SET_NODE_INFO(LibLogoutRequest, SamlpRequestAbstract)
SET_NODE_INFO(LibRegisterNameIdentifierRequest, SamlpRequestAbstract)
SET_NODE_INFO(LibRequestAuthnContext, Node)
SET_NODE_INFO(LibStatusResponse, SamlpResponseAbstract)

SET_NODE_INFO(LibLogoutResponse, LibStatusResponse)
SET_NODE_INFO(LibRegisterNameIdentifierResponse, LibStatusResponse)


/* ID-WSF */


/* disco prefix */

SET_NODE_INFO(DiscoCredentials, Node)
SET_NODE_INFO(DiscoDescription, Node)
SET_NODE_INFO(DiscoEncryptedResourceID, Node)
SET_NODE_INFO(DiscoInsertEntry, Node)
SET_NODE_INFO(DiscoModify, Node)
SET_NODE_INFO(DiscoModifyResponse, Node)
SET_NODE_INFO(DiscoOptions, Node)
SET_NODE_INFO(DiscoQuery, Node)
SET_NODE_INFO(DiscoQueryResponse, Node)
SET_NODE_INFO(DiscoRemoveEntry, Node)
SET_NODE_INFO(DiscoRequestedServiceType, Node)
SET_NODE_INFO(DiscoResourceID, Node)
SET_NODE_INFO(DiscoResourceOffering, Node)
SET_NODE_INFO(DiscoServiceInstance, Node)

/* dst prefix */

SET_NODE_INFO(DstData, Node)
SET_NODE_INFO(DstModification, Node)
SET_NODE_INFO(DstModify, Node)
SET_NODE_INFO(DstModifyResponse, Node)
SET_NODE_INFO(DstNewData, Node)
SET_NODE_INFO(DstQuery, Node)
SET_NODE_INFO(DstQueryItem, Node)
SET_NODE_INFO(DstQueryResponse, Node)

/* is prefix */

SET_NODE_INFO(IsHelp, Node)
SET_NODE_INFO(IsInquiry, Node)
SET_NODE_INFO(IsInquiryElement, Node)
SET_NODE_INFO(IsInteractionRequest, Node)
SET_NODE_INFO(IsInteractionResponse, Node)
SET_NODE_INFO(IsInteractionStatement, Node)
SET_NODE_INFO(IsItem, Node)
SET_NODE_INFO(IsParameter, Node)
SET_NODE_INFO(IsRedirectRequest, Node)
/* FIXME: IsSelect should inherit from IsInquiryElement */
SET_NODE_INFO(IsSelect, Node)
/* FIXME: IsText should inherit from IsInquiryElement */
SET_NODE_INFO(IsText, Node)
SET_NODE_INFO(IsUserInteraction, Node)

/* utility prefix */

SET_NODE_INFO(UtilityStatus, Node)
