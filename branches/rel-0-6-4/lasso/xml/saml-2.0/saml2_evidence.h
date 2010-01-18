/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
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

#ifndef __LASSO_SAML2_EVIDENCE_H__
#define __LASSO_SAML2_EVIDENCE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/xml/xml.h>

#ifndef __LASSO_SAML2_ASSERTION_H__
/* to avoid circular inclusion of saml2_assertion.h */
typedef struct _LassoSaml2Assertion LassoSaml2Assertion;
#endif


#define LASSO_TYPE_SAML2_EVIDENCE (lasso_saml2_evidence_get_type())
#define LASSO_SAML2_EVIDENCE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML2_EVIDENCE, \
				LassoSaml2Evidence))
#define LASSO_SAML2_EVIDENCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML2_EVIDENCE, \
				LassoSaml2EvidenceClass))
#define LASSO_IS_SAML2_EVIDENCE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML2_EVIDENCE))
#define LASSO_IS_SAML2_EVIDENCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML2_EVIDENCE))
#define LASSO_SAML2_EVIDENCE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML2_EVIDENCE, \
				LassoSaml2EvidenceClass)) 

typedef struct _LassoSaml2Evidence LassoSaml2Evidence;
typedef struct _LassoSaml2EvidenceClass LassoSaml2EvidenceClass;


struct _LassoSaml2Evidence {
	LassoNode parent;

	/*< public >*/
	/* elements */
	GList *AssertionIDRef;
	GList *AssertionURIRef;
	GList *Assertion; /* of LassoSaml2Assertion */
	GList *EncryptedAssertion; /* of LassoSaml2EncryptedElement */
};


struct _LassoSaml2EvidenceClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml2_evidence_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml2_evidence_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML2_EVIDENCE_H__ */
