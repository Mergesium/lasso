/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_XML_H__
#define __LASSO_XML_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/strings.h>
#include <lasso/xml/tools.h>

#define LASSO_TYPE_NODE (lasso_node_get_type())
#define LASSO_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NODE, LassoNode))
#define LASSO_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NODE, LassoNodeClass))
#define LASSO_IS_NODE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NODE))
#define LASSO_IS_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NODE))
#define LASSO_NODE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NODE, LassoNodeClass)) 

typedef struct _xmlAttr LassoAttr;

typedef struct _LassoNode LassoNode;
typedef struct _LassoNodeClass LassoNodeClass;
typedef struct _LassoNodePrivate LassoNodePrivate;

/**
 * _LassoNode:
 * @parent: the parent object
 * @private: private pointer structure
 **/
struct _LassoNode {
  GObject parent;
  /*< private >*/
  LassoNodePrivate *private;
};

struct _LassoNodeClass {
  GObjectClass parent_class;
  /*< vtable >*/
  /*< public >*/
  GString *   (* build_query)      (LassoNode     *node);
  void        (* dump)             (LassoNode     *,
				    const xmlChar *,
				    int);
  LassoAttr*  (* get_attr)         (LassoNode     *,
				    const xmlChar *);
  GPtrArray*  (* get_attrs)        (LassoNode     *);
  LassoNode*  (* get_child)        (LassoNode     *,
				    const xmlChar *);
  GPtrArray*  (* get_children)     (LassoNode     *);
  xmlChar *   (* get_content)      (LassoNode     *);
  xmlChar *   (* get_name)         (LassoNode     *);
  GData *     (* serialize)        (LassoNode     *,
				    GData         *);
  gchar *     (* url_encode)       (LassoNode     *node,
				    guint          sign_method,
				    const gchar   *key_file);
  gint        (* verify_signature) (LassoNode     *node,
				    const gchar   *certificate_file);
  /*< private >*/
  void       (* add_child)    (LassoNode *,
			       LassoNode *,
			       gboolean);
  xmlNodePtr (* get_xmlNode)  (LassoNode     *);
  void       (* new_child)    (LassoNode     *,
			       const xmlChar *,
			       const xmlChar *,
			       gboolean);
  void       (* new_ns)       (LassoNode     *,
			       const xmlChar *,
			       const xmlChar *);
  void       (* rename_prop)  (LassoNode     *node,
			       const xmlChar *old_name,
			       const xmlChar *new_name);
  void       (* set_name)     (LassoNode     *,
			       const xmlChar *);
  void       (* set_node)     (LassoNode     *,
			       xmlNodePtr);
  void       (* set_prop)     (LassoNode     *,
			       const xmlChar *,
			       const xmlChar *);
};

typedef enum {
  LassoUrlEncodeRsaSha1 = 1,
  LassoUrlEncodeDsaSha1
} LassoUrlEncodeSignMethod;

LASSO_EXPORT GType lasso_node_get_type(void);
LASSO_EXPORT LassoNode* lasso_node_new(xmlNodePtr node);

LASSO_EXPORT GString*   lasso_node_build_query  (LassoNode *node);

LASSO_EXPORT void       lasso_node_dump         (LassoNode     *,
						 const xmlChar *,
						 int);

LASSO_EXPORT LassoAttr* lasso_node_get_attr     (LassoNode *node,
						 const xmlChar *name);

LASSO_EXPORT GPtrArray* lasso_node_get_attrs    (LassoNode *node);

LASSO_EXPORT LassoNode* lasso_node_get_child    (LassoNode *node,
						 const xmlChar *name);

LASSO_EXPORT GPtrArray* lasso_node_get_children (LassoNode *node);

LASSO_EXPORT xmlChar*   lasso_node_get_content  (LassoNode *node);

LASSO_EXPORT xmlChar*   lasso_node_get_name     (LassoNode *node);

LASSO_EXPORT void       lasso_node_rename_prop  (LassoNode *node,
						 const xmlChar *old_name,
						 const xmlChar *new_name);

LASSO_EXPORT GData*     lasso_node_serialize    (LassoNode *node,
						 GData     *gd);

LASSO_EXPORT gchar*     lasso_node_url_encode   (LassoNode *node,
						 guint sign_method,
						 const gchar *key_file);

LASSO_EXPORT gchar*     lasso_node_verify_signature(LassoNode *node,
						    const gchar *certificate_file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_XML_H__ */
