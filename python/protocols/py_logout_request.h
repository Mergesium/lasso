/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *         Nicolas Clapies <nclapies@entrouvert.com>
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

#ifndef __PYLASSO_PY_LOGOUT_REQUEST_H__
#define __PYLASSO_PY_LOGOUT_REQUEST_H__

#include <lasso/protocols/logout_request.h>
#include <lasso/xml/lib_logout_request.h>

typedef struct {
    PyObject_HEAD
    LassoLogoutRequest *obj;
} LassoLogoutRequest_object;

#define lassoLogoutRequest_get(v) (((v) == Py_None) ? NULL : (((LassoLogoutRequest_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *lassoLogoutRequest_wrap(LassoLogoutRequest *request);

PyObject *logout_request_getattr(PyObject *self, PyObject *args);
PyObject *logout_request(PyObject *self, PyObject *args);

PyObject *logout_request_set_sessionIndex(PyObject *self, PyObject *args);
PyObject *logout_request_set_relayState(PyObject *self, PyObject *args);
PyObject *logout_request_set_consent(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_LOGOUT_REQUEST_H__ */
