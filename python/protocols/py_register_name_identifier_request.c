/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
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

#include "../lassomod.h"

#include "py_register_name_identifier_request.h"

PyObject *LassoRegisterNameIdentifierRequest_wrap(LassoRegisterNameIdentifierRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "LassoRegisterNameIdentifierRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *register_name_identifier_request_new(PyObject *self, PyObject *args) {
  const xmlChar *providerID;

  const xmlChar *idpNameIdentifier;
  const xmlChar *idpNameQualifier;
  const xmlChar *idpFormat;

  const xmlChar *spNameIdentifier;
  const xmlChar *spNameQualifier;
  const xmlChar *spFormat;

  const xmlChar *oldNameIdentifier;
  const xmlChar *oldNameQualifier;
  const xmlChar *oldFormat;

  LassoNode *request;

  if (CheckArgs(args, "SSSSSSSSSS:register_name_identifier_request_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ssssssssss:register_name_identifier_request_new",
			 &providerID,
			 &idpNameIdentifier, &idpNameQualifier, &idpFormat,
			 &spNameIdentifier,  &spNameQualifier,  &spFormat,
			 &oldNameIdentifier, &oldNameQualifier, &oldFormat))
      return NULL;
  }
  else return NULL;

  request = lasso_register_name_identifier_request_new(providerID,
						       idpNameIdentifier,
						       idpNameQualifier,
						       idpFormat,
						       spNameIdentifier,
						       spNameQualifier,
						       spFormat,
						       oldNameIdentifier,
						       oldNameQualifier,
						       oldFormat);

  return (LassoRegisterNameIdentifierRequest_wrap(LASSO_REGISTER_NAME_IDENTIFIER_REQUEST(request)));
}

PyObject *register_name_identifier_request_rename_attributes_for_query(PyObject *self, PyObject *args){
  PyObject *request_obj;

  if (CheckArgs(args, "O:register_name_identifier_request_rename_attributes_for_query")) {
    if(!PyArg_ParseTuple(args, (char *) "O:register_name_identifier_request_rename_attributes_for_query",
			 &request_obj))
      return NULL;
  }
  else return NULL;
     
  lasso_register_name_identifier_rename_attributes_for_query(LassoRegisterNameIdentifierRequest_get(request_obj));
  
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *register_name_identifier_request_new_from_soap(PyObject *self, PyObject *args) {
  const xmlChar *soap_buffer;

  LassoNode     *request;

  if (CheckArgs(args, "S:register_name_identifier_request_new_from_soap")) {
    if(!PyArg_ParseTuple(args, (char *) "s:register_name_identifier_request_new_from_soap",
			 &soap_buffer))
      return NULL;
  }
  else return NULL;

  request = lasso_register_name_identifier_request_new_from_soap(soap_buffer);

  return (LassoRegisterNameIdentifierRequest_wrap(LASSO_REGISTER_NAME_IDENTIFIER_REQUEST(request)));
}

PyObject *register_name_identifier_request_new_from_query(PyObject *self, PyObject *args) {
  const xmlChar *query;

  LassoNode     *request;

  if (CheckArgs(args, "S:register_name_identifier_request_new_from_query")) {
    if(!PyArg_ParseTuple(args, (char *) "s:register_name_identifier_request_new_from_query",
			 &query))
      return NULL;
  }
  else return NULL;

  request = lasso_register_name_identifier_request_new_from_query(query);

  return (LassoRegisterNameIdentifierRequest_wrap(LASSO_REGISTER_NAME_IDENTIFIER_REQUEST(request)));
}
