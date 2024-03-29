#include <Python.h>
#include <structmember.h>
#include <lasso/lasso.h>
#include <config.h>
#include "../ghashtable.h"
#include "../../lasso/debug.h"
#include "../../lasso/utils.h"
#include "../utils.c"

#define PY_SSIZE_T_CLEAN

#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

/** @todo Remove Python 3 defines and update the code when Python 2 is out of the picture. */

// Python 3 has unified int & long types.
#if PY_MAJOR_VERSION >= 3
#define PyInt_AS_LONG PyLong_AS_LONG
#define PyInt_Check PyLong_Check
#define PyInt_FromLong PyLong_FromLong
#endif

// Python 3 has removed PyString and related functions, in favor of PyBytes & PyUnicode.
#if PY_MAJOR_VERSION > 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 3)
#define PyString_Check PyUnicode_Check
#define PyString_FromFormat PyUnicode_FromFormat
#define PyString_FromString PyUnicode_FromString
#define PyString_AsString PyUnicode_AsUTF8
#define get_pystring PyUnicode_AsUTF8AndSize
#define PyStringFree(string) ;
#elif PY_MAJOR_VERSION >= 3
#define PyString_Check PyUnicode_Check
#define PyString_FromFormat PyUnicode_FromFormat
#define PyString_FromString PyUnicode_FromString
static char *PyString_AsString(PyObject *string) {
	PyObject *bytes = PyUnicode_AsUTF8String(string);
	char *ret = NULL;
	if (! bytes)
		return NULL;
	ret = g_strdup(PyBytes_AsString(bytes));
	Py_DECREF(bytes);
	return ret;
}
static char *get_pystring(PyObject *string, Py_ssize_t *size) {
	char *ret = NULL;

	ret = PyString_AsString(string);
	*size = strlen(ret);
	return ret;
}
#define PyStringFree(string) g_free(string)
#elif PY_MAJOR_VERSION >= 3
#else
static char *get_pystring(PyObject *string, Py_ssize_t *size) {
	char *ret = NULL;

	PyString_AsStringAndSize(string, &ret, size);

	return ret;
}
#define PyStringFree(string) ;
void PyErr_WarnFormat(PyObject *category, int stacklevel, const char *format, ...) {

	va_list ap;
	char s[1024];

	va_start(ap, format);
	g_vsnprintf(s, 1024, format, ap);
	va_end(ap);
	PyErr_WarnEx(category, s, stacklevel);
}
#endif

#define RETURN_IF_FAIL(op) do { if (! (op)) { return NULL; } } while(0)
#define EXIT_IF_FAIL(op) do { if (! (op)) { ok = 0; goto failure; } } while(0)

GQuark lasso_wrapper_key;


#if PY_MAJOR_VERSION > 3
PyMODINIT_FUNC PyInit_lasso(void);
#else
PyMODINIT_FUNC init_lasso(void);
#endif
G_GNUC_UNUSED static PyObject* get_pystring_from_xml_node(xmlNode *xmlnode);
G_GNUC_UNUSED static xmlNode*  get_xml_node_from_pystring(PyObject *string);
G_GNUC_UNUSED static PyObject* get_dict_from_hashtable_of_objects(GHashTable *value);
G_GNUC_UNUSED static PyObject* get_dict_from_hashtable_of_strings(GHashTable *value);
G_GNUC_UNUSED static PyObject* PyGObjectPtr_New(GObject *obj);
G_GNUC_UNUSED static int set_hashtable_of_pygobject(GHashTable *a_hash, PyObject *dict);
G_GNUC_UNUSED static int set_hashtable_of_strings(GHashTable *a_hash, PyObject *dict);
G_GNUC_UNUSED static int set_list_of_strings(GList **a_list, PyObject *seq);
G_GNUC_UNUSED static int set_list_of_xml_nodes(GList **a_list, PyObject *seq);
G_GNUC_UNUSED static int set_list_of_pygobject(GList **a_list, PyObject *seq);
G_GNUC_UNUSED static PyObject *get_list_of_strings(const GList *a_list);
G_GNUC_UNUSED static PyObject *get_list_of_xml_nodes(const GList *a_list);
G_GNUC_UNUSED static PyObject *get_list_of_pygobject(const GList *a_list);
G_GNUC_UNUSED static gboolean valid_seq(PyObject *seq);
G_GNUC_UNUSED static void free_list(GList **a_list, GFunc free_help);
G_GNUC_UNUSED static time_t* get_time_t(PyObject *time);

typedef struct {
	PyObject_HEAD
	GObject *obj;
	PyObject *typename;
} PyGObjectPtr;
static PyTypeObject PyGObjectPtrType;

/* utility functions */
static PyObject *
noneRef() {
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject*
get_dict_from_hashtable_of_objects(GHashTable *value)
{
	GList *keys, *begin;
	PyObject *dict,*proxy;
	GObject *item_value;
	PyObject *item;

	dict = PyDict_New();

	begin = keys = g_hash_table_get_keys(value);
	for (; keys; keys = g_list_next(keys)) {
		item_value = g_hash_table_lookup(value, keys->data);
		if (item_value) {
			item = PyGObjectPtr_New(G_OBJECT(item_value));
			PyDict_SetItemString(dict, (char*)keys->data, item);
			Py_DECREF(item);
		} else {
			PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "hashtable contains a null value");
		}
	}
	g_list_free(begin);

	proxy = PyDictProxy_New(dict);
	Py_DECREF(dict);
	return proxy;
}

static PyObject*
get_dict_from_hashtable_of_strings(GHashTable *value)
{
	GList *keys, *begin;
	PyObject *dict,*proxy;
	char *item_value;
	PyObject *item;

	dict = PyDict_New();

	if (value) {
		begin = keys = g_hash_table_get_keys(value);
		for (; keys; keys = g_list_next(keys)) {
			item_value = g_hash_table_lookup(value, keys->data);
			if (item_value) {
				item = PyString_FromString(item_value);
				PyDict_SetItemString(dict, (char*)keys->data, item);
				Py_DECREF(item);
			} else {
				PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "hashtable contains a null value");
			}
		}
		g_list_free(begin);
	}

	proxy = PyDictProxy_New(dict);
	Py_DECREF(dict);
	return proxy;
}

static xmlBuffer*
xmlnode_to_xmlbuffer(xmlNode *node)
{
	xmlOutputBufferPtr output_buffer;
	xmlBuffer *buffer;

	if (! node)
		return NULL;

	buffer = xmlBufferCreate();
	output_buffer = xmlOutputBufferCreateBuffer(buffer, NULL);
	xmlNodeDumpOutput(output_buffer, NULL, node, 0, 0, NULL);
	xmlOutputBufferClose(output_buffer);
	xmlBufferAdd(buffer, BAD_CAST "", 1);

	return buffer;
}

static PyObject*
get_pystring_from_xml_node(xmlNode *xmlnode)
{
	PyObject *pystring = NULL;
	xmlBuffer *buffer;

	if (xmlnode == NULL) {
		return NULL;
	}
	buffer = xmlnode_to_xmlbuffer(xmlnode);

	if (buffer == NULL) {
		pystring = NULL;
	} else {
		pystring = PyString_FromString((char*)xmlBufferContent(buffer));
		xmlBufferFree(buffer);
	}

	return pystring;
}

static gboolean
valid_seq(PyObject *seq) {
	if (! seq || ( seq != Py_None && ! PyTuple_Check(seq))) {
		 return 0;
	}
	return 1;
}

static void
free_list(GList **a_list, GFunc free_help) {
	if (*a_list) {
		g_list_foreach(*a_list, free_help, NULL);
		g_list_free(*a_list);
	}
}

/** Remove all elements from a_hash and replace them with
 * the key-values pairs from the python dict.
 * Increase reference of new values before removeing
 * values from the hash, so if there are somme common
 * values with RefCoun = 1 they won't be deallocated.
 * */
static int
set_hashtable_of_pygobject(GHashTable *a_hash, PyObject *dict) {
	PyObject *key, *value;
	Py_ssize_t i;

	if (! a_hash) {
		 PyErr_SetString(PyExc_TypeError, "hashtable does not exist");
		 return 0;
	}
	if (dict != Py_None && ! PyDict_Check(dict)) {
		 PyErr_SetString(PyExc_TypeError, "value should be a frozen dict");
		 return 0;
	}
	i = 0;
	// Increase ref count of common object between old and new
	// value of the hashtable
	while (PyDict_Next(dict, &i, &key, &value)) {
		if (! PyString_Check(key) || ! PyObject_TypeCheck(value, &PyGObjectPtrType))
		{
			PyErr_SetString(PyExc_TypeError,
					"value should be a dict, "
					"with string keys "
					"and GObjectPtr values");
			goto failure;
		}
		g_object_ref(((PyGObjectPtr*)value)->obj);
	}
	g_hash_table_remove_all (a_hash);
	i = 0;
	while (PyDict_Next(dict, &i, &key, &value)) {
		const char *ckey = PyString_AsString(key);
		g_hash_table_replace (a_hash, g_strdup(ckey), ((PyGObjectPtr*)value)->obj);
		PyStringFree(ckey);
	}
	return 1;
failure:
	i = 0;
	while (PyDict_Next(dict, &i, &key, &value)) {
		if (! PyString_Check(key) || ! PyObject_TypeCheck(value, &PyGObjectPtrType))
			break;
		g_object_unref((PyGObjectPtr*)value);
	}
	return 0;
}

static int
set_hashtable_of_strings(GHashTable *a_hash, PyObject *dict)
{
	PyObject *key, *value;
	Py_ssize_t i;

	if (! a_hash) {
		 PyErr_SetString(PyExc_TypeError, "hashtable does not exist");
		 return 0;
	}
	if (dict != Py_None && ! PyDict_Check(dict)) {
		 PyErr_SetString(PyExc_TypeError, "value should be a frozen dict");
		 return 0;
	}
	i = 0;
	// Increase ref count of common object between old and new
	// value of the hashtable
	while (PyDict_Next(dict, &i, &key, &value)) {
		if (! PyString_Check(key) || ! PyString_Check(value))
		{
			PyErr_SetString(PyExc_TypeError,
					"value should be a dict, "
					"with string keys "
					"and string values");
			goto failure;
		}
	}
	g_hash_table_remove_all (a_hash);
	i = 0;
	while (PyDict_Next(dict, &i, &key, &value)) {
		const char *ckey = PyString_AsString(key);
		const char *cvalue = PyString_AsString(value);
		g_hash_table_insert (a_hash, g_strdup(ckey), g_strdup(cvalue));
		PyStringFree(ckey);
		PyStringFree(cvalue);
	}
	return 1;
failure:
	return 0;
}

/** Set the GList* pointer, pointed by a_list, to a pointer on a new GList
 * created by converting the python seq into a GList of char*.
 */
static int
set_list_of_strings(GList **a_list, PyObject *seq) {
	GList *list = NULL;
	int l = 0,i;

	if (! valid_seq(seq)) {
		PyErr_SetString(PyExc_TypeError,
				"value should be a tuple of strings");
		return 0;
	}
	if (seq != Py_None) {
		l = PySequence_Length(seq);
	}
	for (i=0; i<l; i++) {
		const char *astr = NULL;

		PyObject *pystr = PySequence_Fast_GET_ITEM(seq, i);
		if (! PyString_Check(pystr)) {
			PyErr_SetString(PyExc_TypeError,
					"value should be a tuple of strings");
			goto failure;
		}
		astr = PyString_AsString(pystr);
		list = g_list_append(list, g_strdup(astr));
		PyStringFree(astr);
	}
	free_list(a_list, (GFunc)g_free);
	*a_list = list;
	return 1;
failure:
	free_list(&list, (GFunc)g_free);
	return 0;
}

/** Set the GList* pointer, pointed by a_list, to a pointer on a new GList
 * created by converting the python seq into a GList of xmlNode*.
 */
static int
set_list_of_xml_nodes(GList **a_list, PyObject *seq) {
	GList *list = NULL;
	int l = 0, i;

	if (! valid_seq(seq)) {
		PyErr_SetString(PyExc_TypeError,
				"value should be a tuple of strings");
		return 0;
	}
	if (seq != Py_None) {
		l = PySequence_Length(seq);
	}
	for (i=0; i<l; i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
		xmlNode *item_node;
		if (! PyString_Check(item)) {
			PyErr_SetString(PyExc_TypeError,
					"value should be a tuple of strings");
			goto failure;
		}
		item_node = get_xml_node_from_pystring(item);
		if (! item_node) {
			PyErr_SetString(PyExc_TypeError,
					"values should be valid XML fragments");
			goto failure;
		}
		list = g_list_append(list, item_node);
	}
	free_list(a_list, (GFunc)xmlFreeNode);
	*a_list = list;
	return 1;
failure:
	free_list(&list, (GFunc)xmlFreeNode);
	return 0;
}

/** Set the GList* pointer, pointed by a_list, to a pointer on a new GList
 * created by converting the python seq into a GList of GObject*.
 */
static int
set_list_of_pygobject(GList **a_list, PyObject *seq) {
	GList *list = NULL;
	int l = 0,i;

	if (!valid_seq(seq)) {
		PyErr_SetString(PyExc_TypeError,
				"value should be a tuple of PyGobject");
		return 0;
	}
	if (seq != Py_None) {
		l = PySequence_Length(seq);
	}
	for (i=0; i<l; i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
		GObject *gobject;
		if (! PyObject_TypeCheck(item, &PyGObjectPtrType)) {
			PyErr_SetString(PyExc_TypeError,
					"value should be a tuple of PyGobject");
			goto failure;
		}
		gobject = g_object_ref(((PyGObjectPtr*)item)->obj);
		list = g_list_append(list, gobject);
	}
	free_list(a_list, (GFunc)g_object_unref);
	*a_list = list;
	return 1;
failure:
	free_list(&list, (GFunc)g_object_unref);
	return 0;
}

static xmlNode*
get_xml_node_from_pystring(PyObject *string) {
	const char *utf8 = NULL;
	Py_ssize_t size;
	xmlNode *xml_node;
	utf8 = get_pystring(string, &size);
	xml_node = lasso_string_fragment_to_xmlnode(utf8, size);
	PyStringFree(utf8);
	return xml_node;
}

/** Return a tuple containing the string contained in a_list */
static PyObject *
get_list_of_strings(const GList *a_list) {
	PyObject *a_tuple = NULL;
	int i = 0;

	/* Cast because g_list_length does not take const but is a const function */
	a_tuple = PyTuple_New(g_list_length((GList*)a_list));
	if (! a_tuple)
		goto failure;
	if (! a_list) {
		return a_tuple;
	}
	while (a_list) {
		if (a_list->data) {
			PyObject *str = PyString_FromString((const char*)a_list->data);
			if (!str) {
				goto failure;
			}
			PyTuple_SetItem(a_tuple, i, str);
			i++;
		} else {
			PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "list contains a NULL value");
		}
		a_list = a_list->next;
	}
	if (_PyTuple_Resize(&a_tuple, i))
		goto failure;
	return a_tuple;
failure:
	PyErr_SetString(PyExc_TypeError, "Allocation problem in get_list_of_strings");
	Py_XDECREF(a_tuple);
	return NULL;
}

static PyObject *
get_list_of_xml_nodes(const GList *a_list) {
	PyObject *a_tuple = NULL;
	int i = 0;

	/* Cast because g_list_length does not take const but is a const function */
	a_tuple = PyTuple_New(g_list_length((GList*)a_list));
	if (! a_tuple)
		goto failure;
	if (! a_list) {
		return a_tuple;
	}
	while (a_list) {
		if (a_list->data) {
			PyObject *str = get_pystring_from_xml_node((xmlNode*)a_list->data);
			if (str) {
				PyTuple_SetItem(a_tuple, i, str);
				i++;
			} else {
				PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "could not convert an xmlNode to a string");
			}
		} else {
			PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "list contains a NULL value");
		}
		a_list = a_list->next;
	}
	if (_PyTuple_Resize(&a_tuple, i))
		goto failure;
	return a_tuple;
failure:
	PyErr_SetString(PyExc_TypeError, "Allocation problem in get_list_of_strings");
	Py_XDECREF(a_tuple);
	return NULL;
}

static PyObject *
get_list_of_pygobject(const GList *a_list) {
	PyObject *a_tuple = NULL;
	int i = 0;

	/* Cast because g_list_length does not take const but is a const function */
	a_tuple = PyTuple_New(g_list_length((GList*)a_list));
	if (! a_tuple)
		goto failure;
	if (! a_list) {
		return a_tuple;
	}
	while (a_list) {
		if (a_list->data) {
			PyObject *pygobject;
			pygobject = PyGObjectPtr_New((GObject*)a_list->data);
			if (pygobject) {
				PyTuple_SetItem(a_tuple, i, pygobject);
				i++;
			} else {
				PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "could not convert a GObject to a PyGobject");
			}
		} else {
			PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "list contains a NULL value");
		}
		a_list = a_list->next;
	}
	if (_PyTuple_Resize(&a_tuple, i))
		goto failure;
	return a_tuple;
failure:
	PyErr_SetString(PyExc_TypeError, "Allocation problem in get_list_of_strings");
	Py_XDECREF(a_tuple);
	return NULL;
}

/**
 * get_time_t:
 * @time: a #PyInt
 *
 * Convert a python integer object to a time_t value, considering it is a unsigned 32 bit integer
 * value.
 *
 * Return: a time_t* value if time is a python integer, NULL otherwise.
 */
static time_t*
get_time_t(PyObject *time)
{
	if (time != Py_None && PyInt_Check(time)) {
		time_t *val = malloc(sizeof(time_t));

		*val = (time_t)PyInt_AS_LONG(time);
		return val;
	}
	return NULL;
}

/* wrapper around GObject */
static void
PyGObjectPtr_dealloc(PyGObjectPtr *self)
{
	if (lasso_flag_memory_debug) {
		fprintf(stderr, "dealloc (%p ptr to %p (type:%s, rc:%d))\n",
				self, self->obj,
				G_OBJECT_TYPE_NAME(self->obj),
				self->obj->ref_count);
	}
	g_object_set_qdata_full(self->obj, lasso_wrapper_key, NULL, NULL);
	g_object_unref(self->obj);
	Py_XDECREF(self->typename);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
startswith(const char *string, const char *prefix)
{
    return strncmp(string, prefix, strlen(prefix)) == 0;
}

static PyObject*
PyGObjectPtr_New(GObject *obj)
{
	PyGObjectPtr *self;

	if (obj == NULL) {
		return noneRef();
	}

	self = (PyGObjectPtr*)g_object_get_qdata(obj, lasso_wrapper_key);
	if (self != NULL) {
		Py_INCREF(self);
	} else {
        const char *typename;

		self = (PyGObjectPtr*)PyObject_NEW(PyGObjectPtr, &PyGObjectPtrType);
		g_object_set_qdata_full(obj, lasso_wrapper_key, self, NULL);
		self->obj = g_object_ref(obj);
        typename = G_OBJECT_TYPE_NAME(obj);
        /* XXX: Fixme !!!!! */
        if (startswith(typename, "LassoDgme")) {
    		self->typename = PyString_FromString(typename+9);
        } else if (startswith(typename, "Lasso")) {
    		self->typename = PyString_FromString(typename+5);
        } else {
            self->typename = PyString_FromString(typename);
        }
	}
	return (PyObject*)self;
}

static PyObject *
PyGObjectPtr_repr(PyGObjectPtr *obj)
{
	return PyString_FromFormat("<PyGObjectPtr to %p (type: %s, refcount: %d)>",
			obj->obj,
			G_OBJECT_TYPE_NAME(obj->obj),
			obj->obj->ref_count);
}

static PyMemberDef PyGObjectPtr_members[] = {
	{"typename", T_OBJECT, offsetof(PyGObjectPtr, typename), 0, "typename"},
	{NULL, 0, 0, 0, NULL}
};

static PyObject*
PyGObjectPtr_get_refcount(PyGObjectPtr *self, G_GNUC_UNUSED void *closure)
{
	PyObject *refcount;

	refcount = PyInt_FromLong(self->obj->ref_count);
	Py_INCREF(refcount);
	return refcount;
}

static PyGetSetDef PyGObjectPtr_getseters[] = {
	{"refcount", (getter)PyGObjectPtr_get_refcount, NULL,
		"reference count of intern GObject*", NULL},
	{NULL, NULL, NULL, NULL, NULL}  /* Sentinel */
};


static PyTypeObject PyGObjectPtrType = {
	PyVarObject_HEAD_INIT(NULL, 0 /* ob_size */)
	"_lasso.PyGObjectPtr", /* tp_name */
	sizeof(PyGObjectPtr),  /* tp_basicsize */
	0,                     /* tp_itemsize */
	(destructor)PyGObjectPtr_dealloc, /* tp_dealloc */
	0,       /*tp_print*/
	0,                      /*tp_getattr*/
	.tp_setattr = 0,       /*tp_setattr*/
	0,       /*tp_compare*/
	(reprfunc)PyGObjectPtr_repr,       /*tp_repr*/
	0,       /*tp_as_number*/
	0,       /*tp_as_sequence*/
	0,       /*tp_as_mapping*/
	0,       /*tp_hash */
	0,       /*tp_call*/
	0,       /*tp_str*/
	0,       /*tp_getattro*/
	0,       /*tp_setattro*/
	0,       /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,  /*tp_flags*/
	"PyGObjectPtr objects",   /* tp_doc */
	0,       /* tp_traverse */
	0,       /* tp_clear */
	0,       /* tp_richcompare */
	0,       /* tp_weaklistoffset */
	0,       /* tp_iter */
	0,       /* tp_iternext */
	0,       /* tp_methods */
	.tp_members=PyGObjectPtr_members,   /* tp_members */
	PyGObjectPtr_getseters, /* tp_getset */
	NULL,
	NULL
};

static void
set_object_field(GObject **a_gobject_ptr, PyGObjectPtr *a_pygobject) {
	if (*a_gobject_ptr) {
		g_object_unref(*a_gobject_ptr);
	}
	if ((PyObject*)a_pygobject == Py_None) {
		*a_gobject_ptr = NULL;
	} else {
		*a_gobject_ptr = g_object_ref(a_pygobject->obj);
	}
}


static PyObject *get_logger_object(const char *domain) {
	static PyObject *_logger_object = NULL;
	PyObject *lasso_module = NULL;
	PyObject *logging_module = NULL;

	lasso_module = PyImport_ImportModule("lasso");
	if (lasso_module && PyObject_HasAttrString(lasso_module, "logger")) {
		_logger_object = PyObject_GetAttrString(lasso_module, "logger");
		if (_logger_object)
			goto exit;
	}

	logging_module = PyImport_ImportModule("logging");
	if (logging_module) {
		_logger_object = PyObject_CallMethod(logging_module, "getLogger", "s", domain);
	}
exit:
	if (lasso_module) {
		Py_DECREF(lasso_module);
	}
	if (logging_module) {
		Py_DECREF(logging_module);
	}
	if (_logger_object == Py_None) {
		Py_DECREF(_logger_object);
		_logger_object = NULL;
	}
	return _logger_object;
}

static void
lasso_python_log(const char *domain, GLogLevelFlags log_level, const gchar *message,
		G_GNUC_UNUSED gpointer user_data)
{
	PyObject *logger_object = get_logger_object(domain), *result;

	if (PyErr_Occurred()) {
		PyErr_Print();
		PyErr_Clear();
		return;
	}

	char *method = NULL;

	if (! logger_object) {
		PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "neither lasso.logger nor "
				 "logging.getLogger('lasso') did return a logger", 1);
		return;
	}
	switch (log_level) {
		case G_LOG_LEVEL_DEBUG:
			method = "debug";
			break;
		case G_LOG_LEVEL_INFO:
		case G_LOG_LEVEL_MESSAGE:
			method = "info";
			break;
		case G_LOG_LEVEL_WARNING:
			method = "warning";
			break;
		case G_LOG_LEVEL_CRITICAL:
			method = "error";
			break;
		case G_LOG_LEVEL_ERROR:
			method = "critical";
			break;
		default:
			return;
	}
	result = PyObject_CallMethod(logger_object, method, "ss", "%s", message);
	Py_DECREF(logger_object);
	if (result) {
		Py_DECREF(result);
	} else {
		PyErr_WarnFormat(PyExc_RuntimeWarning, 1, "lasso could not call method %s on its logger", method);
	}
	/* clear any exception emitted during log call */
	if (PyErr_Occurred()) {
		PyErr_Print();
	}
	PyErr_Clear();
}
