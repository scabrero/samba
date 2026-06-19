/*
   Unix SMB/CIFS implementation.

   Python bindings for HTTP helpers.

   Copyright (C) 2026

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "lib/replace/system/python.h"
#include "includes.h"
#include "python/py3compat.h"
#include "python/modules.h"
#include "libcli/http/http.h"

static bool py_http_parse_headers(TALLOC_CTX *mem_ctx,
				  PyObject *py_headers,
				  struct http_header **headers)
{
	PyObject *headers_seq = NULL;
	Py_ssize_t i;

	headers_seq = PySequence_Fast(
		py_headers,
		"headers must be a sequence of (key, value) pairs");
	if (headers_seq == NULL) {
		return false;
	}

	for (i = 0; i < PySequence_Fast_GET_SIZE(headers_seq); i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(headers_seq, i);
		PyObject *pair_seq = NULL;
		PyObject *key_obj = NULL;
		PyObject *value_obj = NULL;
		const char *key = NULL;
		const char *value = NULL;
		int ret;

		pair_seq = PySequence_Fast(item, "each header must be (key, value)");
		if (pair_seq == NULL) {
			Py_DECREF(headers_seq);
			return false;
		}

		if (PySequence_Fast_GET_SIZE(pair_seq) != 2) {
			PyErr_SetString(PyExc_TypeError,
					"each header must contain key and value");
			Py_DECREF(pair_seq);
			Py_DECREF(headers_seq);
			return false;
		}

		key_obj = PySequence_Fast_GET_ITEM(pair_seq, 0);
		value_obj = PySequence_Fast_GET_ITEM(pair_seq, 1);

		key = PyUnicode_AsUTF8(key_obj);
		if (key == NULL) {
			Py_DECREF(pair_seq);
			Py_DECREF(headers_seq);
			return false;
		}

		value = PyUnicode_AsUTF8(value_obj);
		if (value == NULL) {
			Py_DECREF(pair_seq);
			Py_DECREF(headers_seq);
			return false;
		}

		ret = http_add_header(mem_ctx, headers, key, value);
		if (ret != 0) {
			PyErr_SetString(PyExc_ValueError,
					"invalid header in headers input");
			Py_DECREF(pair_seq);
			Py_DECREF(headers_seq);
			return false;
		}

		Py_DECREF(pair_seq);
	}

	Py_DECREF(headers_seq);
	return true;
}

static PyObject *py_http_headers_to_list(struct http_header *headers)
{
	PyObject *py_headers = NULL;
	struct http_header *h = NULL;

	py_headers = PyList_New(0);
	if (py_headers == NULL) {
		return NULL;
	}

	for (h = headers; h != NULL; h = h->next) {
		PyObject *item = Py_BuildValue("(ss)", h->key, h->value);
		int ret;

		if (item == NULL) {
			Py_DECREF(py_headers);
			return NULL;
		}

		ret = PyList_Append(py_headers, item);
		Py_DECREF(item);
		if (ret != 0) {
			Py_DECREF(py_headers);
			return NULL;
		}
	}

	return py_headers;
}

static PyObject *py_http_add_header(PyObject *module,
				    PyObject *args,
				    PyObject *kwargs)
{
	const char * const kwnames[] = { "headers", "key", "value", NULL };
	PyObject *py_headers = NULL;
	const char *key = NULL;
	const char *value = NULL;
	struct http_header *headers = NULL;
	PyObject *ret = NULL;
	TALLOC_CTX *frame = NULL;
	int rc;
	bool ok;

	ok = PyArg_ParseTupleAndKeywords(args, kwargs, "Oss",
					 discard_const_p(char *, kwnames),
					 &py_headers, &key, &value);
	if (!ok) {
		return NULL;
	}

	frame = talloc_stackframe();
	if (!py_http_parse_headers(frame, py_headers, &headers)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	rc = http_add_header(frame, &headers, key, value);
	if (rc != 0) {
		PyErr_SetString(PyExc_ValueError, "invalid header key or value");
		TALLOC_FREE(frame);
		return NULL;
	}

	ret = py_http_headers_to_list(headers);
	TALLOC_FREE(frame);
	return ret;
}

static PyObject *py_http_replace_header(PyObject *module,
					PyObject *args,
					PyObject *kwargs)
{
	const char * const kwnames[] = { "headers", "key", "value", NULL };
	PyObject *py_headers = NULL;
	const char *key = NULL;
	const char *value = NULL;
	struct http_header *headers = NULL;
	PyObject *ret = NULL;
	TALLOC_CTX *frame = NULL;
	int rc;
	bool ok;

	ok = PyArg_ParseTupleAndKeywords(args, kwargs, "Oss",
					 discard_const_p(char *, kwnames),
					 &py_headers, &key, &value);
	if (!ok) {
		return NULL;
	}

	frame = talloc_stackframe();
	if (!py_http_parse_headers(frame, py_headers, &headers)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	rc = http_replace_header(frame, &headers, key, value);
	if (rc != 0) {
		PyErr_SetString(PyExc_ValueError, "invalid header key or value");
		TALLOC_FREE(frame);
		return NULL;
	}

	ret = py_http_headers_to_list(headers);
	TALLOC_FREE(frame);
	return ret;
}

static PyObject *py_http_remove_header(PyObject *module,
				       PyObject *args,
				       PyObject *kwargs)
{
	const char * const kwnames[] = { "headers", "key", NULL };
	PyObject *py_headers = NULL;
	const char *key = NULL;
	struct http_header *headers = NULL;
	PyObject *ret = NULL;
	TALLOC_CTX *frame = NULL;
	int rc;
	bool ok;

	ok = PyArg_ParseTupleAndKeywords(args, kwargs, "Os",
					 discard_const_p(char *, kwnames),
					 &py_headers, &key);
	if (!ok) {
		return NULL;
	}

	frame = talloc_stackframe();
	if (!py_http_parse_headers(frame, py_headers, &headers)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	rc = http_remove_header(&headers, key);
	if (rc != 0) {
		PyErr_Format(PyExc_KeyError, "header '%s' not found", key);
		TALLOC_FREE(frame);
		return NULL;
	}

	ret = py_http_headers_to_list(headers);
	TALLOC_FREE(frame);
	return ret;
}

static PyMethodDef py_http_methods[] = {
	{
		"add_header",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_http_add_header),
		METH_VARARGS | METH_KEYWORDS,
		"add_header(headers, key, value) -> new header list",
	},
	{
		"replace_header",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_http_replace_header),
		METH_VARARGS | METH_KEYWORDS,
		"replace_header(headers, key, value) -> new header list",
	},
	{
		"remove_header",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_http_remove_header),
		METH_VARARGS | METH_KEYWORDS,
		"remove_header(headers, key) -> new header list",
	},
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "http",
	.m_doc = "HTTP helper bindings.",
	.m_size = -1,
	.m_methods = py_http_methods,
};

MODULE_INIT_FUNC(http)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return NULL;
	}

	PyModule_AddIntConstant(m, "HTTP_OK", HTTP_OK);
	PyModule_AddIntConstant(m, "HTTP_BADREQUEST", HTTP_BADREQUEST);
	PyModule_AddIntConstant(m, "HTTP_NOTFOUND", HTTP_NOTFOUND);
	PyModule_AddIntConstant(m, "HTTP_INTERNAL", HTTP_INTERNAL);

	return m;
}
