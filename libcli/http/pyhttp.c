#include "lib/replace/system/python.h"
#include "includes.h"
#include "python/py3compat.h"
#include "python/modules.h"
#include "libcli/util/pyerrors.h"
#include "libcli/http/http.h"
#include "libcli/http/http_internal.h"
#include "lib/events/events.h"

struct py_http_connection {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct http_conn *http_conn;
	char *server;
	uint16_t port;
};

static bool py_http_connection_is_connected(struct py_http_connection *self)
{
	return self->http_conn != NULL;
}

static bool py_http_require_connection(struct py_http_connection *self)
{
	if (py_http_connection_is_connected(self)) {
		return true;
	}

	PyErr_SetString(PyExc_RuntimeError, "HTTP connection is not connected");
	return false;
}

static void py_http_connection_dealloc(struct py_http_connection *self)
{
	TALLOC_FREE(self->mem_ctx);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *py_http_connection_new(PyTypeObject *type,
					PyObject *args,
					PyObject *kwargs)
{
	struct py_http_connection *self = NULL;

	(void)args;
	(void)kwargs;

	self = (struct py_http_connection *)type->tp_alloc(type, 0);
	if (self == NULL) {
		return NULL;
	}

	self->mem_ctx = talloc_new(NULL);
	if (self->mem_ctx == NULL) {
		Py_DECREF(self);
		return PyErr_NoMemory();
	}

	self->ev = s4_event_context_init(self->mem_ctx);
	if (self->ev == NULL) {
		Py_DECREF(self);
		return PyErr_NoMemory();
	}

	return (PyObject *)self;
}

static bool py_http_method_from_string(const char *method,
				       enum http_cmd_type *type)
{
	if (strcasecmp_m(method, "GET") == 0) {
		*type = HTTP_REQ_GET;
		return true;
	}
	if (strcasecmp_m(method, "POST") == 0) {
		*type = HTTP_REQ_POST;
		return true;
	}
	if (strcasecmp_m(method, "HEAD") == 0) {
		*type = HTTP_REQ_HEAD;
		return true;
	}
	if (strcasecmp_m(method, "PUT") == 0) {
		*type = HTTP_REQ_PUT;
		return true;
	}
	if (strcasecmp_m(method, "DELETE") == 0) {
		*type = HTTP_REQ_DELETE;
		return true;
	}
	if (strcasecmp_m(method, "OPTIONS") == 0) {
		*type = HTTP_REQ_OPTIONS;
		return true;
	}
	if (strcasecmp_m(method, "TRACE") == 0) {
		*type = HTTP_REQ_TRACE;
		return true;
	}
	if (strcasecmp_m(method, "CONNECT") == 0) {
		*type = HTTP_REQ_CONNECT;
		return true;
	}
	if (strcasecmp_m(method, "PATCH") == 0) {
		*type = HTTP_REQ_PATCH;
		return true;
	}

	return false;
}

static bool py_http_headers_has_key(struct http_header *headers, const char *key)
{
	struct http_header *header = NULL;

	for (header = headers; header != NULL; header = header->next) {
		if (strcasecmp_m(header->key, key) == 0) {
			return true;
		}
	}

	return false;
}

static bool py_http_add_python_headers(TALLOC_CTX *mem_ctx,
				       struct http_header **headers,
				       PyObject *py_headers)
{
	PyObject *py_key = NULL;
	PyObject *py_value = NULL;
	Py_ssize_t pos = 0;

	if (py_headers == Py_None) {
		return true;
	}

	if (!PyDict_Check(py_headers)) {
		PyErr_SetString(PyExc_TypeError, "headers must be a dict or None");
		return false;
	}

	while (PyDict_Next(py_headers, &pos, &py_key, &py_value)) {
		const char *key = NULL;
		const char *value = NULL;
		int ret;

		if (!PyUnicode_Check(py_key) || !PyUnicode_Check(py_value)) {
			PyErr_SetString(PyExc_TypeError,
					"header names and values must be strings");
			return false;
		}

		key = PyUnicode_AsUTF8(py_key);
		if (key == NULL) {
			return false;
		}

		value = PyUnicode_AsUTF8(py_value);
		if (value == NULL) {
			return false;
		}

		ret = http_add_header(mem_ctx, headers, key, value);
		if (ret != 0) {
			PyErr_SetString(PyExc_ValueError, "invalid HTTP header");
			return false;
		}
	}

	return true;
}

static PyObject *py_http_connection_connect(PyObject *self,
					    PyObject *args,
					    PyObject *kwargs)
{
	struct py_http_connection *conn = (struct py_http_connection *)self;
	TALLOC_CTX *frame = NULL;
	const char * const kwnames[] = { "server", "port", NULL };
	const char *server = NULL;
	unsigned int port = 0;
	struct tevent_req *req = NULL;
	struct http_conn *http_conn = NULL;
	int ret;
	bool ok;

	ok = PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "sI:connect",
					 discard_const_p(char *, kwnames),
					 &server,
					 &port);
	if (!ok) {
		return NULL;
	}

	if (py_http_connection_is_connected(conn)) {
		PyErr_SetString(PyExc_RuntimeError, "HTTP connection is already connected");
		return NULL;
	}

	if (port > UINT16_MAX) {
		PyErr_SetString(PyExc_ValueError, "port must be <= 65535");
		return NULL;
	}

	frame = talloc_new(conn->mem_ctx);
	if (frame == NULL) {
		return PyErr_NoMemory();
	}

	req = http_connect_send(frame,
				conn->ev,
				server,
				port,
				NULL,
				NULL);
	if (req == NULL) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	if (!tevent_req_poll(req, conn->ev)) {
		talloc_free(frame);
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	ret = http_connect_recv(req, conn->mem_ctx, &http_conn);
	talloc_free(frame);
	if (ret != 0) {
		errno = ret;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	TALLOC_FREE(conn->server);
	conn->server = talloc_strdup(conn->mem_ctx, server);
	if (conn->server == NULL) {
		TALLOC_FREE(http_conn);
		return PyErr_NoMemory();
	}

	conn->port = port;
	conn->http_conn = http_conn;

	Py_RETURN_NONE;
}

static PyObject *py_http_connection_disconnect(PyObject *self,
					       PyObject *args,
					       PyObject *kwargs)
{
	struct py_http_connection *conn = (struct py_http_connection *)self;
	TALLOC_CTX *frame = NULL;
	struct tevent_req *req = NULL;
	int ret;

	(void)args;
	(void)kwargs;

	if (!py_http_require_connection(conn)) {
		return NULL;
	}

	frame = talloc_new(conn->mem_ctx);
	if (frame == NULL) {
		return PyErr_NoMemory();
	}

	req = http_disconnect_send(frame, conn->ev, conn->http_conn);
	if (req == NULL) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	if (!tevent_req_poll(req, conn->ev)) {
		talloc_free(frame);
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	ret = http_disconnect_recv(req);
	talloc_free(frame);
	if (ret != 0) {
		errno = ret;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	TALLOC_FREE(conn->http_conn);
	TALLOC_FREE(conn->server);
	conn->port = 0;
	Py_RETURN_NONE;
}

static PyObject *py_http_connection_send_request(PyObject *self,
						 PyObject *args,
						 PyObject *kwargs)
{
	struct py_http_connection *conn = (struct py_http_connection *)self;
	TALLOC_CTX *frame = NULL;
	const char * const kwnames[] = {
		"method", "uri", "headers", "body", NULL
	};
	const char *method = NULL;
	const char *uri = NULL;
	PyObject *py_headers = Py_None;
	PyObject *py_body = Py_None;
	struct http_request *request = NULL;
	struct tevent_req *req = NULL;
	enum http_cmd_type type;
	char *body = NULL;
	Py_ssize_t body_len = 0;
	NTSTATUS status;
	bool ok;

	if (!py_http_require_connection(conn)) {
		return NULL;
	}

	ok = PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "ss|OO:send_request",
					 discard_const_p(char *, kwnames),
					 &method,
					 &uri,
					 &py_headers,
					 &py_body);
	if (!ok) {
		return NULL;
	}

	if (!py_http_method_from_string(method, &type)) {
		PyErr_SetString(PyExc_ValueError, "unsupported HTTP method");
		return NULL;
	}

	if (py_body != Py_None) {
		if (!PyBytes_Check(py_body)) {
			PyErr_SetString(PyExc_TypeError, "body must be bytes or None");
			return NULL;
		}
		if (PyBytes_AsStringAndSize(py_body, &body, &body_len) != 0) {
			return NULL;
		}
	}

	frame = talloc_new(conn->mem_ctx);
	if (frame == NULL) {
		return PyErr_NoMemory();
	}

	request = talloc_zero(frame, struct http_request);
	if (request == NULL) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	request->type = type;
	request->major = '1';
	request->minor = '1';
	request->uri = talloc_strdup(request, uri);
	if (request->uri == NULL) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	if (body_len > 0) {
		request->body = data_blob_talloc(request, body, body_len);
		if (request->body.data == NULL) {
			talloc_free(frame);
			return PyErr_NoMemory();
		}
	}

	if (!py_http_add_python_headers(request, &request->headers, py_headers)) {
		talloc_free(frame);
		return NULL;
	}

	if (!py_http_headers_has_key(request->headers, "Host")) {
		char *host = talloc_asprintf(request, "%s:%u",
					     conn->server, (unsigned int)conn->port);
		int ret;

		if (host == NULL) {
			talloc_free(frame);
			return PyErr_NoMemory();
		}

		ret = http_add_header(request, &request->headers, "Host", host);
		if (ret != 0) {
			talloc_free(frame);
			PyErr_SetString(PyExc_ValueError, "invalid Host header");
			return NULL;
		}
	}

	if (!py_http_headers_has_key(request->headers, "Content-Length")) {
		char content_length[32];
		int ret;

		snprintf(content_length, sizeof(content_length),
			 "%zu", (size_t)body_len);
		ret = http_add_header(request,
				      &request->headers,
				      "Content-Length",
				      content_length);
		if (ret != 0) {
			talloc_free(frame);
			PyErr_SetString(PyExc_ValueError,
					"invalid Content-Length header");
			return NULL;
		}
	}

	req = http_send_request_send(frame, conn->ev, conn->http_conn, request);
	if (req == NULL) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	if (!tevent_req_poll(req, conn->ev)) {
		talloc_free(frame);
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	status = http_send_request_recv(req);
	talloc_free(frame);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_http_response_to_python(struct http_request *response)
{
	PyObject *result = NULL;
	PyObject *status = NULL;
	PyObject *reason = NULL;
	PyObject *headers = NULL;
	PyObject *body = NULL;
	struct http_header *header = NULL;
	int ret;

	result = PyTuple_New(4);
	if (result == NULL) {
		return NULL;
	}

	status = PyLong_FromUnsignedLong(response->response_code);
	if (status == NULL) {
		Py_DECREF(result);
		return NULL;
	}
	PyTuple_SET_ITEM(result, 0, status);

	if (response->response_code_line != NULL) {
		reason = PyUnicode_FromString(response->response_code_line);
	} else {
		Py_INCREF(Py_None);
		reason = Py_None;
	}
	if (reason == NULL) {
		Py_DECREF(result);
		return NULL;
	}
	PyTuple_SET_ITEM(result, 1, reason);

	headers = PyDict_New();
	if (headers == NULL) {
		Py_DECREF(result);
		return NULL;
	}
	for (header = response->headers; header != NULL; header = header->next) {
		PyObject *value = PyUnicode_FromString(header->value);

		if (value == NULL) {
			Py_DECREF(headers);
			Py_DECREF(result);
			return NULL;
		}

		ret = PyDict_SetItemString(headers, header->key, value);
		Py_DECREF(value);
		if (ret != 0) {
			Py_DECREF(headers);
			Py_DECREF(result);
			return NULL;
		}
	}
	PyTuple_SET_ITEM(result, 2, headers);

	body = PyBytes_FromStringAndSize((const char *)response->body.data,
					 response->body.length);
	if (body == NULL) {
		Py_DECREF(result);
		return NULL;
	}
	PyTuple_SET_ITEM(result, 3, body);

	return result;
}

static PyObject *py_http_connection_read_response(PyObject *self,
						  PyObject *args,
						  PyObject *kwargs)
{
	struct py_http_connection *conn = (struct py_http_connection *)self;
	TALLOC_CTX *frame = NULL;
	PyObject *result = NULL;
	const char * const kwnames[] = { "max_content_length", NULL };
	unsigned long long max_content_length = SIZE_MAX;
	struct tevent_req *req = NULL;
	struct http_request *response = NULL;
	NTSTATUS status;
	bool ok;

	if (!py_http_require_connection(conn)) {
		return NULL;
	}

	ok = PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "|K:read_response",
					 discard_const_p(char *, kwnames),
					 &max_content_length);
	if (!ok) {
		return NULL;
	}

	if (max_content_length > SIZE_MAX) {
		PyErr_SetString(PyExc_ValueError,
				"max_content_length exceeds platform size_t");
		return NULL;
	}

	frame = talloc_new(conn->mem_ctx);
	if (frame == NULL) {
		return PyErr_NoMemory();
	}

	req = http_read_response_send(frame,
				      conn->ev,
				      conn->http_conn,
				      (size_t)max_content_length);
	if (req == NULL) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	if (!tevent_req_poll(req, conn->ev)) {
		talloc_free(frame);
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	status = http_read_response_recv(req, frame, &response);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(frame);
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	result = py_http_response_to_python(response);
	talloc_free(frame);
	return result;
}

static PyMethodDef py_http_connection_methods[] = {
	{
		"connect",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_http_connection_connect),
		METH_VARARGS|METH_KEYWORDS,
		"connect(server, port) -> None",
	},
	{
		"disconnect",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_http_connection_disconnect),
		METH_VARARGS|METH_KEYWORDS,
		"disconnect() -> None",
	},
	{
		"send_request",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_http_connection_send_request),
		METH_VARARGS|METH_KEYWORDS,
		"send_request(method, uri, headers=None, body=None) -> None",
	},
	{
		"read_response",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_http_connection_read_response),
		METH_VARARGS|METH_KEYWORDS,
		"read_response(max_content_length=SIZE_MAX) -> (status, reason, headers, body)",
	},
	{0},
};

static PyTypeObject py_http_connection_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "http.Connection",
	.tp_basicsize = sizeof(struct py_http_connection),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "Samba HTTP connection",
	.tp_new = py_http_connection_new,
	.tp_dealloc = (destructor)py_http_connection_dealloc,
	.tp_methods = py_http_connection_methods,
};

static PyMethodDef py_http_methods[] = {
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "http",
	.m_doc = "Python bindings for Samba HTTP client support.",
	.m_size = -1,
	.m_methods = py_http_methods,
};

MODULE_INIT_FUNC(http)
{
	PyObject *m = NULL;

	if (PyType_Ready(&py_http_connection_type) < 0) {
		return NULL;
	}

	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return NULL;
	}

	Py_INCREF((PyObject *)&py_http_connection_type);
	if (PyModule_AddObject(m,
			       "Connection",
			       (PyObject *)&py_http_connection_type) != 0) {
		Py_DECREF((PyObject *)&py_http_connection_type);
		Py_DECREF(m);
		return NULL;
	}
	return m;
}
