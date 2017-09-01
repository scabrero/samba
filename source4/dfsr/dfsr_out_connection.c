/*
   Unix SMB/CIFS mplementation.

   DFS Replication service

   Copyright (C) Matthieu Patou <mat@matws.net> 2013-2014
   Copyright (C) Samuel Cabrero <scabrero@samba.org> 2021

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

#include "includes.h"
#include "dfsr/dfsr_service.h"
#include "samba/service.h"
#include "auth/auth.h"
#include "lib/events/events.h"
#include "util/tevent_ntstatus.h"
#include "libcli/composite/composite.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

struct dfsrsrv_conn_state {
	struct dfsrsrv_service *service;
	struct dfsrsrv_connection *conn;
	struct dcerpc_pipe *pipe;

	enum frstrans_ProtocolVersion version;
	uint32_t flags;
	struct frstrans_AsyncResponseContext *poll_response;
};

static void dfsrsrv_frstrans_connect_done(struct composite_context *creq);
static struct tevent_req *dfsrsrv_establish_connection_send(
		TALLOC_CTX *mem_ctx,
		struct dfsrsrv_service *service,
		struct dfsrsrv_connection *conn)
{
	struct tevent_req *req;
	struct dfsrsrv_conn_state *state;
	struct composite_context *creq;
	struct cli_credentials *credentials;
	struct GUID_txt_buf txtguid;

	req = tevent_req_create(mem_ctx, &state, struct dfsrsrv_conn_state);
	if (req == NULL) {
		return NULL;
	}

	state->service = service;
	state->conn = conn;

	DBG_INFO("Establish DFS-R connection {%s} to '%s'\n",
		 GUID_buf_string(&state->conn->guid, &txtguid),
		 dcerpc_binding_get_string_option(conn->binding, "host"));
	dcerpc_binding_set_flags(conn->binding,
			DCERPC_CONCURRENT_MULTIPLEX, 0);

	credentials = service->system_session_info->credentials;
	creq = dcerpc_pipe_connect_b_send(state, conn->binding,
					  &ndr_table_frstrans,
					  credentials,
					  service->task->event_ctx,
					  service->task->lp_ctx);
	if (tevent_req_nomem(creq, req)) {
		return tevent_req_post(req, service->task->event_ctx);
	}
	composite_continue(NULL, creq, dfsrsrv_frstrans_connect_done, req);

	return req;
}

static void dfsrsrv_establish_connection_done(struct tevent_req *subreq);
static void dfsrsrv_frstrans_connect_done(struct composite_context *creq)
{
	struct tevent_req *req;
	struct dfsrsrv_conn_state *state;
	NTSTATUS status;
	struct tevent_req *subreq;

	req = talloc_get_type(creq->async.private_data, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_conn_state);

	status = dcerpc_pipe_connect_b_recv(creq, state, &state->pipe);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = dcerpc_frstrans_EstablishConnection_send(
			state,
			state->service->task->event_ctx,
			state->pipe->binding_handle,
			state->conn->group->guid,
			state->conn->guid,
			FRSTRANS_PROTOCOL_VERSION_LONGHORN_SERVER,
			0,
			&state->version,
			&state->flags);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_establish_connection_done,
				req);
}

static void dfsrsrv_connection_asyncpoll_done(struct tevent_req *subreq);
static void dfsrsrv_establish_connection_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_conn_state *state;
	NTSTATUS status;
	WERROR result;
	uint32_t old_timeout;
	struct GUID_txt_buf txtguid;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_conn_state);

	status = dcerpc_frstrans_EstablishConnection_recv(subreq, state,
							  &result);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to establish DFS-R connection {%s}: %s\n",
			GUID_buf_string(&state->conn->guid, &txtguid),
			nt_errstr(status));

		/* [MS-FRS2] 3.3.4.2 On error, transition to DISCONNECTED and
		 * try again after a timeout interval */
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		DBG_ERR("Failed to establish DFS-R connection {%s}: %s\n",
			GUID_buf_string(&state->conn->guid, &txtguid),
			win_errstr(result));

		/* [MS-FRS2] 3.3.4.2 On error, transition to DISCONNECTED and
		 * try again after a timeout interval */
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		tevent_req_nterror(req, werror_to_ntstatus(result));
		return;
	}

	/* [MS-FRS2] 3.3.4.2 On success, transition to CONNECTED state and
	 * call AsyncPoll */
	state->poll_response = talloc_zero(state,
			struct frstrans_AsyncResponseContext);
	if (tevent_req_nomem(state->poll_response, req)) {
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		return;
	}
	state->conn->state = CONNECTION_STATE_CONNECTED;

	old_timeout = dcerpc_binding_handle_set_timeout(
			state->pipe->binding_handle, UINT32_MAX);

	subreq =  dcerpc_frstrans_AsyncPoll_send(state,
			state->service->task->event_ctx,
			state->pipe->binding_handle,
			state->conn->guid,
			state->poll_response);

	dcerpc_binding_handle_set_timeout(state->pipe->binding_handle,
			old_timeout);

	if (tevent_req_nomem(subreq, req)) {
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_connection_asyncpoll_done,
				req);

	/* [MS-FRS2] 3.3.4.2 Then, transition to POLLING state and call
	 * EstablishSession for each content set that is part of this
	 * connection's replica group */
	state->conn->state = CONNECTION_STATE_POLLING;
}

static void dfsrsrv_connection_asyncpoll_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_conn_state *state;
	NTSTATUS status;
	WERROR result;
	uint32_t old_timeout;
	struct frstrans_AsyncResponseContext *response;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_conn_state);
	response = state->poll_response;

	status = dcerpc_frstrans_AsyncPoll_recv(subreq, response, &result);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		/* [MS-FRS2] 3.3.4.5 On error calling, try again after a time
		 * out interval */
		state->conn->state = CONNECTION_STATE_CONNECTED;
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		/* [MS-FRS2] 3.3.4.5 On error returned, transition to
		 * disconnected state to call EstablishConnection again */
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		tevent_req_nterror(req, werror_to_ntstatus(result));
		return;
	}

	/* [MS-FRS2] 3.3.4.5 On sucess, register another AsyncPoll callback
	 * for this connection */
	state->poll_response = talloc_zero(state,
			struct frstrans_AsyncResponseContext);
	if (tevent_req_nomem(state->poll_response, req)) {
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		return;
	}

	old_timeout = dcerpc_binding_handle_set_timeout(
			state->pipe->binding_handle, UINT32_MAX);

	subreq = dcerpc_frstrans_AsyncPoll_send(state,
			state->service->task->event_ctx,
			state->pipe->binding_handle,
			state->conn->guid,
			state->poll_response);

	dcerpc_binding_handle_set_timeout(
			state->pipe->binding_handle, old_timeout);

	if (tevent_req_nomem(subreq, req)) {
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_connection_asyncpoll_done,
				req);
}

static void dfsrsrv_connection_done(struct tevent_req *req)
{
	struct dfsrsrv_connection *conn;
	struct GUID_txt_buf txtguid;

	conn = tevent_req_callback_data(req, struct dfsrsrv_connection);
	TALLOC_FREE(req);

	DBG_WARNING("DFS-R Connection {%s} to '%s' terminated\n",
		    GUID_buf_string(&conn->guid, &txtguid),
		    dcerpc_binding_get_string_option(conn->binding, "host"));

	conn->state = CONNECTION_STATE_DISCONNECTED;
	conn->req = NULL;
}

static NTSTATUS check_connection(struct dfsrsrv_service *service,
				 struct dfsrsrv_connection *conn)
{
	struct GUID_txt_buf txtguid1, txtguid2;

	if (!conn->enabled) {
		DBG_INFO("Connection {%s} on replication group {%s} disabled\n",
			 GUID_buf_string(&conn->guid, &txtguid1),
			 GUID_buf_string(&conn->group->guid, &txtguid2));

		return NT_STATUS_OK;
	}

	if (conn->state == CONNECTION_STATE_DISCONNECTED) {
		conn->req = dfsrsrv_establish_connection_send(conn, service,
							      conn);
		if (conn->req == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(conn->req, dfsrsrv_connection_done,
					conn);
	}

	return NT_STATUS_OK;
}

NTSTATUS dfsrsrv_run_subscriptions(struct dfsrsrv_service *service)
{
	struct dfsrsrv_replication_group *group;
	struct dfsrsrv_connection *conn;

	DBG_DEBUG("Running subscriptions\n");

	for (group = service->subscriptions; group; group = group->next) {
		for (conn = group->connections; conn; conn = conn->next) {
			NTSTATUS status;

			status = check_connection(service, conn);
			if (!NT_STATUS_IS_OK(status)) {
				struct GUID_txt_buf txtguid1, txtguid2;
				DBG_ERR("Failed to run replication group "
					"{%s} connection {%s}: %s\n",
					GUID_buf_string(&group->guid,
							&txtguid1),
					GUID_buf_string(&conn->guid,
							&txtguid2),
					nt_errstr(status));
				continue;
			}
		}
	}

	return NT_STATUS_OK;
}
