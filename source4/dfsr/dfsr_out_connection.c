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
#include "util/dlinklist.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

struct dfsrsrv_conn_state {
	struct dfsrsrv_service *service;
	struct dfsrsrv_connection *conn;
	struct dcerpc_pipe *pipe;

	enum frstrans_ProtocolVersion version;
	uint32_t flags;
	struct frstrans_AsyncResponseContext *poll_response;

	uint32_t next_sequence_number;
};

struct dfsrsrv_session_state {
	struct dfsrsrv_session *session;
	struct dfsrsrv_conn_state *conn_ctx;

	/* RequestVersionVector */
	uint32_t sequence_number;
	enum frstrans_VersionRequestType request_type;
	enum frstrans_VersionChangeType change_type;

	/* [MS-FRS2] 3.2.4.1.5 The vvGeneration parameter is
	 * used to control when an AsyncPoll request can be completed
	 * by the server. The AsyncPoll request must be completed by
	 * the server when its version vector time stamp supersedes
	 * the time stamp passed in as the vvGeneration parameter of
	 * the version vector request. */
	uint64_t vv_generation;

	/* Computed delta between the received version chain vector and the
	 * already known version chain vector */
	struct frstrans_VersionVector *vv_delta;
	uint32_t vv_delta_count;
};

struct dfsrsrv_request_updates_state {
	struct dfsrsrv_service *service;
	struct dcerpc_pipe *pipe;
	struct dfsrsrv_connection *conn;
	struct dfsrsrv_content_set *set;

	uint32_t max_updates;
	uint32_t num_updates;
	uint32_t hash_requested;
	enum frstrans_UpdateRequestType update_request_type;
	struct frstrans_VersionVector *request_vv_delta;
	uint32_t request_vv_delta_count;

	enum frstrans_UpdateStatus update_status;
	struct frstrans_Update *updates;
	struct GUID gvsn_db_guid;
	uint64_t gvsn_version;

	/* A queue for the updates */
	struct dfsrsrv_vv_queue *queue;
};

static void dfsrsrv_session_request_updates_next(struct tevent_req *subreq);
static struct tevent_req *dfsrsrv_session_request_updates_send(
		TALLOC_CTX *mem_ctx,
		struct dfsrsrv_service *service,
		struct dcerpc_pipe *pipe,
		struct dfsrsrv_connection *conn,
		struct dfsrsrv_content_set *set,
		struct frstrans_VersionVector *vv,
		uint32_t vv_count)
{
	struct tevent_req *req, *subreq;
	struct dfsrsrv_request_updates_state *state;
	NTSTATUS status;
	struct GUID_txt_buf txtguid1, txtguid2;
	int i;

	req = tevent_req_create(mem_ctx, &state,
			struct dfsrsrv_request_updates_state);
	if (req == NULL) {
		return NULL;
	}

	state->service = service;
	state->pipe = pipe;
	state->conn = conn;
	state->set = set;
	state->num_updates = 0;
	state->max_updates = 256;
	state->hash_requested = 0;
	state->update_request_type = FRSTRANS_UPDATE_REQUEST_ALL;

	/* Copy the vectors as they will be freed if all updates do not fit
	 * in the max_updates */
	status = dfsrsrv_vv_copy(state, vv, &state->request_vv_delta,
				 vv_count);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, service->task->event_ctx);
	}
	state->request_vv_delta_count = vv_count;

	/* The queue for the updates pertaining to this version vector */
	state->queue = talloc_zero(service, struct dfsrsrv_vv_queue);
	if (tevent_req_nomem(state->queue, req)) {
		return tevent_req_post(req, service->task->event_ctx);
	}
	state->queue->set = set;
	state->queue->conn = conn;
	state->queue->pipe = pipe;

	state->updates = talloc_zero_array(state,
					   struct frstrans_Update,
					   state->max_updates);
	if (tevent_req_nomem(state->updates, req)) {
		return tevent_req_post(req, service->task->event_ctx);
	}

	/* Save the original version chain vector as it will be needed to
	   go through the request updates state machine and to update the
	   persisted known version chain vector in database when all updates
	   pertaining to this chain are processed */
	status = dfsrsrv_vv_copy(state->queue, vv, &state->queue->vv,
				 vv_count);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, service->task->event_ctx);
	}
	state->queue->vv_count = vv_count;

	DBG_INFO("Requesting updates [type %d] for content set "
		 "{%s} on connection {%s}:\n", state->update_request_type,
		 GUID_buf_string(&state->set->guid, &txtguid1),
		 GUID_buf_string(&state->conn->guid, &txtguid2));
	for (i = 0; i < state->request_vv_delta_count; i++) {
		DBG_INFO("         {%s} [%lu - %lu]\n",
			 GUID_buf_string(&state->request_vv_delta[i].db_guid,
					 &txtguid1),
			 state->request_vv_delta[i].low,
			 state->request_vv_delta[i].high);
	}

	subreq = dcerpc_frstrans_RequestUpdates_send(
					state,
					state->service->task->event_ctx,
					state->pipe->binding_handle,
					state->conn->guid,
					state->set->guid,
					state->max_updates,
					state->hash_requested,
					state->update_request_type,
					state->request_vv_delta_count,
					state->request_vv_delta,
					state->updates,
					&state->num_updates,
					&state->update_status,
					&state->gvsn_db_guid,
					&state->gvsn_version);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, service->task->event_ctx);
	}
	tevent_req_set_callback(subreq, dfsrsrv_session_request_updates_next,
				req);

	return req;
}

static void dfsrsrv_session_request_updates_next(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_request_updates_state *state;
	struct frstrans_VersionVector *new_vv;
	uint32_t new_vv_count;
	NTSTATUS status;
	WERROR result;
	int i;
	struct GUID_txt_buf txtguid1, txtguid2, txtguid3;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_request_updates_state);
	status = dcerpc_frstrans_RequestUpdates_recv(subreq, state, &result);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to request updates: %s\n", nt_errstr(status));
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		DBG_ERR("Failed to request updates: %s\n", win_errstr(result));
		tevent_req_nterror(req, werror_to_ntstatus(result));
		return;
	}

	/* [MS-FRS2] 3.3.4.6 Upon completion, the server has returned at
	 * least some of the requested updates. The client must queue received
	 * updates and process them as specified in section 3.3.4.6.2 */
	for (i = 0; i < state->num_updates; i++) {
		struct dfsrsrv_update *entry;

		entry = talloc_zero(state->queue, struct dfsrsrv_update);
		if (tevent_req_nomem(entry, req)) {
			return;
		}

		entry->update = talloc_memdup(entry, &state->updates[i],
					      sizeof(struct frstrans_Update));
		entry->update->name = talloc_strdup(entry->update,
						    state->updates[i].name);
		DLIST_ADD_END(state->queue->pending_updates, entry);

		DBG_INFO("Queued update {%s}-v%lu (%s) "
			 "(Content set {%s}, Connection {%s})\n",
			 GUID_buf_string(&entry->update->gsvn_db_guid,
					 &txtguid1),
			 entry->update->gsvn_version, entry->update->name,
			 GUID_buf_string(&state->set->guid, &txtguid2),
			 GUID_buf_string(&state->conn->guid, &txtguid3));
	}
	TALLOC_FREE(state->updates);

	/* [MS-FRS2] 3.3.4.6.1 Requesting updates state machine */
	switch (state->update_request_type) {
	case FRSTRANS_UPDATE_REQUEST_ALL:
	{
		if (state->update_status == FRSTRANS_UPDATE_STATUS_DONE) {
			goto done;
		} else if (state->update_status == FRSTRANS_UPDATE_STATUS_MORE) {
			state->update_request_type = FRSTRANS_UPDATE_REQUEST_TOMBSTONES;
			goto filter_and_request_more;
		}
		break;
	}
	case FRSTRANS_UPDATE_REQUEST_TOMBSTONES:
	{
		if (state->update_status == FRSTRANS_UPDATE_STATUS_DONE) {
			state->update_request_type = FRSTRANS_UPDATE_REQUEST_LIVE;
			TALLOC_FREE(state->request_vv_delta);

			/* Restore the original VV delta saved in the queue */
			status = dfsrsrv_vv_copy(state, state->queue->vv,
					&state->request_vv_delta,
					state->queue->vv_count);
			if (tevent_req_nterror(req, status)) {
				return;
			}
			state->request_vv_delta_count = state->queue->vv_count;
			goto request_more;
		} else if (state->update_status == FRSTRANS_UPDATE_STATUS_MORE) {
			/* The request type remains UPDATE_REQUEST_TOMSTONES */
			goto filter_and_request_more;
		}
		break;
	}
	case FRSTRANS_UPDATE_REQUEST_LIVE:
	{
		if (state->update_status == FRSTRANS_UPDATE_STATUS_DONE) {
			goto done;
		} else if (state->update_status == FRSTRANS_UPDATE_STATUS_MORE) {
			/* The request type remains UPDATE_REQUEST_LIVE */
			goto filter_and_request_more;
		}
	}
	}

filter_and_request_more:
	/*
	 * Remove all entries from the version chain vector that
	 * are lexicographically less than or equal to
	 * (gvsnDbGuid, gvsnVersion)
	 */
	status = dfsrsrv_lexicofilter_vector(state,
			state->gvsn_db_guid, state->gvsn_version,
			state->request_vv_delta,
			state->request_vv_delta_count,
			&new_vv, &new_vv_count);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to filter version vectors: %s\n",
			nt_errstr(status));
		return;
	}
	TALLOC_FREE(state->request_vv_delta);
	state->request_vv_delta = new_vv;
	state->request_vv_delta_count = new_vv_count;

request_more:
	/* Request more */
	state->updates = talloc_zero_array(state,
					   struct frstrans_Update,
					   state->max_updates);
	if (tevent_req_nomem(state->updates, req)) {
		return;
	}

	DBG_INFO("Requesting updates [type %d] for content set {%s} on "
		 "connection {%s}:\n", state->update_request_type,
		 GUID_buf_string(&state->set->guid, &txtguid1),
		 GUID_buf_string(&state->conn->guid, &txtguid2));
	for (i = 0; i < state->request_vv_delta_count; i++) {
		DBG_INFO("         {%s} [%lu - %lu]\n",
			 GUID_buf_string(&state->request_vv_delta[i].db_guid,
					 &txtguid1),
			 state->request_vv_delta[i].low,
			 state->request_vv_delta[i].high);
	}

	subreq = dcerpc_frstrans_RequestUpdates_send(
			state,
			state->service->task->event_ctx,
			state->pipe->binding_handle,
			state->conn->guid,
			state->set->guid,
			state->max_updates,
			state->hash_requested,
			state->update_request_type,
			state->request_vv_delta_count,
			state->request_vv_delta,
			state->updates,
			&state->num_updates,
			&state->update_status,
			&state->gvsn_db_guid,
			&state->gvsn_version);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_session_request_updates_next,
				req);
	return;

done:
	/* Update the runtime known version chain vector for the content set*/
	status = dfsrsrv_update_known_vv(state->set, state->queue->vv,
			state->queue->vv_count);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to update known version vectors: %s\n",
			nt_errstr(status));
		return;
	}

	/* Append to the version vectors queue */
	DLIST_ADD_END(state->service->process_queue.pending_vv, state->queue);
	DBG_INFO("Queued version chain vector (Content set {%s}, "
		 "Connection {%s}) for processing\n",
		 GUID_buf_string(&state->queue->set->guid, &txtguid1),
		 GUID_buf_string(&state->queue->conn->guid, &txtguid2));

	/* Schedule an immediate event to process received updates */
	tevent_schedule_immediate(state->service->pending.im,
				  state->service->task->event_ctx,
				  dfsrsrv_process_updates_handler_im,
				  state->service);

	/* [MS-FRS2] 3.3.4.6.1 All updates from the original
	 * version chain vector have been received. */
	tevent_req_done(req);
}

static NTSTATUS dfsrsrv_session_request_updates_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static void dfsrsrv_establish_session_done(struct tevent_req *subreq);
static struct tevent_req *dfsrsrv_establish_session_send(
		TALLOC_CTX *mem_ctx,
		struct dfsrsrv_conn_state *conn_ctx,
		struct dfsrsrv_session *session)
{
	struct tevent_req *req, *subreq;
	struct dfsrsrv_session_state *state;
	struct GUID_txt_buf txtguid1, txtguid2;

	req = tevent_req_create(mem_ctx, &state, struct dfsrsrv_session_state);
	if (req == NULL) {
		return NULL;
	}

	state->session = session;
	state->conn_ctx = conn_ctx;

	DBG_INFO("Establish DFS-R session for content set {%s} over DFS-R "
		 "connection {%s}\n",
		 GUID_buf_string(&session->set->guid, &txtguid1),
		 GUID_buf_string(&session->conn->guid, &txtguid2));

	subreq = dcerpc_frstrans_EstablishSession_send(
					state,
					conn_ctx->service->task->event_ctx,
					conn_ctx->pipe->binding_handle,
					session->conn->guid,
					session->set->guid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req,
				       conn_ctx->service->task->event_ctx);
	}
	tevent_req_set_callback(subreq,	dfsrsrv_establish_session_done, req);
	return req;
}

static void dfsrsrv_session_request_vv_done(struct tevent_req *subreq);
static void dfsrsrv_establish_session_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_session_state *state;
	struct dfsrsrv_session *session;
	struct GUID_txt_buf txtguid1, txtguid2;
	NTSTATUS status;
	WERROR result;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_session_state);
	session = state->session;

	status = dcerpc_frstrans_EstablishSession_recv(subreq, state, &result);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to establish DFS-R session for content set "
			"{%s} on connection {%s}: %s\n",
			GUID_buf_string(&session->set->guid, &txtguid1),
			GUID_buf_string(&session->conn->guid, &txtguid2),
			nt_errstr(status));
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		DBG_ERR("Failed to establish DFS-R session for content set "
			"{%s} on connection {%s}: %s\n",
			GUID_buf_string(&session->set->guid, &txtguid1),
			GUID_buf_string(&session->conn->guid, &txtguid2),
			win_errstr(result));

		/* [MS-FRS2] 3.3.4.3 Error handling */
		if (W_ERROR_EQUAL(result, WERR_FRS_ERROR_CONNECTION_INVALID)) {
			session->conn->state = CONNECTION_STATE_DISCONNECTED;
			tevent_req_nterror(req, werror_to_ntstatus(result));
			return;
		}

		if (W_ERROR_EQUAL(result,
				  WERR_FRS_ERROR_CONTENTSET_READ_ONLY)) {
			session->set->read_only = true;
			tevent_req_nterror(req, werror_to_ntstatus(result));
			return;
		}

		if (W_ERROR_GT(result,
			WERR_RPC_S_INVALID_STRING_BINDING) &&
			W_ERROR_LT(result, WERR_RPC_S_GRP_ELT_NOT_REMOVED)) {
			session->conn->state = CONNECTION_STATE_DISCONNECTED;
			tevent_req_nterror(req, werror_to_ntstatus(result));
			return;
		}

		/* Remain on polling state and try again later */
		session->state = SESSION_STATE_RESTART;
		return;
	}

	/* [MS-FRS2] 3.3.4.3 On success transition to InSession
	 * state and request the version chain vector */
	session->state = SESSION_STATE_IN_SESSION;

	/* Assing the request a unique sequence number to identify the
	 * response when AsyncPoll response arrives */
	state->sequence_number = state->conn_ctx->next_sequence_number++;
	state->request_type = FRSTRANS_VERSION_REQUEST_NORNAL_SYNC;
	state->change_type = FRSTRANS_VERSION_CHANGE_NOTIFY;

	DBG_INFO("Registering version chain vector generation %lu "
		 "change notification for content set {%s} "
		 "on connection {%s}\n", state->vv_generation,
		 GUID_buf_string(&session->set->guid, &txtguid1),
		 GUID_buf_string(&session->conn->guid, &txtguid2));
	subreq = dcerpc_frstrans_RequestVersionVector_send(
				state,
				state->conn_ctx->service->task->event_ctx,
				state->conn_ctx->pipe->binding_handle,
				state->sequence_number,
				session->conn->guid,
				session->set->guid,
				state->request_type,
				state->change_type,
				state->vv_generation);
	if (tevent_req_nomem(subreq, req)) {
		session->state = SESSION_STATE_RESTART;
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_session_request_vv_done, req);

	session->state = SESSION_STATE_REQUESTING_VV;
}

static void dfsrsrv_session_request_vv_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_session_state *state;
	struct dfsrsrv_session *session;
	struct GUID_txt_buf txtguid1, txtguid2;
	NTSTATUS status;
	WERROR result;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_session_state);
	session = state->session;

	status = dcerpc_frstrans_RequestVersionVector_recv(subreq, state,
							   &result);
	TALLOC_FREE(subreq);

	/* [MS-FRS2] 3.3.4.4 Error handling */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to request version vectors for content set "
			"{%s} on connection {%s}: %s\n",
			GUID_buf_string(&session->set->guid, &txtguid1),
			GUID_buf_string(&session->conn->guid, &txtguid2),
			nt_errstr(status));
		session->conn->state = CONNECTION_STATE_DISCONNECTED;
		tevent_req_nterror(req, status);
		return;
	}
	if (!W_ERROR_IS_OK(result)) {
		DBG_ERR("Failed to request version vectors for content set "
			"{%s} on connection {%s}: %s\n",
			GUID_buf_string(&session->set->guid, &txtguid1),
			GUID_buf_string(&session->conn->guid, &txtguid2),
			win_errstr(result));
		session->conn->state = CONNECTION_STATE_DISCONNECTED;
		tevent_req_nterror(req, werror_to_ntstatus(result));
		return;
	}

	/* Then wait for AsyncPoll completion */
}

static void dfsrsrv_session_done(struct tevent_req *req)
{
	struct dfsrsrv_session *session;
	struct GUID_txt_buf txtguid1, txtguid2;

	session = tevent_req_callback_data(req, struct dfsrsrv_session);
	TALLOC_FREE(req);

	DBG_WARNING("Content set {%s} session on connection {%s} terminated\n",
		    GUID_buf_string(&session->set->guid, &txtguid1),
		    GUID_buf_string(&session->conn->guid, &txtguid2));

	session->state = SESSION_STATE_RESTART;
}

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
	struct dfsrsrv_content_set *set;
	struct dfsrsrv_session *session;

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

	for (set = state->conn->group->sets; set; set = set->next) {
		if (set->enabled && !set->read_only) {
			session = talloc_zero(state->conn,
					      struct dfsrsrv_session);
			if (tevent_req_nomem(session, req)) {
				state->conn->state =
					CONNECTION_STATE_DISCONNECTED;
				return;
			}

			session->state = SESSION_STATE_RESTART;
			session->conn = state->conn;
			session->set = set;
			DLIST_ADD_END(state->conn->sessions, session);

			session->req = dfsrsrv_establish_session_send(session,
					state, session);
			if (tevent_req_nomem(subreq, req)) {
				state->conn->state =
					CONNECTION_STATE_DISCONNECTED;
				return;
			}
			tevent_req_set_callback(session->req,
					dfsrsrv_session_done, session);
		}
	}
}

static void dfsrsrv_session_handle_requesting_vv(
		struct dfsrsrv_conn_state *conn_state,
		struct dfsrsrv_session_state *session_state);
static void dfsrsrv_session_handle_poll_again(
		struct dfsrsrv_conn_state *conn_state,
		struct dfsrsrv_session_state *session_state,
		struct frstrans_AsyncResponseContext *response);
static void dfsrsrv_connection_asyncpoll_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_conn_state *state;
	NTSTATUS status;
	WERROR result;
	uint32_t old_timeout;
	struct frstrans_AsyncResponseContext *response;
	struct dfsrsrv_session *session = NULL;
	struct dfsrsrv_session_state *session_state = NULL;

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
	 * for this connection. Save the current response for later process */
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

	/* Locate the session this response is for */
	for (session = state->conn->sessions; session;
			session = session->next) {
		session_state = tevent_req_data(session->req,
				struct dfsrsrv_session_state);
		if (response->sequence_number ==
				session_state->sequence_number) {
			break;
		}
	}

	if (session == NULL || session_state == NULL) {
		DBG_ERR("Got an AsyncPoll response (seq num %d) but no "
			"matching session found\n",
			response->sequence_number);
		TALLOC_FREE(response);
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		return;
	}

	if (session_state->request_type !=
			FRSTRANS_VERSION_REQUEST_NORNAL_SYNC) {
		DBG_WARNING("Request type %d not supported\n",
			    session_state->request_type);
		TALLOC_FREE(response);
		state->conn->state = CONNECTION_STATE_DISCONNECTED;
		return;
	}

	/* [MS-FRS2] 3.3.4.5 Subsequent process depends on the type of
	 * version vector request that has triggered this AsyncPoll
	 * completion */

	if (session->state == SESSION_STATE_REQUESTING_VV) {
		dfsrsrv_session_handle_requesting_vv(state, session_state);
	} else if (session->state == SESSION_STATE_POLL_AGAIN) {
		dfsrsrv_session_handle_poll_again(state, session_state,
						  response);
	}

	TALLOC_FREE(response);

	/* [MS-FRS2] 3.3.4.5 If the session state is neither REQUESTING_VV
	 * nor POLL_AGAIN, ignore this AsyncPoll reply */
}

static void dfsrsrv_session_handle_requesting_vv(
		struct dfsrsrv_conn_state *conn_state,
		struct dfsrsrv_session_state *session_state)
{
	struct tevent_req *subreq;
	struct GUID_txt_buf txtguid1, txtguid2;

	DBG_INFO("Version chain vector changed, generation %lu available for "
		 "content set {%s} on connection {%s}\n",
		 session_state->vv_generation,
		 GUID_buf_string(&session_state->session->set->guid,
				 &txtguid1),
		 GUID_buf_string(&session_state->session->conn->guid,
				 &txtguid2));

	/* [MS-FRS2] 3.3.4.5 The server version vector has changed and
	 * has versions not known to us. Transition to poll again
	 * state and request those versions */
	session_state->session->state = SESSION_STATE_POLL_AGAIN;
	session_state->request_type = FRSTRANS_VERSION_REQUEST_NORNAL_SYNC;
	session_state->change_type = FRSTRANS_VERSION_CHANGE_ALL;

	/* Assign the next request a new sequence number to identify
	 * the AsyncPoll response when it arrives, notifying us a new
	 * version vector is available */
	session_state->sequence_number = conn_state->next_sequence_number++;

	DBG_INFO("Requesting version chain vector generation %lu for content "
		 "set {%s} on connection {%s}\n",
		 session_state->vv_generation,
		 GUID_buf_string(&session_state->session->set->guid,
				 &txtguid1),
		 GUID_buf_string(&session_state->session->conn->guid,
				 &txtguid2));
	subreq = dcerpc_frstrans_RequestVersionVector_send(
				conn_state,
				conn_state->service->task->event_ctx,
				conn_state->pipe->binding_handle,
				session_state->sequence_number,
				session_state->session->conn->guid,
				session_state->session->set->guid,
				session_state->request_type,
				session_state->change_type,
				session_state->vv_generation);
	if (tevent_req_nomem(subreq, session_state->session->req)) {
		session_state->session->state = SESSION_STATE_RESTART;
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_session_request_vv_done,
				session_state->session->req);

	session_state->session->state = SESSION_STATE_POLL_AGAIN;
}

static void dfsrsrv_session_request_updates_done(struct tevent_req *subreq);
static void dfsrsrv_session_handle_poll_again(
		struct dfsrsrv_conn_state *conn_state,
		struct dfsrsrv_session_state *session_state,
		struct frstrans_AsyncResponseContext *response)
{
	struct tevent_req *subreq;
	struct GUID_txt_buf txtguid1, txtguid2;
	NTSTATUS status;
	int i;

	/* [MS-FRS2] 3.3.4.5 The server has sent its version chain vector */
	DBG_INFO("Received version chain vector generation "
		 "%lu for content set {%s} on connection {%s}:\n",
		 session_state->vv_generation,
		 GUID_buf_string(&session_state->session->set->guid,
				 &txtguid1),
		 GUID_buf_string(&session_state->session->conn->guid,
				 &txtguid2));
	for (i = 0; i < response->response.version_vector_count; i++) {
		DBG_INFO("         {%s} [%lu - %lu]\n",
			 GUID_buf_string(
				 &response->response.version_vector[i].db_guid,
				 &txtguid1),
			 response->response.version_vector[i].low,
			 response->response.version_vector[i].high);
	}

	/* Calculate the delta between what we know and the server
	 * has sent. Store in the session state */
	TALLOC_FREE(session_state->vv_delta);
	session_state->vv_delta_count = 0;

	status = dfsrsrv_calculate_delta_vectors(session_state,
		response->response.version_vector,
		response->response.version_vector_count,
		&session_state->vv_delta,
		&session_state->vv_delta_count,
		session_state->session->set->known_vv,
		session_state->session->set->known_vv_count);
	if (tevent_req_nterror(session_state->session->req, status)) {
		DBG_ERR("Failed to compute version vector delta for "
			"content set {%s} on connection {%s}: %s\n",
			GUID_buf_string(&session_state->session->set->guid,
					&txtguid1),
			GUID_buf_string(&session_state->session->conn->guid,
					&txtguid2),
			nt_errstr(status));
		session_state->session->state = SESSION_STATE_RESTART;
	}

	DBG_INFO("Computed version vector delta for content set {%s}"
		 " on connection {%s}:\n",
		 GUID_buf_string(&session_state->session->set->guid,
				 &txtguid1),
		 GUID_buf_string(&session_state->session->conn->guid,
				 &txtguid2));
	for (i = 0; i < session_state->vv_delta_count; i++) {
		DBG_INFO("         {%s} [%lu - %lu]\n",
			 GUID_buf_string(&session_state->vv_delta[i].db_guid,
					 &txtguid1),
			 session_state->vv_delta[i].low,
			 session_state->vv_delta[i].high);
	}

	/* Save received generation as the poll response is shared
	 * among sessions. Will be used later to register the change
	 * notification */
	session_state->vv_generation = response->response.vv_generation;

	/* Assign the next request a new sequence number to identify
	 * the AsyncPoll response when it arrives, notifying us a new
	 * version vector is available */
	session_state->sequence_number = conn_state->next_sequence_number++;

	/* If already know everything (empty delta), register a new
	 * change notification and wait */
	if (session_state->vv_delta_count == 0) {
		session_state->request_type =
				FRSTRANS_VERSION_REQUEST_NORNAL_SYNC;
		session_state->change_type = FRSTRANS_VERSION_CHANGE_NOTIFY;

		DBG_INFO("Registering version chain vector generation %lu "
			 "change notification for content set {%s} on "
			 "connection {%s}\n",
			 session_state->vv_generation,
			 GUID_buf_string(&session_state->session->set->guid,
					 &txtguid1),
			 GUID_buf_string(&session_state->session->conn->guid,
					 &txtguid2));

		subreq = dcerpc_frstrans_RequestVersionVector_send(
			session_state,
			session_state->conn_ctx->service->task->event_ctx,
			session_state->conn_ctx->pipe->binding_handle,
			session_state->sequence_number,
			session_state->session->conn->guid,
			session_state->session->set->guid,
			session_state->request_type,
			session_state->change_type,
			session_state->vv_generation);
		if (tevent_req_nomem(subreq, session_state->session->req)) {
			session_state->session->state = SESSION_STATE_RESTART;
			return;
		}
		tevent_req_set_callback(subreq,
					dfsrsrv_session_request_vv_done,
					session_state->session->req);

		session_state->session->state = SESSION_STATE_REQUESTING_VV;
		return;
	}

	/* There VV delta contain updates not known to us. Enter in
	 * REQUESTING_UPDATES state and request the updates in the
	 * computed delta */
	subreq = dfsrsrv_session_request_updates_send(
			session_state,
			conn_state->service,
			conn_state->pipe,
			session_state->session->conn,
			session_state->session->set,
			session_state->vv_delta,
			session_state->vv_delta_count);
	if (tevent_req_nomem(subreq, session_state->session->req)) {
		session_state->session->state = SESSION_STATE_RESTART;
		tevent_req_done(session_state->session->req);
		return;
	}
	tevent_req_set_callback(subreq,
				dfsrsrv_session_request_updates_done,
				session_state->session->req);
	session_state->session->state = SESSION_STATE_REQUESTING_UPDATES;
}

static void dfsrsrv_session_request_updates_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_session_state *state;
	NTSTATUS status;
	struct GUID_txt_buf txtguid1, txtguid2;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_session_state);
	status = dfsrsrv_session_request_updates_recv(subreq);
	TALLOC_FREE(subreq);

	TALLOC_FREE(state->vv_delta);
	state->vv_delta_count = 0;

	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to request updates: %s\n", nt_errstr(status));
		state->session->state = SESSION_STATE_RESTART;
		return;
	}

	/* All updates from the requested version vector obtained. Request to
	 * be notified when a new version vector is available */
	state->request_type = FRSTRANS_VERSION_REQUEST_NORNAL_SYNC;
	state->change_type = FRSTRANS_VERSION_CHANGE_NOTIFY;

	/* Assign the next request a new sequence number to identify the
	 * AsyncPoll response when it arrives, notifying us a new version
	 * vector is available */
	state->sequence_number = state->conn_ctx->next_sequence_number++;

	DBG_INFO("dfsrsrv: Registering version chain vector "
		 "generation %lu change notification for content "
		 "set {%s} on connection {%s}\n",
		 state->vv_generation,
		 GUID_buf_string(&state->session->set->guid, &txtguid1),
		 GUID_buf_string(&state->session->conn->guid, &txtguid2));

	subreq = dcerpc_frstrans_RequestVersionVector_send(
				state,
				state->conn_ctx->service->task->event_ctx,
				state->conn_ctx->pipe->binding_handle,
				state->sequence_number,
				state->session->conn->guid,
				state->session->set->guid,
				state->request_type,
				state->change_type,
				state->vv_generation);
	if (tevent_req_nomem(subreq, req)) {
		state->session->state = SESSION_STATE_RESTART;
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_session_request_vv_done, req);

	state->session->state = SESSION_STATE_REQUESTING_VV;
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

static NTSTATUS check_session(struct dfsrsrv_connection *conn,
			  struct dfsrsrv_session *session)
{
	if (session->state == SESSION_STATE_RESTART) {
		struct dfsrsrv_conn_state *conn_cnx;
		conn_cnx = tevent_req_data(conn->req,
				struct dfsrsrv_conn_state);

		session->req = dfsrsrv_establish_session_send(session,
							      conn_cnx,
							      session);
		if (session->req == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(session->req, dfsrsrv_session_done,
					session);
	}

	return NT_STATUS_OK;
}

static NTSTATUS check_connection(struct dfsrsrv_service *service,
				 struct dfsrsrv_connection *conn)
{
	struct GUID_txt_buf txtguid1, txtguid2;
	struct dfsrsrv_session *session;
	NTSTATUS status;

	if (!conn->enabled) {
		DBG_INFO("Connection {%s} on replication group {%s} disabled\n",
			 GUID_buf_string(&conn->guid, &txtguid1),
			 GUID_buf_string(&conn->group->guid, &txtguid2));

		return NT_STATUS_OK;
	}

	if (conn->state == CONNECTION_STATE_DISCONNECTED) {
		/* Clear the session list */
		while ((session = conn->sessions) != NULL) {
			DLIST_REMOVE(conn->sessions, session);
			TALLOC_FREE(session);
		}

		conn->req = dfsrsrv_establish_connection_send(conn, service,
							      conn);
		if (conn->req == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(conn->req, dfsrsrv_connection_done,
					conn);
		return NT_STATUS_OK;
	}

	for (session = conn->sessions; session; session = session->next) {
		if (!session->set->enabled) {
			DBG_INFO("Content set {%s} on replication group {%s} "
				 "disabled\n",
				 GUID_buf_string(&session->set->guid,
						 &txtguid1),
				 GUID_buf_string(&session->set->group->guid,
						 &txtguid2));
			continue;
		}

		status = check_session(conn, session);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to run content set {%s} session on "
				"connection {%s}: %s\n",
				GUID_buf_string(&session->set->guid,
						&txtguid1),
				GUID_buf_string(&session->conn->guid,
						&txtguid2),
				nt_errstr(status));
		}
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
