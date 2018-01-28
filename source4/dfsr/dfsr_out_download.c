/*
   Unix SMB/CIFS mplementation.

   DFS Replication service

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
#include "lib/events/events.h"
#include "util/tevent_ntstatus.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

struct dfsrsrv_download_state {
	struct tevent_context *ev;
	struct dcerpc_pipe *pipe;
	struct policy_handle server_context;
	uint8_t *data_buffer;
	uint32_t buffer_size;
	uint32_t size_read;
	uint32_t is_end_of_file;

	char *staging_file;
};

static void dfsrsrv_download_update_next(struct tevent_req *subreq);
struct tevent_req *dfsrsrv_download_update_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct dcerpc_pipe *pipe,
					struct policy_handle server_context,
					char *staging_file)
{
	struct tevent_req *req, *subreq;
	struct dfsrsrv_download_state *state;

	req = tevent_req_create(mem_ctx, &state, struct dfsrsrv_download_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->pipe = pipe;
	state->server_context = server_context;
	state->size_read = 0;
	state->is_end_of_file = 0;
	state->buffer_size = 262144;
	state->data_buffer = talloc_zero_array(state, uint8_t,
			state->buffer_size);
	state->staging_file = staging_file;

	subreq = dcerpc_frstrans_RawGetFileData_send(state,
			state->ev,
			state->pipe->binding_handle,
			&state->server_context,
			state->data_buffer,
			state->buffer_size,
			&state->size_read,
			&state->is_end_of_file);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dfsrsrv_download_update_next, req);

	return req;
}

static void dfsrsrv_download_update_close(struct tevent_req *subreq);
static void dfsrsrv_download_update_next(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_download_state *state;
	NTSTATUS status;
	WERROR result;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_download_state);

	status = dcerpc_frstrans_RawGetFileData_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to download update: %s\n", nt_errstr(status));
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		DBG_ERR("Failed to download update: %s\n", win_errstr(result));
		tevent_req_nterror(req, werror_to_ntstatus(result));
		return;
	}

	if (state->size_read > 0) {
		/* Write to stage file */
		status = dfsrsrv_staging_write_buffer(state,
				state->staging_file,
				state->data_buffer,
				state->size_read,
				true);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	/* [MS-FRS2] 3.3.4.9 In order to receive the full file contents, the
	 * client MUST create another call to the RawGetFileData method if the
	 * output value of the isEndOfFile parameter is 0. If the output value
	 * of isEndOfFile is 1, the client MUST call the RdcClose method on the
	 * context handle associated with the file download.*/
	if (state->is_end_of_file == 0) {
		subreq = dcerpc_frstrans_RawGetFileData_send(state,
				state->ev,
				state->pipe->binding_handle,
				&state->server_context,
				state->data_buffer,
				state->buffer_size,
				&state->size_read,
				&state->is_end_of_file);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, dfsrsrv_download_update_next,
					req);
		return;
	}

	subreq = dcerpc_frstrans_RdcClose_send(state,
			state->ev,
			state->pipe->binding_handle,
			&state->server_context);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_download_update_close, req);
}

static void dfsrsrv_download_update_close(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_download_state *state;
	NTSTATUS status;
	WERROR result;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_download_state);

	status = dcerpc_frstrans_RdcClose_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to close update download: %s\n",
			nt_errstr(status));
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		DBG_ERR("Failed to close update download: %s\n",
			win_errstr(result));
		tevent_req_nterror(req, werror_to_ntstatus(result));
		return;
	}

	tevent_req_done(req);
}

NTSTATUS dfsrsrv_download_update_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);

	return NT_STATUS_OK;
}
