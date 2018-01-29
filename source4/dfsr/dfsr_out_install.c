/*
   Unix SMB/CIFS mplementation.

   DFS Replication service

   Copyright (C) Samuel Cabrero <scabrero@suse.de> 2018

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
#include "lib/messaging/messaging.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_frsblobs.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

struct dfsrsrv_install_state {
	struct tevent_context *ev_ctx;
	struct imessaging_context *imsg_ctx;
	NTSTATUS result;
};

struct dfsrsrv_meet_notify_context {
	struct tevent_req *req;
};

struct tevent_req *dfsrsrv_install_send(TALLOC_CTX *mem_ctx,
		struct tevent_context *ev_ctx,
		struct imessaging_context *imsg_ctx,
		struct dfsrsrv_meet_notify_context *notify_ctx,
		const char *staged_path,
		const char *install_path,
		const char *root_path,
		struct frstrans_Update *update)
{
	struct dfsrsrv_install_state *state;
	struct server_id *server_ids;
	uint32_t num_server_ids = 0;
	DATA_BLOB b = {};
	struct dfsr_meet_install_update request;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	struct GUID_txt_buf txtguid1;

	DEBUG(6, ("dfsrsrv: Sending update {%s}-%lu (%s) to meet for "
		  "installation\n",
		  GUID_buf_string(&update->gsvn_db_guid, &txtguid1),
		  update->gsvn_version, update->name));

	notify_ctx->req = tevent_req_create(mem_ctx, &state,
			struct dfsrsrv_install_state);
	if (notify_ctx->req == NULL) {
		return NULL;
	}

	state->ev_ctx = ev_ctx;
	state->imsg_ctx = imsg_ctx;

	request.staged_file = staged_path != NULL ? staged_path : "";
	request.installing_dir = install_path;
	request.root_dir = root_path;
	request.update = update;

	ndr_err = ndr_push_struct_blob(&b, state, &request,
		(ndr_push_flags_fn_t)ndr_push_dfsr_meet_install_update);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("dfsrsrv: Failed ndr push\n"));
		tevent_req_nterror(notify_ctx->req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(notify_ctx->req, ev_ctx);
	}

	status = irpc_servers_byname(imsg_ctx, state, "dfsr-meet",
			&num_server_ids, &server_ids);
	if (tevent_req_nterror(notify_ctx->req, status)) {
		return tevent_req_post(notify_ctx->req, ev_ctx);
	}
	if (num_server_ids < 1) {
		DEBUG(0, ("dfsrsrv: Failed to find DFS-R Meet irpc server\n"));
		tevent_req_nterror(notify_ctx->req,
				NT_STATUS_SERVER_UNAVAILABLE);
		return tevent_req_post(notify_ctx->req, ev_ctx);
	}

	status = imessaging_send(state->imsg_ctx, server_ids[0],
			MSG_DFSR_MEET_INSTALL_UPDATE, &b);
	if (tevent_req_nterror(notify_ctx->req, status)) {
		DEBUG(0, ("dfsrsrv: Failed to send irpc message: %s\n",
			  nt_errstr(status)));
		return tevent_req_post(notify_ctx->req, ev_ctx);
	}

	return notify_ctx->req;
}

NTSTATUS dfsrsrv_install_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);

	return NT_STATUS_OK;
}

static void dfsrsrv_meet_notify_handler(struct imessaging_context *msg,
					void *private_data,
					uint32_t msg_type,
					struct server_id pid,
					DATA_BLOB *blob)
{
	struct dfsrsrv_meet_notify_context *notify_ctx;
	struct dfsr_meet_update_installed response;
	enum ndr_err_code ndr_err;
	struct tevent_req *req;

	notify_ctx = talloc_get_type(private_data,
			struct dfsrsrv_meet_notify_context);
	if (notify_ctx == NULL) {
		DEBUG(0, ("dfsrsrv: Error getting notify context.\n"));
		return;
	}

	if (notify_ctx->req == NULL) {
		DEBUG(0, ("dfsrsrv: Error getting notify request.\n"));
		return;
	}

	ndr_err = ndr_pull_struct_blob(blob, notify_ctx, &response,
		(ndr_pull_flags_fn_t)ndr_pull_dfsr_meet_update_installed);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("dfsrsrv: Failed ndr pull\n"));
	} else if (tevent_req_nterror(notify_ctx->req, response.result)) {
		notify_ctx->req = NULL;
		return;
	}

	req = notify_ctx->req;
	notify_ctx->req = NULL;
	tevent_req_done(req);
}

struct dfsrsrv_meet_notify_context *dfsrsrv_meet_notify_init(
		TALLOC_CTX *mem_ctx,
		struct imessaging_context *imsg_ctx)
{
	NTSTATUS status;
	struct dfsrsrv_meet_notify_context *notify_ctx;

	notify_ctx = talloc_zero(mem_ctx, struct dfsrsrv_meet_notify_context);
	if (notify_ctx == NULL) {
		DEBUG(0, ("dfsrsrv: No memory\n"));
		return NULL;
	}

	status = imessaging_register(imsg_ctx, notify_ctx,
			MSG_DFSR_MEET_UPDATE_INSTALLED,
			dfsrsrv_meet_notify_handler);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dfssrv: Failed to register notify context: %s\n",
			  nt_errstr(status)));
		return NULL;
	}

	return notify_ctx;
}
