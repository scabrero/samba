/*
   Unix SMB/CIFS mplementation.

   DFS Replication meet module

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
#include "dfsr_meet.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/param/param.h"
#include "source4/lib/messaging/messaging.h"
#include "source4/lib/messaging/irpc.h"
#include "gen_ndr/ndr_frsblobs.h"
#include "dfsr/dfsr_db.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR_MEET

struct dfsr_meet_state {
	struct imessaging_context *imsg_ctx;
	struct loadparm_context *lp_ctx;
	pid_t parent_pid;
	struct dfsr_db *db_ctx;
};

static NTSTATUS dfsr_meet_store(TALLOC_CTX *mem_ctx,
				struct dfsr_db *db_ctx,
				struct frstrans_Update *update)
{
	struct dfsr_db_record *record = NULL;
	struct GUID_txt_buf guid;
	NTSTATUS status;

	status = dfsr_db_fetch(db_ctx, mem_ctx, &update->uid_db_guid,
			update->uid_version, &record);
	if (NT_STATUS_EQUAL(NT_STATUS_NOT_FOUND, status)) {
		record = talloc_zero(mem_ctx, struct dfsr_db_record);
		if (record == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to fetch {%s}-v%lu record: %s\n",
			GUID_buf_string(&update->uid_db_guid, &guid),
			update->uid_version, nt_errstr(status));
		goto out;
	}

	record->update = update;
	record->meet_installed = 1;
	if (update->present == 0) {
		record->fid.devid = 0;
		record->fid.inode = 0;
		record->fid.extid = 0;
	}

	DBG_DEBUG("Storing update {%s}-%lu\n",
		  GUID_buf_string(&update->gsvn_db_guid, &guid),
		  update->gsvn_version);
	status = dfsr_db_store(db_ctx, &update->uid_db_guid,
			update->uid_version, record);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to store {%s}-v%lu record: %s\n",
			GUID_buf_string(&update->uid_db_guid, &guid),
			update->uid_version, nt_errstr(status));
		goto out;
	}

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(record);

	return status;
}

static NTSTATUS dfsr_meet_install_update_internal(TALLOC_CTX *mem_ctx,
		struct dfsr_meet_state *state,
		const char *staged_file,
		const char *installing_dir,
		const char *root_dir,
		struct frstrans_Update *update)
{
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dfsr_meet_store(tmp_ctx, state->db_ctx, update);

	TALLOC_FREE(tmp_ctx);

	return status;
}

static void dfsr_meet_install_update(struct imessaging_context *imsg_ctx,
				     void *private_data,
				     uint32_t msg_type,
				     struct server_id src,
				     size_t num_fds,
				     int *fds,
				     DATA_BLOB *blob)
{
	TALLOC_CTX *tmp_ctx;
	struct dfsr_meet_install_update request;
	struct dfsr_meet_update_installed response;
	enum ndr_err_code ndr_err;
	struct dfsr_meet_state *state;
	DATA_BLOB b = data_blob_null;
	struct GUID_txt_buf txtguid;

	state = talloc_get_type(private_data, struct dfsr_meet_state);

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		DBG_ERR("No memory\n");

		/* Just send an empty response, will be considered an error */
		imessaging_send(imsg_ctx, src, MSG_DFSR_MEET_UPDATE_INSTALLED,
				&b);
		return;
	}

	ndr_err = ndr_pull_struct_blob(blob, tmp_ctx, &request,
		(ndr_pull_flags_fn_t)ndr_pull_dfsr_meet_install_update);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to pull meet update: %s\n",
			ndr_errstr(ndr_err));
		response.result = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	DBG_DEBUG("Installing update {%s}-v%lu\n",
		  GUID_buf_string(&request.update->gsvn_db_guid, &txtguid),
		  request.update->gsvn_version);

	response.result = dfsr_meet_install_update_internal(tmp_ctx, state,
			request.staged_file, request.installing_dir,
			request.root_dir, request.update);

out:
	ndr_err = ndr_push_struct_blob(&b, tmp_ctx, &response,
		(ndr_push_flags_fn_t)ndr_push_dfsr_meet_update_installed);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to push meet installed: %s\n",
			ndr_errstr(ndr_err));

		/* Just send an empty response, will be considered an error */
		b.data = NULL;
		b.length = 0;
	}

	imessaging_send(imsg_ctx, src, MSG_DFSR_MEET_UPDATE_INSTALLED, &b);

	talloc_free(tmp_ctx);
}

struct tevent_req *dfsr_meet_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  pid_t parent_pid)
{
	struct tevent_req *req;
	struct dfsr_meet_state *state;
	struct loadparm_context *lp_ctx;
	struct imessaging_context *imsg_ctx;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct dfsr_meet_state);
	if (req == NULL) {
		return NULL;
	}

	lp_ctx = loadparm_init_s3(state, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DBG_ERR("Could not load smb.conf to init server's "
			"imessaging context.\n");
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	imsg_ctx = imessaging_init(state, lp_ctx, pid_to_procid(getpid()), ev);
	if (tevent_req_nomem(imsg_ctx, req)) {
		return tevent_req_post(req, ev);
	}

	status = irpc_add_name(imsg_ctx, "dfsr-meet");
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->parent_pid = parent_pid;
	state->imsg_ctx = imsg_ctx;
	state->lp_ctx = lp_ctx;
	state->db_ctx = dfsr_db_init(state, lp_state_directory());
	if (tevent_req_nomem(state->db_ctx, req)) {
		return tevent_req_post(req, ev);
	}

	status = imessaging_register(imsg_ctx, state,
			MSG_DFSR_MEET_INSTALL_UPDATE,
			dfsr_meet_install_update);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

NTSTATUS dfsr_meet_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
