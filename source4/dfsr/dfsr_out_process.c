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
#include "samba/service.h"
#include "dfsr/dfsr_service.h"
#include "lib/events/events.h"
#include "util/tevent_ntstatus.h"
#include "util/dlinklist.h"
#include "dfsr/dfsr_db.h"
#include "librpc/gen_ndr/ndr_fscc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

struct dfsrsrv_process_state {
	struct tevent_context *ev_ctx;
	struct imessaging_context *imsg_ctx;
	struct dfsrsrv_meet_notify_context *notify_ctx;
	struct dfsrsrv_vv_queue *queue;
	struct dfsrsrv_update *entry;

	enum frstrans_RequestedStagingPolicy staging_policy;
	struct policy_handle server_context;
	struct frstrans_RdcFileInfo *rdc_file_info;
	uint8_t *data_buffer;
	uint32_t buffer_size;
	uint32_t size_read;
	uint32_t is_end_of_file;

	char *staging_file;
};

static void dfsrsrv_process_next(struct tevent_req *subreq);
static void dfsrsrv_process_install_done(struct tevent_req *subreq);
static struct tevent_req *dfsrsrv_process_send(
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev_ctx,
		struct imessaging_context *imsg_ctx,
		struct dfsrsrv_meet_notify_context *notify_ctx,
		struct dfsrsrv_vv_queue *queue,
		struct dfsrsrv_update *entry)
{
	struct tevent_req *req, *subreq;
	struct dfsrsrv_process_state *state;
	struct GUID_txt_buf txtguid;

	req = tevent_req_create(mem_ctx, &state, struct dfsrsrv_process_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev_ctx = ev_ctx;
	state->imsg_ctx = imsg_ctx;
	state->notify_ctx = notify_ctx;
	state->queue = queue;
	state->entry = entry;
	state->staging_policy = FRSTRANS_STAGING_POLICY_SERVER_DEFAULTY;
	state->size_read = 0;
	state->is_end_of_file = 0;
	state->buffer_size = 0;
	state->data_buffer = NULL;
	state->staging_file = NULL;

	/* If a client receives an update whose gvsnVersion is larger
	 * than any corresponding update that it already has for the
	 * same UID and if the received update has the present field
	 * set to a nonzero value, the client must download and
	 * persist file contents pertaining to the file */
	if (state->entry->update->present) {
		state->buffer_size = 262144;
		state->data_buffer = talloc_zero_array(state, uint8_t,
				state->buffer_size);
		if (tevent_req_nomem(state->data_buffer, req)) {
			return tevent_req_post(req, ev_ctx);
		}

		DBG_DEBUG("Downloading update {%s}-%lu (%s)\n",
			  GUID_buf_string(&state->entry->update->gsvn_db_guid,
					  &txtguid),
			  state->entry->update->gsvn_version,
			  state->entry->update->name);

		subreq = dcerpc_frstrans_InitializeFileTransferAsync_send(
				state,
				state->ev_ctx,
				state->queue->pipe->binding_handle,
				state->queue->conn->guid,
				state->entry->update,
				0, /* rdc_desired */
				&state->staging_policy,
				&state->server_context,
				&state->rdc_file_info,
				state->data_buffer,
				state->buffer_size,
				&state->size_read,
				&state->is_end_of_file);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev_ctx);
		}
		tevent_req_set_callback(subreq, dfsrsrv_process_next, req);
	} else {
		/* This is a tombstone, an update pertaining to a file
		 * deletion */

		DBG_DEBUG("Tombstone update {%s}-%lu (%s)\n",
			  GUID_buf_string(&state->entry->update->gsvn_db_guid,
					  &txtguid),
			  state->entry->update->gsvn_version,
			  state->entry->update->name);
		subreq = dfsrsrv_install_send(state,
				state->ev_ctx,
				state->imsg_ctx,
				state->notify_ctx,
				"",
				state->queue->set->installing_path,
				state->queue->set->root_path,
				state->entry->update);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev_ctx);
		}
		tevent_req_set_callback(subreq, dfsrsrv_process_install_done,
					req);
	}

	return req;
}

static void dfsrsrv_process_download_done(struct tevent_req *subreq);
static void dfsrsrv_process_next(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_process_state *state;
	struct GUID_txt_buf txtguid1;
	NTSTATUS status;
	WERROR result;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_process_state);
	status = dcerpc_frstrans_InitializeFileTransferAsync_recv(subreq,
			state->entry, &result);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to process update: %s\n", nt_errstr(status));
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		DBG_ERR("Failed to process update: %s\n", win_errstr(result));
		tevent_req_nterror(req, werror_to_ntstatus(result));
		return;
	}

	/* Build the staged file path */
	status = dfsrsrv_staging_get_path(state,
			state->queue->set->staging_path,
			state->entry->update, &state->staging_file);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * Create or tructate the stage file and write the received buffer. If
	 * no data received this may be because the update does not fit in the
	 * InitializeFileTransferAsync buffer. This will prepare the staging
	 * file to be fully downloaded by RawGetFileData
	 */
	DBG_DEBUG("Staging update {%s}-%lu (%s) to '%s'\n",
		  GUID_buf_string(&state->entry->update->gsvn_db_guid,
				  &txtguid1),
		  state->entry->update->gsvn_version,
		  state->entry->update->name, state->staging_file);
	status = dfsrsrv_staging_write_buffer(state, state->staging_file,
			state->data_buffer, state->size_read, false);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * [MS-FRS2] 3.3.4.8 Upon successful completion, the client must
	 * proceed to download the full file contents. If the server context
	 * handle returned is set to 0, the entire contents fit in the buffer
	 * provided as part of the output parameters. The client assumes that
	 * the returne value of frsUpdate parameter holds the authoritative
	 * metadata for the file contents that corresponds to the time that
	 * the file download took place
	 */
	if (state->entry->update->present &&
			!ndr_policy_handle_empty(&state->server_context)) {
		/* The update did not fit in the provided buffer. Proceed to
		 * download the full update. */
		DBG_DEBUG("Downloading full update {%s}-%lu (%s)\n",
			  GUID_buf_string(&state->entry->update->gsvn_db_guid,
					  &txtguid1),
			  state->entry->update->gsvn_version,
			  state->entry->update->name);
		subreq = dfsrsrv_download_update_send(state, state->ev_ctx,
				state->queue->pipe, state->server_context,
				state->staging_file);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, dfsrsrv_process_download_done,
					req);
		return;
	}

	/* Update fits in the InitializeTransferAsync provided buffer and is
	 * written to staging file. Install to persistent storage */
	subreq = dfsrsrv_install_send(state,
				      state->ev_ctx,
				      state->imsg_ctx,
				      state->notify_ctx,
				      state->staging_file,
				      state->queue->set->installing_path,
				      state->queue->set->root_path,
				      state->entry->update);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_process_install_done, req);
}

static void dfsrsrv_process_download_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_process_state *state;
	NTSTATUS status;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_process_state);

	status = dfsrsrv_download_update_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* At this point the update is fully downloaded to the staging file.
	 * Install to persistent storage */
	subreq = dfsrsrv_install_send(state,
				      state->ev_ctx,
				      state->imsg_ctx,
				      state->notify_ctx,
				      state->staging_file,
				      state->queue->set->installing_path,
				      state->queue->set->root_path,
				      state->entry->update);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dfsrsrv_process_install_done, req);
}

static void dfsrsrv_process_install_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct dfsrsrv_process_state *state;
	NTSTATUS status;
	struct GUID_txt_buf txtguid1;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct dfsrsrv_process_state);
	TALLOC_FREE(state->data_buffer);

	status = dfsrsrv_install_recv(subreq);
	TALLOC_FREE(subreq);

	DBG_DEBUG("Installed {%s}-%lu (%s): %s\n",
		  GUID_buf_string(&state->entry->update->gsvn_db_guid,
				  &txtguid1),
		  state->entry->update->gsvn_version,
		  state->entry->update->name, nt_errstr(status));

	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = dfsrsrv_staging_delete(state->staging_file);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("Failed to delete staging file '%s': %s\n",
			state->staging_file, nt_errstr(status));
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS dfsrsrv_process_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);

	return NT_STATUS_OK;
}

static void dfsrsrv_process_done(struct tevent_req *req)
{
	struct dfsrsrv_service *service;
	NTSTATUS status;
	struct GUID_txt_buf txtguid1;

	service = tevent_req_callback_data(req, struct dfsrsrv_service);

	status = dfsrsrv_process_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		struct dfsrsrv_update *entry;
		struct dfsrsrv_vv_queue *vv;
		entry = service->process_queue.current_vv->current_update;
		vv = service->process_queue.current_vv;

		DBG_ERR("Failed to process update {%s}-%lu (%s): %s\n",
			GUID_buf_string(&entry->update->gsvn_db_guid,
					&txtguid1),
			entry->update->gsvn_version,
			entry->update->name, nt_errstr(status));

		/* Add again to the tail of pending updates */
		DLIST_ADD_END(vv->pending_updates, entry);

		/* Reset current installing update to pick again */
		service->process_queue.current_vv->current_update = NULL;

		return;
	}

	TALLOC_FREE(service->process_queue.current_vv->current_update);

	/* [MS-FRS2] 1.3 Clients can update their previously saved version
	 * chain vector based on the server's version chain vector after a
	 * completed synchronization; that is, when all updates pertaining to
	 * a version chain vector have been processed and all file data that
	 * is required by a client to synchronize with a server has been
	 * downloaded. */
	if (service->process_queue.current_vv->pending_updates == NULL) {
		/* TODO Merge and save the set known version chain vectors
		 * with the processed one and save to database */

		DLIST_REMOVE(service->process_queue.pending_vv,
				service->process_queue.current_vv);
		TALLOC_FREE(service->process_queue.current_vv);
	}


	/* Schedule inmediate trigger to continue with the next update */
	tevent_schedule_immediate(service->pending.im,
				  service->task->event_ctx,
				  dfsrsrv_process_updates_handler_im,
				  service);
}

static NTSTATUS dfsrsrv_process_check_installed(
		TALLOC_CTX *mem_ctx,
		struct dfsrsrv_service *service,
		struct GUID *guid,
		uint64_t version)
{
	NTSTATUS status;
	struct dfsr_db_record *rec;

	status = dfsr_db_fetch(service->dfsrdb, mem_ctx, guid, version,
			       &rec);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	TALLOC_FREE(rec);

	return status;
}

static bool dfsrsrv_process_check_superseded(TALLOC_CTX *mem_ctx,
					     struct dfsrsrv_service *service,
					     struct frstrans_Update *current)
{
	struct dfsr_db_record *record = NULL;
	struct frstrans_Update *stored = NULL;
	bool superseded = false;
	NTSTATUS status;

	status = dfsr_db_fetch(service->dfsrdb, mem_ctx, &current->uid_db_guid,
			       current->uid_version, &record);
	if (NT_STATUS_IS_OK(status)) {
		uint32_t stored_folder_attr;
		uint32_t current_folder_attr;
		int res;

		stored = record->update;

		/* An update with a higher value of fence supersedes updates
		 * with lower fence values; otherwise, the fence values are
		 * equal. */
		if (stored->fence != current->fence) {
			superseded = (stored->fence > current->fence);
			goto out;
		}

		/* An update with the directory attribute set in the attributes
		 * field supersedes updates that do not have the directory
		 * attribute set; otherwise, these attributes coincide. */
		stored_folder_attr = (stored->attributes &
				      FSCC_FILE_ATTRIBUTE_DIRECTORY);
		current_folder_attr = (current->attributes &
				       FSCC_FILE_ATTRIBUTE_DIRECTORY);
		if (stored_folder_attr != current_folder_attr) {
			superseded = (current_folder_attr &&
				      !stored_folder_attr);
			goto out;
		}

		/* An update with a higher value of the createTime supersedes
		 * updates with lower values, otherwise, the create times are
		 * the same. */
		if (stored->create_time != current->create_time) {
			superseded = (stored->create_time >
				      current->create_time);
			goto out;
		}

		/* An update with a higher value of the clock field supersedes
		 * updates with a lower value; otherwise, the clock fields are
		 * the same */
		if (stored->clock != current->clock) {
			superseded = (stored->clock > current->clock);
			goto out;
		}

		/* An update with the lexicographically highest uidDbGuid
		 * supersedes one with a lower value. GUIDs are compared using
		 * a lexicographic left-to-right comparison of each byte, where
		 * each byte is treated as an unsigned 8-bit number. If the
		 * uidDbGuid coincide, comparison proceeds to version numbers */
		res = memcmp(&stored->uid_db_guid, &current->uid_db_guid,
			     sizeof(struct GUID));
		if (res != 0) {
			superseded = (res > 0);
			goto out;
		}

		/* An update with the largest value of uidVersion supersedes an
		 * update with a lower value of uidVersion. Otherwise, the
		 * versions are the same */
		if (stored->uid_version != current->uid_version) {
			superseded = (stored->uid_version >
				      current->uid_version);
			goto out;
		}

		/* An update with the lexicographically largest gvsnDbGuid
		 * supersedes one with a lower value; otherwise, the GUIDs are
		 * the same */
		res = memcmp(&stored->gsvn_db_guid, &current->gsvn_db_guid,
			     sizeof(struct GUID));
		if (res != 0) {
			superseded = (res > 0);
			goto out;
		}

		/* An update with the largest gvsnVersion supersedes an update
		 * with a lower gvsnVersion; otherwise, the two updates have
		 * the same GVSN, which a well-behaved implementation of DFS-R
		 * would allow only if the updates are in fact identical. */
		if (stored->gsvn_version != current->gsvn_version) {
			superseded = (stored->gsvn_version >=
				      current->gsvn_version);
			goto out;
		}

		/* Otherwise, the updates are equal. Set as superseeded to
		 * avoid installing the same update. */
		superseded = true;
	}

out:
	if (superseded) {
		struct GUID_txt_buf guid1, guid2;
		char *superseded_txt, *superseding_txt;
		superseded_txt = talloc_asprintf(mem_ctx, "{%s-v%lu}",
				GUID_buf_string(&current->gsvn_db_guid, &guid1),
				current->gsvn_version);
		superseding_txt = talloc_asprintf(mem_ctx, "{%s-v%lu}",
				GUID_buf_string(&stored->gsvn_db_guid, &guid2),
				stored->gsvn_version);
		DBG_DEBUG("Update %s superseded by %s\n",
			  superseded_txt, superseding_txt);
		TALLOC_FREE(superseding_txt);
		TALLOC_FREE(superseded_txt);
	}

	TALLOC_FREE(record);

	return superseded;
}

NTSTATUS dfsrsrv_process_updates(struct dfsrsrv_service *service)
{
	struct dfsrsrv_update *entry = NULL;
	struct GUID_txt_buf txtguid1, txtguid2;
	NTSTATUS status;

	if (service->process_queue.pending_vv == NULL) {
		/* There are no pending version chain vectors to process */
		DBG_INFO("Version vector processing queue is empty\n");
		return NT_STATUS_OK;
	}

	if (service->process_queue.current_vv == NULL) {
		struct dfsrsrv_content_set *set;
		struct dfsrsrv_connection *conn;

		/* Pick a version chain vector to process */
		service->process_queue.current_vv =
			service->process_queue.pending_vv;
		set = service->process_queue.current_vv->set;
		conn = service->process_queue.current_vv->conn;

		DBG_INFO("dfsrsrv: Processing pending version chain vector "
			 "(Content set {%s}, Connection {%s})\n",
			 GUID_buf_string(&set->guid, &txtguid1),
			 GUID_buf_string(&conn->guid, &txtguid2));
	}

	if (service->process_queue.current_vv->current_update != NULL) {
		entry = service->process_queue.current_vv->current_update;

		/* There is an update process operation in progress */
		DBG_INFO("dfsrsrv: Ongoing update installation: {%s}-%lu\n",
			 GUID_buf_string(&entry->update->gsvn_db_guid,
					 &txtguid1),
			 entry->update->gsvn_version);
		return NT_STATUS_OK;
	}

	DBG_DEBUG("Searching a candidate update for installation\n");

	/* Pick and update to install from the queue */
	entry = service->process_queue.current_vv->pending_updates;
	while (entry != NULL) {
		/*
		 * [MS-FRS2] 3.3.4.6.2 The UID of replicated folder roots
		 * The UID of replicated folder roots is fixed by using
		 * version 1 and the GUID of the replicated folder, that is:
		 *      uidDbGuid = {GUID Replicated Folder}
		 *      uidVersion = 1the root folder has uid version 1
		 */
		if (entry->update->uid_version == 1) {
			break;
		}

		/*
		 * [MS-FRS2] 3.3.4.6.2 The UID of version vector tombstones
		 * DFS-R allows members to garbage collect entries in their
		 * version vectors. If a member is not originating updates for
		 * a long period and wants to ensure that replication partners
		 * do not erroneously determine that it is stale, it should
		 * periodically generate this update, with the present field
		 * set to 1, for each of its own replicated folders.
		 * The update UID consists of the following:
		 *      uid_db_guid = xor guid(set_guid, m1)
		 *      uid_db_version = 2
		 */
		if (entry->update->uid_version == 2) {
			struct dfsrsrv_update *free = entry;
			struct dfsrsrv_vv_queue *current;

			entry = entry->next;
			current = service->process_queue.current_vv;

			DBG_INFO("Skipped content set tombstone\n");
			DLIST_REMOVE(current->pending_updates, free);
			TALLOC_FREE(free);
			continue;
		}

		/*
		 * [MS-FRS2] 3.3.4.6.2 To ensure convergence, a replicating
		 * member must store one update per UID that is maximal with
		 * respect to the specified lexicographic ordering
		 */
		if (dfsrsrv_process_check_superseded(entry, service,
					entry->update)) {
			struct dfsrsrv_update *free = entry;
			struct dfsrsrv_vv_queue *current;

			entry = entry->next;
			current = service->process_queue.current_vv;

			DBG_INFO("Skipped superseded update {%s}-%lu\n",
				 GUID_buf_string(&free->update->gsvn_db_guid,
					 	 &txtguid1),
				 free->update->gsvn_version);

			DLIST_REMOVE(current->pending_updates, free);
			TALLOC_FREE(free);
			continue;
		}

		/*
		 * [MS-FRS2] 3.3.4.6.2 To avoid Dangling child conflict,
		 * ensure that parents are saved in persistent storage prior
		 * to their children. To avoid Cycle conflicts, process
		 * received updates in ancestral order (parents before
		 * children)
		 */
		status = dfsrsrv_process_check_installed(entry, service,
				&entry->update->parent_db_guid,
				entry->update->parent_version);
		if (NT_STATUS_IS_OK(status)) {
			/* Parent is installed, proceed */
			break;
		} else if (NT_STATUS_EQUAL(NT_STATUS_NOT_FOUND, status)) {
			DBG_INFO("Skipped update {%s}-v%lu, parent {%s}-v%lu "
				 " is not installed\n",
				 GUID_buf_string(
					 &entry->update->gsvn_db_guid,
					 &txtguid1),
				 entry->update->gsvn_version,
				 GUID_buf_string(
					 &entry->update->parent_db_guid,
					 &txtguid2),
				 entry->update->parent_version);
		} else {
			return status;
		}

		entry = entry->next;
	}

	if (entry == NULL) {
		/*
		 * The pending update list for the first queue is traversed
		 * and there is no install candidate. Check if the pending
		 * updates queue is empty and has to be deleted
		 */
		if (service->process_queue.current_vv->pending_updates == NULL) {
			DLIST_REMOVE(service->process_queue.pending_vv,
				     service->process_queue.current_vv);
			TALLOC_FREE(service->process_queue.current_vv);

			/* Schedule to pick a new version vector queue */
			tevent_schedule_immediate(service->pending.im,
					service->task->event_ctx,
					dfsrsrv_process_updates_handler_im,
					service);
			return NT_STATUS_OK;
		}

		/* Something goes wrong */
		DBG_INFO("Failed to find a candidate update "
			 "to install. There are pending updates in "
			 "the current version chain vector.\n");
		return NT_STATUS_NOT_FOUND;
	}

	/* Process the selected update */
	service->process_queue.current_vv->current_update = entry;
	DLIST_REMOVE(service->process_queue.current_vv->pending_updates,
		     entry);
	entry->req = dfsrsrv_process_send(entry,
			service->task->event_ctx,
			service->task->msg_ctx,
			service->meet_notify_ctx,
			service->process_queue.current_vv,
			entry);
	if (entry->req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(entry->req, dfsrsrv_process_done, service);

	return NT_STATUS_OK;
}

void dfsrsrv_process_updates_handler_im(struct tevent_context *ev,
					struct tevent_immediate *im,
					void *ptr)
{
	struct dfsrsrv_service *service;

	service = talloc_get_type(ptr, struct dfsrsrv_service);

	dfsrsrv_process_updates(service);
}
