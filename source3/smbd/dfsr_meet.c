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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR_MEET

struct dfsr_meet_state {
	struct imessaging_context *imsg_ctx;
	struct loadparm_context *lp_ctx;
	pid_t parent_pid;
};

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

	return req;
}

NTSTATUS dfsr_meet_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
