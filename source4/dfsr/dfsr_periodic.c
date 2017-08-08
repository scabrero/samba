/*
   Unix SMB/CIFS mplementation.

   DFS Replication service

   Copyright (C) Matthieu Patou <mat@matws.net> 2013-2014
   Copyright (C) Samuel Cabrero <scabrero@suse.de> 2021

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
#include "lib/events/events.h"
#include "dfsr/dfsr_service.h"
#include "samba/service.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

static NTSTATUS dfsrsrv_periodic_run(struct dfsrsrv_service *service)
{
	DBG_INFO("dfsrsrv: Periodic run\n");

	return NT_STATUS_OK;
}

static void dfsrsrv_periodic_handler_te(struct tevent_context *ev,
					struct tevent_timer *te,
					struct timeval t, void *ptr)
{
	struct dfsrsrv_service *service;
	NTSTATUS status;

	service = talloc_get_type(ptr, struct dfsrsrv_service);
	service->periodic.te = NULL;

	status = dfsrsrv_periodic_run(service);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dfsrsrv_periodic_run failed: %s\n",
			  nt_errstr(status));
	}

	status = dfsrsrv_periodic_schedule(service,
					   service->periodic.interval);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(service->task, nt_errstr(status),
				      false);
		return;
	}
}

NTSTATUS dfsrsrv_periodic_schedule(struct dfsrsrv_service *service,
				   uint32_t next_interval)
{
	struct tevent_timer *new_te;
	struct timeval next_time;

	/* prevent looping */
	if (next_interval == 0) {
		next_interval = 1;
	}

	next_time = timeval_current_ofs(next_interval, 50);

	if (service->periodic.te) {
		/*
		 * if the timestamp of the new event is higher,
		 * as current next we don't need to reschedule
		 */
		if (timeval_compare(&next_time,
			&service->periodic.next_event) > 0) {
			return NT_STATUS_OK;
		}
	}

	/* reset the next scheduled timestamp */
	service->periodic.next_event = next_time;

	new_te = tevent_add_timer(service->task->event_ctx, service,
				  service->periodic.next_event,
				  dfsrsrv_periodic_handler_te, service);
	if (new_te == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (DEBUGLEVEL >= DBGLVL_INFO) {
		TALLOC_CTX *tmp_ctx;
		tmp_ctx = talloc_new(service);
		if (tmp_ctx == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		DBG_INFO("Periodic schedule (%u) %sscheduled for: %s\n",
			 next_interval,
			 (service->periodic.te ? "re" : ""),
			 nt_time_string(tmp_ctx,
					timeval_to_nttime(&next_time)));
		TALLOC_FREE(tmp_ctx);
	}

	talloc_free(service->periodic.te);
	service->periodic.te = new_te;

	return NT_STATUS_OK;
}
