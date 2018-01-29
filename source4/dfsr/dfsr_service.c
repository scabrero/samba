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
#include "auth/auth.h"
#include "samba/service.h"
#include <ldb_errors.h>
#include <ldb_module.h>
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "libds/common/roles.h"
#include "dfsr/dfsr_service.h"
#include "dfsr/dfsr_db.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

static NTSTATUS dfsrsrv_init_creds(struct dfsrsrv_service *service)
{
	service->system_session_info = system_session(service->task->lp_ctx);
	if (service->system_session_info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dfsrsrv_connect_dbs(struct dfsrsrv_service *service,
				    struct loadparm_context *lp_ctx)
{
	service->samdb = samdb_connect(service, service->task->event_ctx,
				lp_ctx, service->system_session_info, NULL, 0);
	if (service->samdb == NULL) {
		return NT_STATUS_DS_UNAVAILABLE;
	}

	service->dfsrdb = dfsr_db_init(service, lpcfg_state_directory(lp_ctx));
	if (service->dfsrdb == NULL) {
		return NT_STATUS_SERVER_UNAVAILABLE;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dfsrsrv_init_local_settings(struct dfsrsrv_service *service)
{
	NTSTATUS status;
	struct ldb_dn *account_dn = NULL;
	struct ldb_result *res = NULL;
	struct ldb_message *msg = NULL;
	int ret;

	ret = samdb_server_reference_dn(service->samdb, service, &account_dn);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search the computer account: %s",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto out;
	}

	ret = ldb_search(service->samdb, service, &res, account_dn,
			 LDB_SCOPE_ONELEVEL, NULL,
			 "(objectclass=msDFSR-LocalSettings)");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search DFSR-LocalSettings: %s",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto out;
	}

	if (res->count == 0) {
		DBG_NOTICE("Initializing DFS-R local settings\n");

		msg = ldb_msg_new(service);
		if (msg == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		msg->dn = ldb_dn_new_fmt(service,
				service->samdb, "CN=DFSR-LocalSettings,%s",
				ldb_dn_get_linearized(account_dn));
		if (msg->dn == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ret = ldb_msg_add_string(msg, "objectClass",
				"msDFSR-LocalSettings");
		if (ret != LDB_SUCCESS) {
			status = dsdb_ldb_err_to_ntstatus(ret);
			goto out;
		}

		ret = ldb_msg_add_string(msg, "msDFSR-Version", "1.0.0.0");
		if (ret != LDB_SUCCESS) {
			status = dsdb_ldb_err_to_ntstatus(ret);
			goto out;
		}

		ret = ldb_msg_add_string(msg, "msDFSR-Flags", "48");
		if (ret != LDB_SUCCESS) {
			status = dsdb_ldb_err_to_ntstatus(ret);
			goto out;
		}

		ret = ldb_add(service->samdb, msg);
		if (ret != LDB_SUCCESS) {
			status = dsdb_ldb_err_to_ntstatus(ret);
			goto out;
		}
	}

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(msg);
	TALLOC_FREE(res);
	TALLOC_FREE(account_dn);

	return status;
}

/*
 * startup the dfsr service task
 */
static NTSTATUS dfsrsrv_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct dfsrsrv_service *service;
	uint32_t periodic_startup_interval;

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		break;
	case ROLE_STANDALONE:
		task_server_terminate(task, "dfsrsrv: no dfsr required in "
				      "standalone configuration", false);
		return NT_STATUS_INVALID_PARAMETER;
	case ROLE_DOMAIN_MEMBER:
		/*
		 * FIXME To be implemented
		 */
		task_server_terminate(task, "dfsrsrv: no dfsr required in "
				      "domain member configuration", false);
		return NT_STATUS_NOT_IMPLEMENTED;
	default:
		task_server_terminate(task, "dfsrsrv: unknown server role, "
				      "stopping service", false);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* FIXME Check domain level > 2008 */

	task_server_set_title(task, "task[dfsrsrv]");

	service = talloc_zero(task, struct dfsrsrv_service);
	if (!service) {
		task_server_terminate(task,
			"dfsrsrv_task_init: no memory", true);
		return NT_STATUS_NO_MEMORY;
	}
	service->task		= task;
	service->startup_time	= timeval_current();
	task->private_data	= service;

	status = dfsrsrv_init_creds(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
			"dfsrsrv: Failed to obtain server credentials: %s\n",
			nt_errstr(status)), true);
		return status;
	}

	status = dfsrsrv_connect_dbs(service, task->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
			"dfsrsrv: Failed to connect to database: %s\n",
			nt_errstr(status)), true);
		return status;
	}

	status = dfsrsrv_init_local_settings(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
			"dfsrsrv: Failed to init DFS-R local settings: %s\n",
			nt_errstr(status)), true);
		return status;
	}

	status = dfsrsrv_sysvol_subscription_check(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
			"dfsrsrv: Failed to subscribe to sysvol replication "
			"group: %s\n", nt_errstr(status)), true);
		return status;
	}

	status = dfsrsrv_meet_notify_init(service,
					  service->task->msg_ctx,
					  &service->meet_notify_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
			"dfsrsrv: Failed to init meet messaging context: %s\n",
			nt_errstr(status)), true);
		return status;
	}

	periodic_startup_interval = lpcfg_parm_int(task->lp_ctx, NULL,
						   "dfsrsrv",
						   "periodic_startup_interval",
						   1); /* in seconds */
	service->periodic.interval = lpcfg_parm_int(task->lp_ctx, NULL,
						    "dfsrsrv",
						    "periodic_interval",
						    10); /* in seconds */

	status = dfsrsrv_periodic_schedule(service, periodic_startup_interval);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
			"dfsrsrv: Failed to periodic schedule: %s\n",
			nt_errstr(status)), true);
		return status;
	}

	service->pending.im = tevent_create_immediate(service);
	if (service->pending.im == NULL) {
		task_server_terminate(task,
				      "dfsrsrv: Failed to create immediate "
				      "task for processing updates\n",
				      true);
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/*
 * register ourselves as a available server
 */
NTSTATUS server_service_dfsr_init(TALLOC_CTX *ctx)
{
	struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true,
		.task_init = dfsrsrv_task_init,
		.post_fork = NULL
	};
	return register_server_service(ctx, "dfsr", &details);
}
