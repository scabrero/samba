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
#include <ldb_errors.h>
#include <ldb_module.h>
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "samba/service.h"
#include "util/dlinklist.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

static NTSTATUS dfsrsrv_sysvol_join(TALLOC_CTX *mem_ctx,
				    struct dfsrsrv_service *service,
				    struct ldb_dn *sysvol_group_dn,
				    struct GUID sysvol_group_guid,
				    const char *sysvol_group_name,
				    struct GUID sysvol_set_guid,
				    struct ldb_dn *computer_account_dn)
{
	NTSTATUS status;
	struct ldb_dn *member_dn;
	struct ldb_dn *subscriber_dn;
	struct ldb_dn *subscription_dn;
	struct ldb_message *msg;
	struct loadparm_service *lp_sysvol;
	const char *sysvol_path;
	int ret;
	bool sysvol_join;

	sysvol_join = lpcfg_parm_bool(service->task->lp_ctx, NULL, "dfsrsrv",
				      "sysvol_join", false);
	if (!sysvol_join) {
		DBG_NOTICE("Skip adding ourselves as a member of "
			   "sysvol replication group\n");
		return NT_STATUS_OK;
	}

	DBG_INFO("Adding ourselves as a member of sysvol replication group\n");

	ret = ldb_transaction_start(service->samdb);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to start ldb transaction: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		return status;
	}

	/* Add ourselves as member of the sysvol replication group */
	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	member_dn = ldb_dn_new_fmt(mem_ctx, service->samdb,
			"CN=%s,CN=Topology,%s",
			lpcfg_netbios_name(service->task->lp_ctx),
			ldb_dn_get_linearized(sysvol_group_dn));
	if (member_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	msg->dn = member_dn;

	ret = ldb_msg_add_string(msg, "objectClass", "msDFSR-Member");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_msg_add_string(msg, "serverReference",
			ldb_dn_get_linearized(
				samdb_ntds_settings_dn(
					service->samdb, msg)));
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_msg_add_string(msg, "msDFSR-ComputerReference",
			ldb_dn_get_linearized(computer_account_dn));
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_add(service->samdb, msg);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add '%s' to sysvol replication group "
			"'%s': %s\n",
			ldb_dn_get_linearized(computer_account_dn),
			ldb_dn_get_linearized(sysvol_group_dn),
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}
	TALLOC_FREE(msg);

	/* Add the subscription */
	DBG_INFO("Subscribing ourselves to sysvol replication group\n");

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	subscriber_dn = ldb_dn_new_fmt(mem_ctx, service->samdb,
			"CN=%s,CN=DFSR-LocalSettings,%s", sysvol_group_name,
			ldb_dn_get_linearized(computer_account_dn));
	if (subscriber_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	msg->dn = subscriber_dn;

	ret = ldb_msg_add_string(msg, "objectClass", "msDFSR-Subscriber");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = dsdb_msg_add_guid(msg, &sysvol_group_guid,
			"msDFSR-ReplicationGroupGuid");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_msg_add_string(msg, "msDFSR-MemberReference",
			ldb_dn_get_linearized(member_dn));
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_add(service->samdb, msg);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add sysvol replication group "
			"subscription: %s\n",ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}
	TALLOC_FREE(msg);

	/* Add content sets subscription */
	DBG_INFO("Subscribing ourselves to sysvol content set\n");

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	subscription_dn = ldb_dn_new_fmt(mem_ctx, service->samdb,
			"CN=SYSVOL Subscription,%s",
			 ldb_dn_get_linearized(subscriber_dn));
	if (subscription_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	msg->dn = subscription_dn;

	ret = ldb_msg_add_string(msg, "objectClass", "msDFSR-Subscription");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	/* Build the sysvol path in persistent storage */
	lp_sysvol = lpcfg_service(service->task->lp_ctx , "sysvol");
	sysvol_path = lpcfg_path(lp_sysvol, lpcfg_default_service(
			service->task->lp_ctx), mem_ctx);
	if (sysvol_path == NULL) {
		DBG_ERR("Failed to get sysvol path\n");
		status = NT_STATUS_NOT_FOUND;
		goto fail;
	}

	sysvol_path = talloc_asprintf(mem_ctx, "%s/%s", sysvol_path,
			lpcfg_dnsdomain(service->task->lp_ctx));
	if (sysvol_path == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	ret = ldb_msg_add_string(msg, "msDFSR-RootPath", sysvol_path);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_msg_add_string(msg, "msDFSR-Enabled", "TRUE");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_msg_add_string(msg, "msDFSR-Options", "0");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = dsdb_msg_add_guid(msg, &sysvol_set_guid,
				"msDFSR-ContentSetGuid");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = dsdb_msg_add_guid(msg, &sysvol_group_guid,
				"msDFSR-ReplicationGroupGuid");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_msg_add_string(msg, "msDFSR-ReadOnly", "FALSE");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add message attribute: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}

	ret = ldb_add(service->samdb, msg);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add content set subscription: "
			"%s\n", ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto fail;
	}
	TALLOC_FREE(msg);

	ret = ldb_transaction_commit(service->samdb);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to commit samdb transaction: %s",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		return status;
	}

	return NT_STATUS_OK;

fail:
	ldb_transaction_cancel(service->samdb);

	return status;
}

NTSTATUS dfsrsrv_sysvol_subscription_check(struct dfsrsrv_service *service)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *dfsr_global_settings_dn;
	struct ldb_result *res;
	int ret;
	const char *attrs[] = { "objectGUID", "name", NULL };
	struct ldb_dn *sysvol_group_dn;
	struct GUID sysvol_group_guid;
	const char *sysvol_group_name;
	struct ldb_dn *topology_dn, *account_dn;
	const char *attrs2[] = { "objectGUID",
				"msDFSR-MemberReferenceBL", NULL };

	tmp_ctx = talloc_new(service);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	dfsr_global_settings_dn = ldb_dn_new_fmt(tmp_ctx, service->samdb,
		"CN=DFSR-GlobalSettings,CN=System,%s",
		ldb_dn_get_linearized(ldb_get_root_basedn(service->samdb)));
	if (dfsr_global_settings_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	/* Search the guid and DN of the SYSVOL replica group */
	ret = ldb_search(service->samdb, tmp_ctx, &res,
		dfsr_global_settings_dn, LDB_SCOPE_ONELEVEL, attrs,
		"(&(objectClass=msDFSR-ReplicationGroup)"
		"(msDFSR-ReplicationGroupType=1))");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search sysvol replication group: '%s'",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto out;
	}
	if (res->count != 1) {
		DBG_ERR("Failed to search sysvol replication group, "
			"expected one entry but %d found\n",
			res->count);
		status = NT_STATUS_NOT_FOUND;
		goto out;
	}

	sysvol_group_dn = talloc_steal(tmp_ctx, res->msgs[0]->dn);
	sysvol_group_guid = samdb_result_guid(res->msgs[0], "objectGUID");
	sysvol_group_name = talloc_strdup(tmp_ctx,
				ldb_msg_find_attr_as_string(res->msgs[0],
					"name", NULL));
	if (sysvol_group_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	TALLOC_FREE(res);

	/* Check if we are a member of sysvol replication group */
	ret = samdb_server_reference_dn(service->samdb, tmp_ctx, &account_dn);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search the computer account: %s",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto out;
	}

	topology_dn = ldb_dn_new_fmt(tmp_ctx, service->samdb, "%s,%s",
		"CN=Topology", ldb_dn_get_linearized(sysvol_group_dn));
	if (topology_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = ldb_search(service->samdb, tmp_ctx, &res, topology_dn,
			 LDB_SCOPE_ONELEVEL, attrs2,
			 "(&(objectClass=msDFSR-Member)"
			 "(msDFSR-ComputerReference=%s))",
			 ldb_dn_get_linearized(account_dn));
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search members of sysvol "
			"replication group: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto out;
	}

	if (res->count == 0) {
		struct ldb_dn *content_dn;
		struct ldb_result *res2;
		struct GUID sysvol_set_guid;

		content_dn = ldb_dn_new_fmt(tmp_ctx, service->samdb,
			"CN=Content,%s",
			ldb_dn_get_linearized(sysvol_group_dn));
		if (content_dn == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ret = ldb_search(service->samdb, tmp_ctx, &res2, content_dn,
			 LDB_SCOPE_ONELEVEL, attrs,
			 "(objectClass=msDFSR-ContentSet)");
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Failed to search sysvol content set: %s\n",
				ldb_errstring(service->samdb));
			status = dsdb_ldb_err_to_ntstatus(ret);
			goto out;
		}

		/*
		 * Ensure sysvol replication group has at least one content
		 * set
		 */
		if (res2->count != 1) {
			DBG_ERR("Content set not found in sysvol replication "
				"group '%s'\n", sysvol_group_name);
			status = NT_STATUS_NOT_FOUND;
			goto out;
		}

		sysvol_set_guid = samdb_result_guid(res2->msgs[0],
				"objectGUID");
		status = dfsrsrv_sysvol_join(tmp_ctx, service,
				sysvol_group_dn, sysvol_group_guid,
				sysvol_group_name, sysvol_set_guid,
				account_dn);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(tmp_ctx);

	return status;
}

NTSTATUS dfsrsrv_sysvol_refresh_connections(TALLOC_CTX *mem_ctx,
		struct dfsrsrv_service *service,
		struct dfsrsrv_replication_group *group,
		struct ldb_dn *member_dn)
{
	struct ldb_result *res;
	int ret, i;
	const char* attrs[] = {"objectGUID", "serverReference", NULL};
	const char* attrs2[] = {"objectGUID", "fromServer", NULL};
	struct ldb_dn *settings_dn;
	struct GUID_txt_buf txtguid1, txtguid2;

	/* Get topology member entry */
	ret = ldb_search(service->samdb, mem_ctx, &res, member_dn,
		LDB_SCOPE_BASE, attrs, "(objectClass=msDFSR-Member)");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search replication group {%s} member '%s': "
			"%s\n", GUID_buf_string(&group->guid, &txtguid1),
			ldb_dn_get_linearized(member_dn),
			ldb_errstring(service->samdb));
		return dsdb_ldb_err_to_ntstatus(ret);
	}
	if (res->count != 1) {
		DBG_ERR("Failed to search replication group {%s} member '%s': "
			"Expected one entry but %d found\n",
			GUID_buf_string(&group->guid, &txtguid1),
			ldb_dn_get_linearized(member_dn), res->count);
		return NT_STATUS_NOT_FOUND;
	}

	/* Get serverReference */
	settings_dn = ldb_msg_find_attr_as_dn(service->samdb, mem_ctx,
		 res->msgs[0], "serverReference");
	if (settings_dn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_search(service->samdb, mem_ctx, &res, settings_dn,
				LDB_SCOPE_ONELEVEL, attrs2,
				"(objectclass=nTDSConnection)");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search nTDSConnection: %s\n",
			ldb_errstring(service->samdb));
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	for (i = 0; i < res->count; i++) {
		struct GUID guid;
		struct ldb_dn *from_server, *from_server_ntds;
		struct ldb_result *res2;
		const char* attrs3[] = {"dNSHostName", NULL};
		struct dfsrsrv_connection *c = NULL;

		guid = samdb_result_guid(res->msgs[i], "objectGUID");

		from_server_ntds = ldb_msg_find_attr_as_dn(service->samdb,
					mem_ctx, res->msgs[i], "fromServer");
		if (from_server_ntds == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		from_server = ldb_dn_get_parent(mem_ctx, from_server_ntds);
		if (from_server == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		ret = ldb_search(service->samdb, mem_ctx, &res2, from_server,
				 LDB_SCOPE_BASE, attrs3,
				 "(&(objectclass=server)(dnsHostName=*))");
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Failed to search dnsHostName: %s\n",
				ldb_errstring(service->samdb));
			continue;
		}

		if (res2->count != 1) {
			DBG_ERR("Failed to search dnsHostName: Expected one "
				"entry buf %d found.\n", res2->count);
			TALLOC_FREE(res2);
			continue;
		}

		for (c = group->connections; c; c = c->next) {
			if (GUID_equal(&c->guid, &guid)) {
				break;
			}
		}

		if (c == NULL) {
			const char *hostname;
			char *binding_string;
			NTSTATUS status;

			hostname = ldb_msg_find_attr_as_string(
					res2->msgs[0], "dNSHostName", NULL);
			if (hostname == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			binding_string = talloc_asprintf(c,
				"%s@ncacn_ip_tcp:%s[krb5,seal%s]",
				"5bc1ed07-f5f5-485f-9dfd-6fd0acf9a23c",
				hostname, DEBUGLVL(10) ? ",print" : "");
			if (binding_string == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			c = talloc_zero(group, struct dfsrsrv_connection);
			if (c == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			c->guid = guid;
			c->group = group;
			status = dcerpc_parse_binding(c, binding_string,
						      &c->binding);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("Failed to parse binding string '%s': "
					"%s\n", binding_string,
					nt_errstr(status));
				TALLOC_FREE(c);
				continue;
			}

			DLIST_ADD_END(group->connections, c);

			DBG_INFO("Found new connection {%s} (%s) on "
				 "replication group {%s}\n",
				 GUID_buf_string(&c->guid, &txtguid1),
				 hostname,
				 GUID_buf_string(&group->guid, &txtguid2));
		}

		/* Sysvol connections are always enabled */
		c->enabled = true;
	}

	return NT_STATUS_OK;
}
