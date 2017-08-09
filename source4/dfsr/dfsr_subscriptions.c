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
#include "util/dlinklist.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

static NTSTATUS dfsrsrv_refresh_group_content_sets(
		TALLOC_CTX *mem_ctx,
		struct dfsrsrv_service *service,
		struct dfsrsrv_replication_group *group,
		struct ldb_dn *subscriber_dn)
{
	int ret, i;
	struct ldb_result *res;
	static const char *attrs[] = {
		"msDFSR-ContentSetGuid",
		"msDFSR-Enabled",
		"msDFSR-ReadOnly",
		NULL };
	struct GUID_txt_buf txtguid1, txtguid2;

	DBG_INFO("Refreshing replication group {%s} content set "
		 "subscriptions\n", GUID_buf_string(&group->guid, &txtguid1));

	ret = ldb_search(service->samdb, mem_ctx, &res, subscriber_dn,
			LDB_SCOPE_ONELEVEL, attrs,
			"(objectClass=msDFSR-Subscription)");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search local subscriptions: %s\n",
			ldb_errstring(service->samdb));
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message *msg = res->msgs[i];
		struct dfsrsrv_content_set *set = NULL;
		struct GUID set_guid;
		struct ldb_result *res2;
		static const char *attrs2[] = { "name", NULL };
		struct ldb_dn *dfsr_global_settings_dn;

		set_guid = samdb_result_guid(msg, "msDFSR-ContentSetGuid");

		dfsr_global_settings_dn = ldb_dn_new_fmt(mem_ctx,
			service->samdb,	"CN=DFSR-GlobalSettings,CN=System,%s",
			ldb_dn_get_linearized(ldb_get_root_basedn(
				service->samdb)));
		if (dfsr_global_settings_dn == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		ret = ldb_search(service->samdb, mem_ctx, &res2,
			dfsr_global_settings_dn, LDB_SCOPE_SUBTREE, attrs2,
			"(&(objectClass=msDFSR-ContentSet)"
			"(objectGUID=%s))", GUID_string(mem_ctx, &set_guid));
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Failed to search content set: %s\n",
				ldb_errstring(service->samdb));
			continue;
		}
		if (res2->count != 1) {
			DBG_ERR("Content set {%s} not found\n",
				GUID_buf_string(&set_guid, &txtguid1));
			continue;
		}

		/* Search current subscriptions */
		for (set = group->sets; set; set = set->next) {
			if (GUID_equal(&set->guid, &set_guid)) {
				break;
			}
		}

		if (set == NULL) {
			set = talloc_zero(group, struct dfsrsrv_content_set);
			if (set == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			set->group = group;
			set->guid = set_guid;
			set->name = talloc_strdup(set,
				ldb_msg_find_attr_as_string(res2->msgs[0],
					"name", NULL));
			if (set->name == NULL) {
				TALLOC_FREE(set);
				return NT_STATUS_NO_MEMORY;
			}

			DLIST_ADD_END(group->sets, set);

			DBG_INFO("Found new subscription to content set "
				 "{%s} (%s) on replication group {%s}\n",
				 GUID_buf_string(&set->guid, &txtguid1),
				 set->name,
				 GUID_buf_string(&group->guid, &txtguid2));
		}
		set->enabled = ldb_msg_find_attr_as_bool(msg,
			"msDFSR-Enabled", false);
		set->read_only = ldb_msg_find_attr_as_bool(msg,
			"msDFSR-ReadOnly", false);
	}

	return NT_STATUS_OK;
}

NTSTATUS dfsrsrv_refresh_subscriptions(struct dfsrsrv_service *service)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	int ret, i;
	struct ldb_dn *account_dn, *local_settings_dn;
	struct ldb_result *res;
	static const char *attrs[] = { "msDFSR-MemberReference" };

	DBG_INFO("Refreshing replication groups subscriptions\n");

	tmp_ctx = talloc_new(service);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Get the references under DFS-R global settings from the local
	 * subscriptions */
	ret = samdb_server_reference_dn(service->samdb, tmp_ctx, &account_dn);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search the computer account: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto out;
	}

	local_settings_dn = ldb_dn_new_fmt(tmp_ctx, service->samdb,
		"CN=DFSR-LocalSettings,%s", ldb_dn_get_linearized(account_dn));
	if (local_settings_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = ldb_search(service->samdb, tmp_ctx, &res, local_settings_dn,
		LDB_SCOPE_ONELEVEL, attrs, "(objectClass=msDFSR-Subscriber)");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search local subscriber: %s\n",
			ldb_errstring(service->samdb));
		status = dsdb_ldb_err_to_ntstatus(ret);
		goto out;
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message *msg = res->msgs[i];
		struct ldb_dn *subscriber_dn, *member_dn;
		struct ldb_dn *topology_dn, *group_dn;
		struct ldb_result *res2;
		static const char *attrs2[] = { "objectGUID", "name",
						"msDFSR-ReplicationGroupType",
						NULL };
		struct dfsrsrv_replication_group *s;
		struct GUID group_guid;

		subscriber_dn = msg->dn;
		member_dn = ldb_msg_find_attr_as_dn(service->samdb, tmp_ctx,
			msg, "msDFSR-MemberReference");
		if (member_dn == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		topology_dn = ldb_dn_get_parent(tmp_ctx, member_dn);
		if (topology_dn == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		group_dn = ldb_dn_get_parent(tmp_ctx, topology_dn);
		if (group_dn == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		ret = ldb_search(service->samdb, tmp_ctx, &res2, group_dn,
			LDB_SCOPE_BASE, attrs2,
			"(objectClass=msDFSR-ReplicationGroup)");
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Failed to search replication group '%s': "
				"%s\n", ldb_dn_get_linearized(group_dn),
				ldb_errstring(service->samdb));
			continue;
		}

		if (res2->count != 1) {
			DBG_ERR("Replication group '%s' not found\n",
				ldb_dn_get_linearized(group_dn));
			continue;
		}

		group_guid = samdb_result_guid(res2->msgs[0], "objectGuid");

		for (s = service->subscriptions; s; s = s->next) {
			if (GUID_equal(&s->guid, &group_guid)) {
				break;
			}
		}

		if (s == NULL) {
			struct GUID_txt_buf txtguid;

			s = talloc_zero(service,
				struct dfsrsrv_replication_group);
			s->guid = group_guid;
			s->name = talloc_strdup(s,
				 ldb_msg_find_attr_as_string(
					res2->msgs[0], "name", NULL));
			if (s->name == NULL) {
				TALLOC_FREE(s);
				return NT_STATUS_NO_MEMORY;
			}

			s->type = ldb_msg_find_attr_as_int(res2->msgs[0],
				 "msDFSR-ReplicationGroupType", -1);

			DLIST_ADD_END(service->subscriptions, s);

			DBG_INFO("Found new subscription to replication "
				 "group {%s} (%s)\n",
				 GUID_buf_string(&s->guid, &txtguid),
				 s->name);
		}

		status = dfsrsrv_refresh_group_content_sets(tmp_ctx,
				service, s, subscriber_dn);
		if (!NT_STATUS_IS_OK(status)) {
			struct GUID_txt_buf txtguid;
			DBG_ERR("Failed to refresh replication group {%s} "
				"content set subscriptions: %s\n",
				GUID_buf_string(&s->guid, &txtguid),
				nt_errstr(status));
			continue;
		}
	}

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(tmp_ctx);

	return status;
}
