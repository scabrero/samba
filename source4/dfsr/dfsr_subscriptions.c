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

static NTSTATUS dfsrsrv_refresh_group_topology(
		TALLOC_CTX *mem_ctx,
		struct dfsrsrv_service *service,
		struct dfsrsrv_replication_group *group,
		struct ldb_dn *member_dn)
{
	struct ldb_result *res;
	int ret, i;
	static const char *attrs[] = { "objectGuid",
					"fromServer",
					"msDFSR-Enabled",
					NULL };
	struct GUID_txt_buf txtguid1, txtguid2;

	DBG_INFO("Refreshing replication group {%s} topology\n",
		 GUID_buf_string(&group->guid, &txtguid1));

	if (group->type == REPLICA_GROUP_TYPE_SYSVOL) {
		return dfsrsrv_sysvol_refresh_connections(mem_ctx, service,
				group, member_dn);
	}

	/* Get connections to other members */
	ret = ldb_search(service->samdb, mem_ctx, &res, member_dn,
		LDB_SCOPE_ONELEVEL, attrs, "(objectClass=msDFSR-Connection)");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to search replication group {%s} connections: "
			"%s\n", GUID_buf_string(&group->guid, &txtguid1),
			ldb_errstring(service->samdb));
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message *msg = res->msgs[i];
		struct dfsrsrv_connection *c = NULL;
		struct GUID cnx_guid;
		struct ldb_result *res2;
		struct ldb_dn *from_server_dn, *computer_dn;
		static const char *attrs3[] = { "msDFSR-ComputerReference",
						NULL };
		static const char *attrs4[] = { "dnsHostName", NULL };

		cnx_guid = samdb_result_guid(msg, "objectGuid");
		from_server_dn = ldb_msg_find_attr_as_dn(
			service->samdb, c, msg, "fromServer");
		if (from_server_dn == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		ret = ldb_search(service->samdb, mem_ctx, &res2,
			from_server_dn, LDB_SCOPE_BASE, attrs3,
			"(objectClass=msDFSR-Member)");
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Failed to search replication group {%s} "
				"connections: %s\n",
				GUID_buf_string(&group->guid, &txtguid1),
				ldb_errstring(service->samdb));
			continue;
		}

		if (res2->count != 1) {
			DBG_ERR("Failed to search replication group {%s} "
				"connections. Member '%s' not found\n",
				GUID_buf_string(&group->guid, &txtguid1),
				ldb_dn_get_linearized(from_server_dn));
			continue;
		}

		computer_dn = ldb_msg_find_attr_as_dn(service->samdb,
				mem_ctx, res2->msgs[0],
				"msDFSR-ComputerReference");
		if (computer_dn == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(res2);

		ret = ldb_search(service->samdb, mem_ctx, &res2,
			computer_dn, LDB_SCOPE_BASE, attrs4,
			"(objectClass=Computer)");
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Failed to search computer '%s': %s\n",
				ldb_dn_get_linearized(computer_dn),
				ldb_errstring(service->samdb));
			continue;
		}
		if (res2->count != 1) {
			DBG_ERR("Failed to search computer '%s': "
				"Expected one entry but %d found\n",
				ldb_dn_get_linearized(computer_dn),
				res2->count);
			continue;
		}

		for (c = group->connections; c; c = c->next) {
			if (GUID_equal(&c->guid, &cnx_guid)) {
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
			c->guid = cnx_guid;
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

		c->enabled = ldb_msg_find_attr_as_bool(msg, "msDFSR-Enabled",
			false);

		TALLOC_FREE(res2);
	}

	return NT_STATUS_OK;
}

static NTSTATUS dfsrsrv_init_set_paths(TALLOC_CTX *mem_ctx,
				       struct dfsrsrv_content_set *set)
{
	int ret;
	char *tmp;
	struct GUID_txt_buf tmp_buf;

	tmp = talloc_asprintf(mem_ctx, "%s/DfsrPrivate", set->root_path);
	if (tmp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = mkdir(tmp,  S_IRWXU | S_IWGRP | S_IRGRP | S_IROTH | S_IXOTH);
	if (ret != 0 && errno != EEXIST) {
		DBG_ERR("Failed to create directory %s: %s\n",
			tmp, strerror(errno));
		return map_nt_error_from_unix_common(errno);
	}

	ret = mkdir(set->staging_path, S_IRWXU | S_IWGRP | S_IRGRP |
				S_IROTH | S_IXOTH);
	if (ret != 0 && errno != EEXIST) {
		DBG_ERR("Failed to create directory %s: %s\n",
			set->staging_path, strerror(errno));
		return map_nt_error_from_unix_common(errno);
	}

	tmp = talloc_asprintf(mem_ctx, "%s/%s", set->staging_path,
			      GUID_buf_string(&set->guid, &tmp_buf));
	ret = mkdir(tmp,  S_IRWXU | S_IWGRP | S_IRGRP | S_IROTH | S_IXOTH);
	if (ret != 0 && errno != EEXIST) {
		DBG_ERR("Failed to create directory %s: %s\n",
			tmp, strerror(errno));
		talloc_free(tmp);
		return map_nt_error_from_unix_common(errno);
	}
	talloc_free(tmp);

	ret = mkdir(set->installing_path, S_IRWXU | S_IWGRP | S_IRGRP |
					  S_IROTH | S_IXOTH);
	if (ret != 0 && errno != EEXIST) {
		DBG_ERR("Failed to create directory %s: %s\n",
			set->installing_path, strerror(errno));
		return map_nt_error_from_unix_common(errno);
	}

	ret = mkdir(set->conflict_path, S_IRWXU | S_IWGRP | S_IRGRP |
					S_IROTH | S_IXOTH);
	if (ret != 0 && errno != EEXIST) {
		DBG_ERR("Failed to create directory %s: %s\n",
			set->conflict_path, strerror(errno));
		return map_nt_error_from_unix_common(errno);
	}

	return NT_STATUS_OK;
}

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
		"msDFSR-RootPath",
		"msDFSR-StagingPath",
		NULL };
	struct GUID_txt_buf txtguid1, txtguid2;
	NTSTATUS status;

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

			set->staging_path = talloc_strdup(set,
				ldb_msg_find_attr_as_string(msg,
					"msDFSR-StagingPath", NULL));

			set->conflict_path = talloc_strdup(set,
					ldb_msg_find_attr_as_string(msg,
					"msDFSR-ConflictPath", NULL));

			set->root_path = talloc_strdup(set,
				ldb_msg_find_attr_as_string(msg,
					"msDFSR-RootPath", NULL));

			if (set->root_path == NULL) {
				struct GUID_txt_buf txtguid;
				DBG_ERR("Content path not defined for folder "
					"{%s}, skipped.\n",
					GUID_buf_string(&set->guid, &txtguid));
				TALLOC_FREE(set);
				continue;
			}

			/* Set defaults if not set in LDAP */
			if (set->root_path && set->staging_path == NULL) {
				set->staging_path = talloc_asprintf(set,
						"%s/DfsrPrivate/Staging",
						set->root_path);
				if (set->staging_path == NULL) {
					TALLOC_FREE(set);
					return NT_STATUS_NO_MEMORY;
				}
			}

			if (set->root_path && set->conflict_path == NULL) {
				set->conflict_path = talloc_asprintf(set,
						"%s/DfsrPrivate/ConflictAndDeleted",
						set->root_path);
				if (set->conflict_path == NULL) {
					TALLOC_FREE(set);
					return NT_STATUS_NO_MEMORY;
				}
			}

			if (set->root_path) {
				set->installing_path = talloc_asprintf(set,
						"%s/DfsrPrivate/Installing",
						set->root_path);
				if (set->installing_path == NULL) {
					TALLOC_FREE(set);
					return NT_STATUS_NO_MEMORY;
				}
			}

			status = dfsrsrv_init_set_paths(mem_ctx, set);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("Failed to initialize local "
					"directories: %s\n",
					nt_errstr(status));
				TALLOC_FREE(set);
				return status;
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

		status = dfsrsrv_refresh_group_topology(tmp_ctx,
				service, s, member_dn);
		if (!NT_STATUS_IS_OK(status)) {
			struct GUID_txt_buf txtguid;
			DBG_ERR("Failed to refresh replication group {%s} "
				"topology: %s\n",
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
