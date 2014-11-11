/*
   Unix SMB/CIFS implementation.

   Helpers to add users and groups to the DB

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2010
   Copyright (C) Matthias Dieter Wallnöfer 2009

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
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "../libds/common/flags.h"
#include "libcli/security/security.h"
#include "libds/common/flag_mapping.h"
#include "param/param.h"
#include "libcli/ldap/ldap_ndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/auth.h"

/**
 * If the client creating the machine account does not have the
 * SEC_ADS_CREATE_CHILD access right on the container object and the role is
 * DC, checks for the SEC_PRIV_MACHINE_ACCOUNT privilege.
 */
static NTSTATUS dsdb_add_machine_is_privileged(TALLOC_CTX *tmp_ctx,
					       struct ldb_context *ldb,
					       struct ldb_dn *container_dn,
					       bool *privileged)
{
	struct auth_session_info *sinfo = NULL;
	int ret;

	sinfo = talloc_get_type_abort(ldb_get_opaque(ldb, "sessionInfo"), struct auth_session_info);

	ret = dsdb_check_access_on_dn(ldb, tmp_ctx, container_dn, sinfo->security_token,
				      SEC_ADS_CREATE_CHILD, NULL);
	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		struct loadparm_context *lp_ctx;
		lp_ctx = talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"), 
					       struct loadparm_context);

		/* Check role, if not DC return access denied */
		if (lpcfg_server_role(lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC) {
			*privileged = false;
			return NT_STATUS_ACCESS_DENIED;
		}

		*privileged = security_token_has_privilege(sinfo->security_token,
							   SEC_PRIV_MACHINE_ACCOUNT);
		return NT_STATUS_ACCESS_DENIED;
	}
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

/**
 * When the machine account is created using the SEC_PRIV_MACHINE_ACCOUNT
 * privilege check the quota. If the attribute does not exists, the default
 * value is used (10).
 */
static NTSTATUS dsdb_add_machine_privileged_check_quota(TALLOC_CTX *tmp_ctx,
							struct ldb_context *ldb)
{
	struct auth_session_info *sinfo = NULL;
	struct ldb_dn *base_dn;
	struct ldb_result *res;
	struct ldb_message *msg;
	struct dom_sid *sid;
	int quota;
	int ret;
	const char *quota_attrs[] = {
		"ms-DS-MachineAccountQuota",
		NULL,
	};
	const char *creator_attrs[] = {
		"mS-DS-CreatorSID",
		NULL,
	};

	/* Get the quota */
	base_dn = ldb_get_default_basedn(ldb);
	if (base_dn == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_BASE,
			 quota_attrs, "(objectClass=domain)");
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (res->count != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res->msgs[0];
	quota = ldb_msg_find_attr_as_int(msg, "ms-DS-MachineAccountQuota", 10);
	talloc_free(res);

	/* Get client SID */
	sinfo = talloc_get_type_abort(ldb_get_opaque(ldb, "sessionInfo"), struct auth_session_info);
	sid = &sinfo->security_token->sids[0];
	if (sid == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* Check quota not exceeded by the client */
	ret = ldb_search(ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_SUBTREE,
			 creator_attrs, "(mS-DS-CreatorSID=%s)",
			 ldap_encode_ndr_dom_sid(tmp_ctx, sid));
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (res->count >= quota) {
		DEBUG(0, ("Failed to create account, quota exceeded\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

/**
 * When the machine account is created using the SEC_PRIV_MACHINE_ACCOUNT
 * privilege the resulting default security descriptor of the object has to
 * be fixed changing the owner to Domain Admins and the group to Domain Users.
 */
static NTSTATUS dsdb_add_machine_privileged_set_sd(TALLOC_CTX *tmp_ctx,
						   struct ldb_context *ldb,
						   struct ldb_dn *account_dn)
{
	struct security_descriptor *sd;
	const struct dom_sid *domain_sid;
	int ret;
	DATA_BLOB data;
	enum ndr_err_code ndr_err;
	struct ldb_request *req;
	struct ldb_message *msg;
	const char *sd_attrs[] = {
		"nTSecurityDescriptor",
		NULL
	};

	domain_sid = samdb_domain_sid(ldb);
	if (domain_sid == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = dsdb_search_one(ldb, tmp_ctx, &msg, account_dn,
			      LDB_SCOPE_BASE, sd_attrs, 0, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = dsdb_get_sd_from_ldb_message(ldb, tmp_ctx, msg, &sd);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	sd->group_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_USERS);
	sd->owner_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ADMINS);
	ndr_err = ndr_push_struct_blob(&data, tmp_ctx, sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	msg->dn = ldb_dn_copy(tmp_ctx, account_dn);

	ret = ldb_msg_add_value(msg, "nTSecurityDescriptor", &data, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	msg->elements[0].flags = LDB_FLAG_MOD_REPLACE;

	ret = ldb_msg_sanity_check(ldb, msg);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = ldb_build_mod_req(&req, ldb, tmp_ctx,
				msg,
				NULL,
				NULL,
				ldb_op_default_callback,
				NULL);
	ret = ldb_request_add_control(req, LDB_CONTROL_AS_SYSTEM_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = ldb_request(ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("Failed to set nTSecurityDescriptor on %s: %s",
				  ldb_dn_get_linearized(account_dn),
				  ldb_errstring(ldb)));
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

/* Add a user, SAMR style, including the correct transaction
 * semantics.  Used by the SAMR server and by pdb_samba4 */
NTSTATUS dsdb_add_user(struct ldb_context *ldb,
		       TALLOC_CTX *mem_ctx,
		       const char *account_name,
		       uint32_t acct_flags,
		       const struct dom_sid *forced_sid,
		       struct dom_sid **sid,
		       struct ldb_dn **dn)
{
	const char *name;
	struct ldb_request *req;
	struct ldb_message *msg;
	struct dsdb_control_samr_create_user *control;
	int ret;
	const char *container, *obj_class=NULL;
	char *cn_name;
	size_t cn_name_len;

	const char *attrs[] = {
		"objectSid",
		"userAccountControl",
		NULL
	};

	uint32_t user_account_control;
	struct ldb_dn *account_dn;
	struct dom_sid *account_sid;
	bool machine_account_privilege = false;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	/*
	 * Start a transaction, so we can query and do a subsequent atomic
	 * modify
	 */

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to start a transaction for user creation: %s\n",
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_LOCK_NOT_GRANTED;
	}

	/* check if the user already exists */
	name = samdb_search_string(ldb, tmp_ctx, NULL,
				   "sAMAccountName",
				   "(&(sAMAccountName=%s)(objectclass=user))",
				   ldb_binary_encode_string(tmp_ctx, account_name));
	if (name != NULL) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_USER_EXISTS;
	}

	cn_name = talloc_strdup(tmp_ctx, account_name);
	if (!cn_name) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	cn_name_len = strlen(cn_name);
	if (cn_name_len < 1) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* This must be one of these values *only* */
	if (acct_flags == ACB_NORMAL) {
		container = "CN=Users";
		obj_class = "user";
		user_account_control = UF_NORMAL_ACCOUNT;
	} else if (acct_flags == ACB_WSTRUST) {
		NTSTATUS status;
		struct ldb_dn *container_dn;

		if (cn_name[cn_name_len - 1] != '$') {
			ldb_transaction_cancel(ldb);
			return NT_STATUS_FOOBAR;
		}
		cn_name[cn_name_len - 1] = '\0';
		container = "CN=Computers";
		obj_class = "computer";
		user_account_control = UF_WORKSTATION_TRUST_ACCOUNT;

		container_dn = ldb_dn_copy(msg, ldb_get_default_basedn(ldb));
		if (container_dn == NULL) {
			ldb_transaction_cancel(ldb);
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		if (!ldb_dn_add_child_fmt(container_dn, "%s", container)) {
			ldb_transaction_cancel(ldb);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}

		status = dsdb_add_machine_is_privileged(tmp_ctx, ldb, container_dn,
							&machine_account_privilege);
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			if (!machine_account_privilege) {
				ldb_transaction_cancel(ldb);
				talloc_free(tmp_ctx);
				return NT_STATUS_ACCESS_DENIED;
			}

			/* Check quota for privileged operation */
			status = dsdb_add_machine_privileged_check_quota(tmp_ctx, ldb);
			if (NT_STATUS_IS_ERR(status)) {
				ldb_transaction_cancel(ldb);
				talloc_free(tmp_ctx);
				return status;
			}
		} else if (NT_STATUS_IS_ERR(status)) {
			ldb_transaction_cancel(ldb);
			talloc_free(tmp_ctx);
			return status;
		}
	} else if (acct_flags == ACB_SVRTRUST) {
		if (cn_name[cn_name_len - 1] != '$') {
			ldb_transaction_cancel(ldb);
			return NT_STATUS_FOOBAR;
		}
		cn_name[cn_name_len - 1] = '\0';
		container = "OU=Domain Controllers";
		obj_class = "computer";
		user_account_control = UF_SERVER_TRUST_ACCOUNT;
	} else if (acct_flags == ACB_DOMTRUST) {
		DEBUG(3, ("Invalid account flags specified:  cannot create domain trusts via this interface (must use LSA CreateTrustedDomain calls\n"));
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	} else {
		DEBUG(3, ("Invalid account flags specified 0x%08X, must be exactly one of \n"
			  "ACB_NORMAL (0x%08X) ACB_WSTRUST (0x%08X) or ACB_SVRTRUST (0x%08X)\n",
			  acct_flags,
			  ACB_NORMAL, ACB_WSTRUST, ACB_SVRTRUST));
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_account_control |= UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD;

	/* add core elements to the ldb_message for the user */
	msg->dn = ldb_dn_copy(msg, ldb_get_default_basedn(ldb));
	if ( ! ldb_dn_add_child_fmt(msg->dn, "CN=%s,%s", cn_name, container)) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_FOOBAR;
	}

	ldb_msg_add_string(msg, "sAMAccountName", account_name);
	ldb_msg_add_string(msg, "objectClass", obj_class);
	samdb_msg_add_uint(ldb, tmp_ctx, msg,
			   "userAccountControl",
			   user_account_control);

	/* This is only here for migrations using pdb_samba4, the
	 * caller and the samldb are responsible for ensuring it makes
	 * sense */
	if (forced_sid) {
		ret = samdb_msg_add_dom_sid(ldb, msg, msg, "objectSID", forced_sid);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(ldb);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	ret = ldb_msg_sanity_check(ldb, msg);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = ldb_build_add_req(&req, ldb, tmp_ctx, msg, NULL, NULL,
				ldb_op_default_callback, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (machine_account_privilege) {
		struct auth_session_info *sinfo = NULL;
		struct dom_sid *creator_sid = NULL;
		DATA_BLOB data;
		enum ndr_err_code ndr_err;

		sinfo = talloc_get_type_abort(ldb_get_opaque(ldb, "sessionInfo"), struct auth_session_info);

		/* Add msDS-Creator-Sid to message */
		creator_sid = &sinfo->security_token->sids[0];
		ndr_err = ndr_push_struct_blob(&data, mem_ctx, creator_sid,
					       (ndr_push_flags_fn_t)ndr_push_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			ldb_transaction_cancel(ldb);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}
		ret = ldb_msg_add_value(msg, "mS-DS-CreatorSID", &data, NULL);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(ldb);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	control = talloc_zero(tmp_ctx, struct dsdb_control_samr_create_user);
	if (control == NULL) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	control->account_type = acct_flags;

	ret = ldb_request_add_control(req, DSDB_CONTROL_SAMR_CREATE_USER_OID, false, control);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* create the user */
	ret = ldb_request(ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}
	talloc_free(req);

	switch (ret) {
	case LDB_SUCCESS:
		break;
	case LDB_ERR_ENTRY_ALREADY_EXISTS:
		ldb_transaction_cancel(ldb);
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_USER_EXISTS;
	case LDB_ERR_UNWILLING_TO_PERFORM:
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		ldb_transaction_cancel(ldb);
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_ACCESS_DENIED;
	default:
		ldb_transaction_cancel(ldb);
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	account_dn = msg->dn;

	if (machine_account_privilege) {
		NTSTATUS status;
		status = dsdb_add_machine_privileged_set_sd(tmp_ctx, ldb,
							    account_dn);
		if (NT_STATUS_IS_ERR(status)) {
			ldb_transaction_cancel(ldb);
			talloc_free(tmp_ctx);
			return status;
		}
	}

	/* retrieve the sid and account control bits for the user just created */
	ret = dsdb_search_one(ldb, tmp_ctx, &msg,
			      account_dn, LDB_SCOPE_BASE, attrs, 0, NULL);

	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(ldb);
		DEBUG(0,("Can't locate the account we just created %s: %s\n",
			 ldb_dn_get_linearized(account_dn), ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	account_sid = samdb_result_dom_sid(tmp_ctx, msg, "objectSid");
	if (account_sid == NULL) {
		ldb_transaction_cancel(ldb);
		DEBUG(0,("Apparently we failed to get the objectSid of the just created account record %s\n",
			 ldb_dn_get_linearized(msg->dn)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to commit transaction to add and modify account record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	*dn = talloc_steal(mem_ctx, account_dn);
	if (sid) {
		*sid = talloc_steal(mem_ctx, account_sid);
	}
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/*
  called by samr_CreateDomainGroup and pdb_samba4
*/
NTSTATUS dsdb_add_domain_group(struct ldb_context *ldb,
			       TALLOC_CTX *mem_ctx,
			       const char *groupname,
			       struct dom_sid **sid,
			       struct ldb_dn **dn)
{
	const char *name;
	struct ldb_message *msg;
	struct dom_sid *group_sid;
	int ret;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	/* check if the group already exists */
	name = samdb_search_string(ldb, tmp_ctx, NULL,
				   "sAMAccountName",
				   "(&(sAMAccountName=%s)(objectclass=group))",
				   ldb_binary_encode_string(tmp_ctx, groupname));
	if (name != NULL) {
		return NT_STATUS_GROUP_EXISTS;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* add core elements to the ldb_message for the user */
	msg->dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(ldb));
	ldb_dn_add_child_fmt(msg->dn, "CN=%s,CN=Users", groupname);
	if (!msg->dn) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	ldb_msg_add_string(msg, "sAMAccountName", groupname);
	ldb_msg_add_string(msg, "objectClass", "group");

	/* create the group */
	ret = ldb_add(ldb, msg);
	switch (ret) {
	case  LDB_SUCCESS:
		break;
	case  LDB_ERR_ENTRY_ALREADY_EXISTS:
		DEBUG(0,("Failed to create group record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_GROUP_EXISTS;
	case  LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		DEBUG(0,("Failed to create group record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_ACCESS_DENIED;
	default:
		DEBUG(0,("Failed to create group record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* retrieve the sid for the group just created */
	group_sid = samdb_search_dom_sid(ldb, tmp_ctx,
					 msg->dn, "objectSid", NULL);
	if (group_sid == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	*dn = talloc_steal(mem_ctx, msg->dn);
	*sid = talloc_steal(mem_ctx, group_sid);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

NTSTATUS dsdb_add_domain_alias(struct ldb_context *ldb,
			       TALLOC_CTX *mem_ctx,
			       const char *alias_name,
			       struct dom_sid **sid,
			       struct ldb_dn **dn)
{
	const char *name;
	struct ldb_message *msg;
	struct dom_sid *alias_sid;
	int ret;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	if (ldb_transaction_start(ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Failed to start transaction in dsdb_add_domain_alias(): %s\n", ldb_errstring(ldb)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* Check if alias already exists */
	name = samdb_search_string(ldb, tmp_ctx, NULL,
				   "sAMAccountName",
				   "(sAMAccountName=%s)(objectclass=group))",
				   ldb_binary_encode_string(mem_ctx, alias_name));

	if (name != NULL) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(ldb);
		return NT_STATUS_ALIAS_EXISTS;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(ldb);
		return NT_STATUS_NO_MEMORY;
	}

	/* add core elements to the ldb_message for the alias */
	msg->dn = ldb_dn_copy(mem_ctx, ldb_get_default_basedn(ldb));
	ldb_dn_add_child_fmt(msg->dn, "CN=%s,CN=Users", alias_name);
	if (!msg->dn) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(ldb);
		return NT_STATUS_NO_MEMORY;
	}

	ldb_msg_add_string(msg, "sAMAccountName", alias_name);
	ldb_msg_add_string(msg, "objectClass", "group");
	samdb_msg_add_int(ldb, mem_ctx, msg, "groupType", GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);

	/* create the alias */
	ret = ldb_add(ldb, msg);
	switch (ret) {
	case LDB_SUCCESS:
		break;
	case LDB_ERR_ENTRY_ALREADY_EXISTS:
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(ldb);
		return NT_STATUS_ALIAS_EXISTS;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(ldb);
		return NT_STATUS_ACCESS_DENIED;
	default:
		DEBUG(0,("Failed to create alias record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(ldb)));
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(ldb);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* retrieve the sid for the alias just created */
	alias_sid = samdb_search_dom_sid(ldb, tmp_ctx,
					 msg->dn, "objectSid", NULL);

	if (ldb_transaction_commit(ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Failed to commit transaction in dsdb_add_domain_alias(): %s\n",
			  ldb_errstring(ldb)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	*dn = talloc_steal(mem_ctx, msg->dn);
	*sid = talloc_steal(mem_ctx, alias_sid);
	talloc_free(tmp_ctx);


	return NT_STATUS_OK;
}

/* Return the members of this group (which may be a domain group or an alias) */
NTSTATUS dsdb_enum_group_mem(struct ldb_context *ldb,
			     TALLOC_CTX *mem_ctx,
			     struct ldb_dn *dn,
			     struct dom_sid **members_out,
			     unsigned int *pnum_members)
{
	struct ldb_message *msg;
	unsigned int i, j;
	int ret;
	struct dom_sid *members;
	struct ldb_message_element *member_el;
	const char *attrs[] = { "member", NULL };
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	ret = dsdb_search_one(ldb, tmp_ctx, &msg, dn, LDB_SCOPE_BASE, attrs,
			      DSDB_SEARCH_SHOW_EXTENDED_DN, NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("dsdb_enum_group_mem: dsdb_search for %s failed: %s\n",
			  ldb_dn_get_linearized(dn), ldb_errstring(ldb)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	member_el = ldb_msg_find_element(msg, "member");
	if (!member_el) {
		*members_out = NULL;
		*pnum_members = 0;
		talloc_free(tmp_ctx);
		return NT_STATUS_OK;
	}

	members = talloc_array(mem_ctx, struct dom_sid, member_el->num_values);
	if (members == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	j = 0;
	for (i=0; i <member_el->num_values; i++) {
		struct ldb_dn *member_dn = ldb_dn_from_ldb_val(tmp_ctx, ldb,
							       &member_el->values[i]);
		if (!member_dn || !ldb_dn_validate(member_dn)) {
			DEBUG(1, ("Could not parse %*.*s as a DN\n",
				  (int)member_el->values[i].length,
				  (int)member_el->values[i].length,
				  (const char *)member_el->values[i].data));
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		status = dsdb_get_extended_dn_sid(member_dn, &members[j],
						  "SID");
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			/* If we fail finding a SID then this is no error since
			 * it could be a non SAM object - e.g. a contact */
			continue;
		} else if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("When parsing DN '%s' we failed to parse it's SID component, so we cannot fetch the membership: %s\n",
				  ldb_dn_get_extended_linearized(tmp_ctx, member_dn, 1),
				  nt_errstr(status)));
			talloc_free(tmp_ctx);
			return status;
		}

		++j;
	}

	*members_out = talloc_steal(mem_ctx, members);
	*pnum_members = j;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

NTSTATUS dsdb_lookup_rids(struct ldb_context *ldb,
			  TALLOC_CTX *mem_ctx,
			  const struct dom_sid *domain_sid,
			  unsigned int num_rids,
			  uint32_t *rids,
			  const char **names,
			  enum lsa_SidType *lsa_attrs)
{
	const char *attrs[] = { "sAMAccountType", "sAMAccountName", NULL };
	unsigned int i, num_mapped;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	num_mapped = 0;

	for (i=0; i<num_rids; i++) {
		struct ldb_message *msg;
		struct ldb_dn *dn;
		uint32_t attr;
		int rc;

		lsa_attrs[i] = SID_NAME_UNKNOWN;

		dn = ldb_dn_new_fmt(tmp_ctx, ldb, "<SID=%s>",
				    dom_sid_string(tmp_ctx,
						   dom_sid_add_rid(tmp_ctx, domain_sid,
								   rids[i])));
		if (dn == NULL) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		rc = dsdb_search_one(ldb, tmp_ctx, &msg, dn, LDB_SCOPE_BASE, attrs, 0, "samAccountName=*");
		if (rc == LDB_ERR_NO_SUCH_OBJECT) {
			continue;
		} else if (rc != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		names[i] = ldb_msg_find_attr_as_string(msg, "samAccountName", NULL);
		if (names[i] == NULL) {
			DEBUG(10, ("no samAccountName\n"));
			continue;
		}
		talloc_steal(names, names[i]);
		attr = ldb_msg_find_attr_as_uint(msg, "samAccountType", 0);
		lsa_attrs[i] = ds_atype_map(attr);
		if (lsa_attrs[i] == SID_NAME_UNKNOWN) {
			continue;
		}
		num_mapped += 1;
	}
	talloc_free(tmp_ctx);

	if (num_mapped == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	if (num_mapped < num_rids) {
		return STATUS_SOME_UNMAPPED;
	}
	return NT_STATUS_OK;
}

