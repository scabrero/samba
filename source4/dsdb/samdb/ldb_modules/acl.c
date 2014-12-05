/*
  ldb database library

  Copyright (C) Simo Sorce 2006-2008
  Copyright (C) Nadezhda Ivanova 2009
  Copyright (C) Anatoliy Atanasov  2009

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

/*
 *  Name: ldb
 *
 *  Component: ldb ACL module
 *
 *  Description: Module that performs authorisation access checks based on the
 *               account's security context and the DACL of the object being polled.
 *               Only DACL checks implemented at this point
 *
 *  Authors: Nadezhda Ivanova, Anatoliy Atanasov
 */

#include "includes.h"
#include "ldb_module.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/util/tsort.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "libcli/ldap/ldap_ndr.h"
#include "ldb_private.h"

struct extended_access_check_attribute {
	const char *oa_name;
	const uint32_t requires_rights;
};

struct acl_private {
	bool acl_search;
	const char **password_attrs;
	void *cached_schema_ptr;
	uint64_t cached_schema_metadata_usn;
	uint64_t cached_schema_loaded_usn;
	const char **confidential_attrs;
};

struct acl_context {
	struct ldb_module *module;
	struct ldb_request *req;
	bool am_system;
	bool am_administrator;
	bool modify_search;
	bool constructed_attrs;
	bool allowedAttributes;
	bool allowedAttributesEffective;
	bool allowedChildClasses;
	bool allowedChildClassesEffective;
	bool sDRightsEffective;
	bool userPassword;
	const char * const *attrs;
	struct dsdb_schema *schema;
};

static int acl_module_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct acl_private *data;
	int ret;
	unsigned int i, n, j;
	TALLOC_CTX *mem_ctx;
	static const char * const attrs[] = { "passwordAttribute", NULL };
	static const char * const secret_attrs[] = {
		DSDB_SECRET_ATTRIBUTES
	};
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *password_attributes;

	ldb = ldb_module_get_ctx(module);

	ret = ldb_mod_register_control(module, LDB_CONTROL_SD_FLAGS_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "acl_module_init: Unable to register control with rootdse!\n");
		return ldb_operr(ldb);
	}

	data = talloc_zero(module, struct acl_private);
	if (data == NULL) {
		return ldb_oom(ldb);
	}

	data->acl_search = lpcfg_parm_bool(ldb_get_opaque(ldb, "loadparm"),
					NULL, "acl", "search", true);
	ldb_module_set_private(module, data);

	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		return ldb_oom(ldb);
	}

	ret = dsdb_module_search_dn(module, mem_ctx, &res,
				    ldb_dn_new(mem_ctx, ldb, "@KLUDGEACL"),
				    attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM,
				    NULL);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	if (res->count == 0) {
		goto done;
	}

	if (res->count > 1) {
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	msg = res->msgs[0];

	password_attributes = ldb_msg_find_element(msg, "passwordAttribute");
	if (!password_attributes) {
		goto done;
	}
	data->password_attrs = talloc_array(data, const char *,
			password_attributes->num_values +
			ARRAY_SIZE(secret_attrs) + 1);
	if (!data->password_attrs) {
		talloc_free(mem_ctx);
		return ldb_oom(ldb);
	}

	n = 0;
	for (i=0; i < password_attributes->num_values; i++) {
		data->password_attrs[n] = (const char *)password_attributes->values[i].data;
		talloc_steal(data->password_attrs, password_attributes->values[i].data);
		n++;
	}

	for (i=0; i < ARRAY_SIZE(secret_attrs); i++) {
		bool found = false;

		for (j=0; j < n; j++) {
			if (strcasecmp(data->password_attrs[j], secret_attrs[i]) == 0) {
				found = true;
				break;
			}
		}

		if (found) {
			continue;
		}

		data->password_attrs[n] = talloc_strdup(data->password_attrs,
							secret_attrs[i]);
		if (data->password_attrs[n] == NULL) {
			talloc_free(mem_ctx);
			return ldb_oom(ldb);
		}
		n++;
	}
	data->password_attrs[n] = NULL;

done:
	talloc_free(mem_ctx);
	return ldb_next_init(module);
}

static int acl_allowedAttributes(struct ldb_module *module,
				 const struct dsdb_schema *schema,
				 struct ldb_message *sd_msg,
				 struct ldb_message *msg,
				 struct acl_context *ac)
{
	struct ldb_message_element *oc_el;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *mem_ctx;
	const char **attr_list;
	int i, ret;
	const struct dsdb_class *objectclass;

	/* If we don't have a schema yet, we can't do anything... */
	if (schema == NULL) {
		ldb_asprintf_errstring(ldb, "cannot add allowedAttributes to %s because no schema is loaded", ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Must remove any existing attribute */
	if (ac->allowedAttributes) {
		ldb_msg_remove_attr(msg, "allowedAttributes");
	}

	mem_ctx = talloc_new(msg);
	if (!mem_ctx) {
		return ldb_oom(ldb);
	}

	oc_el = ldb_msg_find_element(sd_msg, "objectClass");
	attr_list = dsdb_full_attribute_list(mem_ctx, schema, oc_el, DSDB_SCHEMA_ALL);
	if (!attr_list) {
		ldb_asprintf_errstring(ldb, "acl: Failed to get list of attributes");
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Get the top-most structural object class for the ACL check
	 */
	objectclass = dsdb_get_last_structural_class(ac->schema,
						     oc_el);
	if (objectclass == NULL) {
		ldb_asprintf_errstring(ldb, "acl_read: Failed to find a structural class for %s",
				       ldb_dn_get_linearized(sd_msg->dn));
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ac->allowedAttributes) {
		for (i=0; attr_list && attr_list[i]; i++) {
			ldb_msg_add_string(msg, "allowedAttributes", attr_list[i]);
		}
	}
	if (ac->allowedAttributesEffective) {
		struct security_descriptor *sd;
		struct dom_sid *sid = NULL;
		struct ldb_control *as_system = ldb_request_get_control(ac->req,
									LDB_CONTROL_AS_SYSTEM_OID);

		if (as_system != NULL) {
			as_system->critical = 0;
		}

		ldb_msg_remove_attr(msg, "allowedAttributesEffective");
		if (ac->am_system || as_system) {
			for (i=0; attr_list && attr_list[i]; i++) {
				ldb_msg_add_string(msg, "allowedAttributesEffective", attr_list[i]);
			}
			return LDB_SUCCESS;
		}

		ret = dsdb_get_sd_from_ldb_message(ldb_module_get_ctx(module), mem_ctx, sd_msg, &sd);

		if (ret != LDB_SUCCESS) {
			return ret;
		}

		sid = samdb_result_dom_sid(mem_ctx, sd_msg, "objectSid");
		for (i=0; attr_list && attr_list[i]; i++) {
			const struct dsdb_attribute *attr = dsdb_attribute_by_lDAPDisplayName(schema,
											attr_list[i]);
			if (!attr) {
				return ldb_operr(ldb);
			}
			/* remove constructed attributes */
			if (attr->systemFlags & DS_FLAG_ATTR_IS_CONSTRUCTED
			    || attr->systemOnly
			    || (attr->linkID != 0 && attr->linkID % 2 != 0 )) {
				continue;
			}
			ret = acl_check_access_on_attribute(module,
							    msg,
							    sd,
							    sid,
							    SEC_ADS_WRITE_PROP,
							    attr,
							    objectclass);
			if (ret == LDB_SUCCESS) {
				ldb_msg_add_string(msg, "allowedAttributesEffective", attr_list[i]);
			}
		}
	}
	return LDB_SUCCESS;
}

static int acl_childClasses(struct ldb_module *module,
			    const struct dsdb_schema *schema,
			    struct ldb_message *sd_msg,
			    struct ldb_message *msg,
			    const char *attrName)
{
	struct ldb_message_element *oc_el;
	struct ldb_message_element *allowedClasses;
	const struct dsdb_class *sclass;
	unsigned int i, j;
	int ret;

	/* If we don't have a schema yet, we can't do anything... */
	if (schema == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), "cannot add childClassesEffective to %s because no schema is loaded", ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Must remove any existing attribute, or else confusion reins */
	ldb_msg_remove_attr(msg, attrName);
	ret = ldb_msg_add_empty(msg, attrName, 0, &allowedClasses);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	oc_el = ldb_msg_find_element(sd_msg, "objectClass");

	for (i=0; oc_el && i < oc_el->num_values; i++) {
		sclass = dsdb_class_by_lDAPDisplayName_ldb_val(schema, &oc_el->values[i]);
		if (!sclass) {
			/* We don't know this class?  what is going on? */
			continue;
		}

		for (j=0; sclass->possibleInferiors && sclass->possibleInferiors[j]; j++) {
			ldb_msg_add_string(msg, attrName, sclass->possibleInferiors[j]);
		}
	}
	if (allowedClasses->num_values > 1) {
		TYPESAFE_QSORT(allowedClasses->values, allowedClasses->num_values, data_blob_cmp);
		for (i=1 ; i < allowedClasses->num_values; i++) {
			struct ldb_val *val1 = &allowedClasses->values[i-1];
			struct ldb_val *val2 = &allowedClasses->values[i];
			if (data_blob_cmp(val1, val2) == 0) {
				memmove(val1, val2, (allowedClasses->num_values - i) * sizeof(struct ldb_val));
				allowedClasses->num_values--;
				i--;
			}
		}
	}

	return LDB_SUCCESS;
}

static int acl_childClassesEffective(struct ldb_module *module,
				     const struct dsdb_schema *schema,
				     struct ldb_message *sd_msg,
				     struct ldb_message *msg,
				     struct acl_context *ac)
{
	struct ldb_message_element *oc_el;
	struct ldb_message_element *allowedClasses = NULL;
	const struct dsdb_class *sclass;
	struct security_descriptor *sd;
	struct ldb_control *as_system = ldb_request_get_control(ac->req,
								LDB_CONTROL_AS_SYSTEM_OID);
	struct dom_sid *sid = NULL;
	unsigned int i, j;
	int ret;

	if (as_system != NULL) {
		as_system->critical = 0;
	}

	if (ac->am_system || as_system) {
		return acl_childClasses(module, schema, sd_msg, msg, "allowedChildClassesEffective");
	}

	/* If we don't have a schema yet, we can't do anything... */
	if (schema == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module), "cannot add allowedChildClassesEffective to %s because no schema is loaded", ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Must remove any existing attribute, or else confusion reins */
	ldb_msg_remove_attr(msg, "allowedChildClassesEffective");

	oc_el = ldb_msg_find_element(sd_msg, "objectClass");
	ret = dsdb_get_sd_from_ldb_message(ldb_module_get_ctx(module), msg, sd_msg, &sd);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	sid = samdb_result_dom_sid(msg, sd_msg, "objectSid");
	for (i=0; oc_el && i < oc_el->num_values; i++) {
		sclass = dsdb_class_by_lDAPDisplayName_ldb_val(schema, &oc_el->values[i]);
		if (!sclass) {
			/* We don't know this class?  what is going on? */
			continue;
		}

		for (j=0; sclass->possibleInferiors && sclass->possibleInferiors[j]; j++) {
			const struct dsdb_class *sc;

			sc = dsdb_class_by_lDAPDisplayName(schema,
							   sclass->possibleInferiors[j]);
			if (!sc) {
				/* We don't know this class?  what is going on? */
				continue;
			}

			ret = acl_check_access_on_objectclass(module, ac,
							      sd, sid,
							      SEC_ADS_CREATE_CHILD,
							      sc);
			if (ret == LDB_SUCCESS) {
				ldb_msg_add_string(msg, "allowedChildClassesEffective",
						   sclass->possibleInferiors[j]);
			}
		}
	}
	allowedClasses = ldb_msg_find_element(msg, "allowedChildClassesEffective");
	if (!allowedClasses) {
		return LDB_SUCCESS;
	}

	if (allowedClasses->num_values > 1) {
		TYPESAFE_QSORT(allowedClasses->values, allowedClasses->num_values, data_blob_cmp);
		for (i=1 ; i < allowedClasses->num_values; i++) {
			struct ldb_val *val1 = &allowedClasses->values[i-1];
			struct ldb_val *val2 = &allowedClasses->values[i];
			if (data_blob_cmp(val1, val2) == 0) {
				memmove(val1, val2, (allowedClasses->num_values - i) * sizeof( struct ldb_val));
				allowedClasses->num_values--;
				i--;
			}
		}
	}
	return LDB_SUCCESS;
}

static int acl_sDRightsEffective(struct ldb_module *module,
				 struct ldb_message *sd_msg,
				 struct ldb_message *msg,
				 struct acl_context *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message_element *rightsEffective;
	int ret;
	struct security_descriptor *sd;
	struct ldb_control *as_system = ldb_request_get_control(ac->req,
								LDB_CONTROL_AS_SYSTEM_OID);
	struct dom_sid *sid = NULL;
	uint32_t flags = 0;

	if (as_system != NULL) {
		as_system->critical = 0;
	}

	/* Must remove any existing attribute, or else confusion reins */
	ldb_msg_remove_attr(msg, "sDRightsEffective");
	ret = ldb_msg_add_empty(msg, "sDRightsEffective", 0, &rightsEffective);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ac->am_system || as_system) {
		flags = SECINFO_OWNER | SECINFO_GROUP |  SECINFO_SACL |  SECINFO_DACL;
	} else {
		const struct dsdb_class *objectclass;
		const struct dsdb_attribute *attr;

		objectclass = dsdb_get_structural_oc_from_msg(ac->schema, sd_msg);
		if (objectclass == NULL) {
			return ldb_operr(ldb);
		}

		attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
							 "nTSecurityDescriptor");
		if (attr == NULL) {
			return ldb_operr(ldb);
		}

		/* Get the security descriptor from the message */
		ret = dsdb_get_sd_from_ldb_message(ldb, msg, sd_msg, &sd);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		sid = samdb_result_dom_sid(msg, sd_msg, "objectSid");
		ret = acl_check_access_on_attribute(module,
						    msg,
						    sd,
						    sid,
						    SEC_STD_WRITE_OWNER,
						    attr,
						    objectclass);
		if (ret == LDB_SUCCESS) {
			flags |= SECINFO_OWNER | SECINFO_GROUP;
		}
		ret = acl_check_access_on_attribute(module,
						    msg,
						    sd,
						    sid,
						    SEC_STD_WRITE_DAC,
						    attr,
						    objectclass);
		if (ret == LDB_SUCCESS) {
			flags |= SECINFO_DACL;
		}
		ret = acl_check_access_on_attribute(module,
						    msg,
						    sd,
						    sid,
						    SEC_FLAG_SYSTEM_SECURITY,
						    attr,
						    objectclass);
		if (ret == LDB_SUCCESS) {
			flags |= SECINFO_SACL;
		}
	}
	return samdb_msg_add_uint(ldb_module_get_ctx(module), msg, msg,
				  "sDRightsEffective", flags);
}

static int acl_validate_spn_value(TALLOC_CTX *mem_ctx,
				  struct ldb_context *ldb,
				  const char *spn_value,
				  uint32_t userAccountControl,
				  const char *samAccountName,
				  const char *dnsHostName,
				  const char *netbios_name,
				  const char *ntds_guid)
{
	int ret;
	krb5_context krb_ctx;
	krb5_error_code kerr;
	krb5_principal principal;
	char *instanceName;
	char *serviceType;
	char *serviceName;
	const char *forest_name = samdb_forest_name(ldb, mem_ctx);
	const char *base_domain = samdb_default_domain_name(ldb, mem_ctx);
	struct loadparm_context *lp_ctx = talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
							  struct loadparm_context);
	bool is_dc = (userAccountControl & UF_SERVER_TRUST_ACCOUNT) ||
		(userAccountControl & UF_PARTIAL_SECRETS_ACCOUNT);

	if (strcasecmp_m(spn_value, samAccountName) == 0) {
		/* MacOS X sets this value, and setting an SPN of your
		 * own samAccountName is both pointless and safe */
		return LDB_SUCCESS;
	}

	kerr = smb_krb5_init_context_basic(mem_ctx,
					   lp_ctx,
					   &krb_ctx);
	if (kerr != 0) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "Could not initialize kerberos context.");
	}

	ret = krb5_parse_name(krb_ctx, spn_value, &principal);
	if (ret) {
		krb5_free_context(krb_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (krb5_princ_size(krb_ctx, principal) < 2) {
		goto fail;
	}

	instanceName = smb_krb5_principal_get_comp_string(mem_ctx, krb_ctx,
							  principal, 1);
	serviceType = smb_krb5_principal_get_comp_string(mem_ctx, krb_ctx,
							 principal, 0);
	if (krb5_princ_size(krb_ctx, principal) == 3) {
		serviceName = smb_krb5_principal_get_comp_string(mem_ctx, krb_ctx,
								 principal, 2);
	} else {
		serviceName = NULL;
	}

	if (serviceName) {
		if (!is_dc) {
			goto fail;
		}
		if (strcasecmp(serviceType, "ldap") == 0) {
			if (strcasecmp(serviceName, netbios_name) != 0 &&
			    strcasecmp(serviceName, forest_name) != 0) {
				goto fail;
			}

		} else if (strcasecmp(serviceType, "gc") == 0) {
			if (strcasecmp(serviceName, forest_name) != 0) {
				goto fail;
			}
		} else {
			if (strcasecmp(serviceName, base_domain) != 0 &&
			    strcasecmp(serviceName, netbios_name) != 0) {
				goto fail;
			}
		}
	}
	/* instanceName can be samAccountName without $ or dnsHostName
	 * or "ntds_guid._msdcs.forest_domain for DC objects */
	if (strlen(instanceName) == (strlen(samAccountName) - 1)
	    && strncasecmp(instanceName, samAccountName, strlen(samAccountName) - 1) == 0) {
		goto success;
	} else if (dnsHostName != NULL && strcasecmp(instanceName, dnsHostName) == 0) {
		goto success;
	} else if (is_dc) {
		const char *guid_str;
		guid_str = talloc_asprintf(mem_ctx,"%s._msdcs.%s",
					   ntds_guid,
					   forest_name);
		if (strcasecmp(instanceName, guid_str) == 0) {
			goto success;
		}
	}

fail:
	krb5_free_principal(krb_ctx, principal);
	krb5_free_context(krb_ctx);
	return LDB_ERR_CONSTRAINT_VIOLATION;

success:
	krb5_free_principal(krb_ctx, principal);
	krb5_free_context(krb_ctx);
	return LDB_SUCCESS;
}

static int acl_check_spn(TALLOC_CTX *mem_ctx,
			 struct ldb_module *module,
			 struct ldb_request *req,
			 struct security_descriptor *sd,
			 struct dom_sid *sid,
			 const struct dsdb_attribute *attr,
			 const struct dsdb_class *objectclass)
{
	int ret;
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *acl_res;
	struct ldb_result *netbios_res;
	struct ldb_message_element *el;
	struct ldb_dn *partitions_dn = samdb_partitions_dn(ldb, tmp_ctx);
	uint32_t userAccountControl;
	const char *samAccountName;
	const char *dnsHostName;
	const char *netbios_name;
	struct GUID ntds;
	char *ntds_guid = NULL;

	static const char *acl_attrs[] = {
		"samAccountName",
		"dnsHostName",
		"userAccountControl",
		NULL
	};
	static const char *netbios_attrs[] = {
		"nETBIOSName",
		NULL
	};

	/* if we have wp, we can do whatever we like */
	if (acl_check_access_on_attribute(module,
					  tmp_ctx,
					  sd,
					  sid,
					  SEC_ADS_WRITE_PROP,
					  attr, objectclass) == LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	ret = acl_check_extended_right(tmp_ctx, sd, acl_user_token(module),
				       GUID_DRS_VALIDATE_SPN,
				       SEC_ADS_SELF_WRITE,
				       sid);

	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		dsdb_acl_debug(sd, acl_user_token(module),
			       req->op.mod.message->dn,
			       true,
			       10);
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_module_search_dn(module, tmp_ctx,
				    &acl_res, req->op.mod.message->dn,
				    acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED,
				    req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	userAccountControl = ldb_msg_find_attr_as_uint(acl_res->msgs[0], "userAccountControl", 0);

	el = ldb_msg_find_element(req->op.mod.message, "samAccountName");
	if (el) {
		samAccountName = ldb_msg_find_attr_as_string(req->op.mod.message, "samAccountName", NULL);
	} else {
		samAccountName = ldb_msg_find_attr_as_string(acl_res->msgs[0], "samAccountName", NULL);
	}

	el = ldb_msg_find_element(req->op.mod.message, "dnsHostName");
	if (el) {
		dnsHostName = ldb_msg_find_attr_as_string(req->op.mod.message, "dnsHostName", NULL);
	} else {
		dnsHostName = ldb_msg_find_attr_as_string(acl_res->msgs[0], "dnsHostName", NULL);
	}

	ret = dsdb_module_search(module, tmp_ctx,
				 &netbios_res, partitions_dn,
				 LDB_SCOPE_ONELEVEL,
				 netbios_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM,
				 req,
				 "(ncName=%s)",
				 ldb_dn_get_linearized(ldb_get_default_basedn(ldb)));

	netbios_name = ldb_msg_find_attr_as_string(netbios_res->msgs[0], "nETBIOSName", NULL);

	el = ldb_msg_find_element(req->op.mod.message, "servicePrincipalName");
	if (!el) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
					 "Error finding element for servicePrincipalName.");
	}

	/* NTDSDSA objectGuid of object we are checking SPN for */
	if (userAccountControl & (UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)) {
		ret = dsdb_module_find_ntdsguid_for_computer(module, tmp_ctx,
							     req->op.mod.message->dn, &ntds, req);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "Failed to find NTDSDSA objectGuid for %s: %s",
					       ldb_dn_get_linearized(req->op.mod.message->dn),
					       ldb_strerror(ret));
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ntds_guid = GUID_string(tmp_ctx, &ntds);
	}

	for (i=0; i < el->num_values; i++) {
		ret = acl_validate_spn_value(tmp_ctx,
					     ldb,
					     (char *)el->values[i].data,
					     userAccountControl,
					     samAccountName,
					     dnsHostName,
					     netbios_name,
					     ntds_guid);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
	}
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

static int acl_check_dnshostname(TALLOC_CTX *mem_ctx,
			 struct ldb_module *module,
			 struct ldb_request *req,
			 struct security_descriptor *sd,
			 struct dom_sid *sid,
			 const struct dsdb_attribute *attr,
			 const struct dsdb_class *objectclass)
{
	int ret;
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *acl_res;
	struct ldb_result *partition_res;
	struct ldb_message_element *el;
	struct ldb_dn *partitions_dn = samdb_partitions_dn(ldb, tmp_ctx);
	char *samAccountName;

	static const char *acl_attrs[] = {
		"samAccountName",
		NULL
	};
	static const char *dnssuffixes_attrs[] = {
		"msDS-AllowedDNSSuffixes",
		NULL
	};
	struct ldb_dn *domain_nc;
	const char *domain_dns_name;
	const char *value_to_write;
	char *value_to_check, *p;

	/* if we have wp, we can do whatever we like */
	if (acl_check_access_on_attribute(module,
					  tmp_ctx,
					  sd,
					  sid,
					  SEC_ADS_WRITE_PROP,
					  attr, objectclass) == LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	ret = acl_check_extended_right(tmp_ctx, sd, acl_user_token(module),
				       GUID_DRS_DNS_HOST_NAME,
				       SEC_ADS_SELF_WRITE,
				       sid);

	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		dsdb_acl_debug(sd, acl_user_token(module),
			       req->op.mod.message->dn,
			       true,
			       10);
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_module_search_dn(module, tmp_ctx,
				    &acl_res, req->op.mod.message->dn,
				    acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED,
				    req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Get the value being written */
	value_to_write = ldb_msg_find_attr_as_string(req->op.mod.message, "dNSHostName", NULL);

	/* The object has class computer or server (or a subclass of them) */

	/* The value being written must have the following format:
	 * computerName.fullDomainDnsName, where computerName is the current
	 * sAMAccountName of the object (without the final "$" character),
	 * and the fullDomainDnsName is the DNS name of the domain NC or one
	 * of the values of msDS-AllowedDNSSuffixes on the domain NC (if any)
	 * where the object that is being modified is located
	 */
	el = ldb_msg_find_element(req->op.mod.message, "samAccountName");
	if (el) {
		samAccountName = talloc_strdup(tmp_ctx, ldb_msg_find_attr_as_string(req->op.mod.message, "samAccountName", NULL));
	} else {
		samAccountName = talloc_strdup(tmp_ctx, ldb_msg_find_attr_as_string(acl_res->msgs[0], "samAccountName", NULL));
	}
	if (samAccountName == NULL) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "Error finding element samAccountName");
	}
	p = strrchr(samAccountName, '$');
	if (p) {
		*p = '\0';
	}

	/* Check the current domain dns */
	domain_nc = ldb_get_default_basedn(ldb);
	domain_dns_name = samdb_dn_to_dns_domain(tmp_ctx, domain_nc);
	value_to_check = talloc_asprintf(tmp_ctx, "%s.%s", samAccountName, domain_dns_name);
	if (strcasecmp(value_to_write, value_to_check) == 0) {
		goto success;
	}

	/* Check the dns allowed suffixes */
	ret = dsdb_module_search(module, tmp_ctx,
				 &partition_res, partitions_dn,
				 LDB_SCOPE_ONELEVEL,
				 dnssuffixes_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM,
				 req,
				 "(ncName=%s)",
				 ldb_dn_get_linearized(domain_nc));
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "Error finding domain partition");
	}

	el = ldb_msg_find_element(partition_res->msgs[0], "msDS-AllowedDNSSuffixes");
	if (el == NULL) {
		goto fail;
	}

	for (i=0; i<el->num_values; i++) {
		value_to_check = talloc_asprintf(tmp_ctx, "%s.%s",
						 samAccountName,
						 (char *)el->values[i].data);
		if (strcasecmp(value_to_write, value_to_check) == 0) {
			goto success;
		}
	}

success:
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
fail:
	talloc_free(tmp_ctx);
	return LDB_ERR_CONSTRAINT_VIOLATION;
}

static int acl_check_machine_quota(struct ldb_module *module,
				   struct ldb_request *req,
				   const struct dom_sid *creator_sid)
{
	int ret;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;
	struct ldb_context *ldb;
	struct ldb_message *msg;
	struct ldb_dn *base_dn;
	int quota;
	const char *quota_attrs[] = {
		"ms-DS-MachineAccountQuota",
		NULL,
	};
	const char *creator_attrs[] = {
		"mS-DS-CreatorSID",
		NULL,
	};

	ldb = ldb_module_get_ctx(module);

	tmp_ctx = talloc_new(req);
	if (tmp_ctx == NULL) {
		return ldb_operr(ldb);
	}

	base_dn = ldb_get_default_basedn(ldb);

	/* Read the quota */
	ret = dsdb_module_search_dn(module, tmp_ctx, &res,
				    base_dn,
				    quota_attrs,
				    DSDB_FLAG_TOP_MODULE |
				    DSDB_FLAG_AS_SYSTEM,
				    req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	if (res->count != 1) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	msg = res->msgs[0];
	quota = ldb_msg_find_attr_as_int(msg, "ms-DS-MachineAccountQuota", 10);
	talloc_free(res);

	/* Check the quota */
	ret = dsdb_module_search(module, tmp_ctx, &res, base_dn,
				 LDB_SCOPE_SUBTREE,
				 creator_attrs,
				 DSDB_FLAG_NEXT_MODULE | DSDB_FLAG_AS_SYSTEM,
				 req,
				 "(mS-DS-CreatorSID=%s)",
				 ldap_encode_ndr_dom_sid(tmp_ctx, creator_sid));
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	if (res->count >= quota) {
		ldb_asprintf_errstring(ldb,
				       "%08X: %s - acl_check_machine_quota: "
				       "Quota exceeded creating computer account",
				       W_ERROR_V(WERR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED),
				       ldb_strerror(LDB_ERR_UNWILLING_TO_PERFORM));
		talloc_free(tmp_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}

/*
 * Check seMachineAccount privilege. [MS-ADTS] section 3.1.1.5.2.1 and
 * [MS-SAMR] 3.1.5.4.4 after an LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS
 */
static int acl_add_privileges(struct ldb_module *module,
				    struct ldb_request *req)
{
	struct loadparm_context *lp_ctx;
	struct auth_session_info *sinfo;
	int ret;
	enum ndr_err_code ndr_err;
	struct ldb_context *ldb;
	const struct dom_sid *creator_sid;
	const struct dom_sid *domain_sid;
	const struct ldb_val *sd_val;
	struct security_descriptor *sd;
	struct ldb_request *add_req;
	struct ldb_message *msg;
	struct ldb_message_element *el;
	struct ldb_control *samr_request;
	const struct ldb_request *orig_req;
	unsigned int uac;
	DATA_BLOB data;
	int i, j;
	const char *allowed_attributes[] = {
		"dNSHostName", "servicePrincipalName",
		"userAccountControl", "unicodePwd",
		"objectClass", "sAMAccountNAme",
		NULL,
	};
	
	ldb = ldb_module_get_ctx(module);

	if (samdb_find_attribute(ldb, req->op.add.message, "objectclass", "computer") == NULL) {
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	sinfo = talloc_get_type_abort(ldb_get_opaque(ldb, "sessionInfo"),
				      struct auth_session_info);
	if (sinfo == NULL) {
		return ldb_operr(ldb);
	}

	lp_ctx = talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"),
				       struct loadparm_context);
	if (lp_ctx == NULL) {
		return ldb_operr(ldb);
	}

	/* On non-DC configurations, return access denied */
	if (lpcfg_server_role(lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC) {
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	/* Check the seMachineAccount privilege */
	if (!security_token_has_privilege(sinfo->security_token, SEC_PRIV_MACHINE_ACCOUNT)) {
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	/* Retrieve the original add request */
	orig_req = req;
	while (orig_req && orig_req->handle && orig_req->handle->parent) {
		orig_req = orig_req->handle->parent;
	}
	if (orig_req == NULL) {
		return ldb_operr(ldb);
	}

	/* Check if the request comes over SAM-R or regular LDAP */
	samr_request = ldb_request_get_control(req, DSDB_CONTROL_SAMR_CREATE_COMPUTER_ACCOUNT);

	/*
	 * Assert no extra attributes have been supplied in the
	 * original request
	 */
	for (i = 0; i < orig_req->op.add.message->num_elements; i++) {
		bool valid = false;
		el = &orig_req->op.add.message->elements[i];
		for (j = 0; allowed_attributes[j] != NULL; j++) {
			const char *attr;
			attr = allowed_attributes[j];
			if (strcasecmp(el->name, attr) == 0) {
				valid = true;
				continue;
			}
		}
		if (!valid) {
			/* An invalid attribute has been supplied */
			ldb_asprintf_errstring(ldb,
					       "%s - %s: Invalid attribute %s specified in request",
					       ldb_strerror(LDB_ERR_CONSTRAINT_VIOLATION),
					       __func__,
					       el->name);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}

	/*
	 * Check supplied attribtues
	 *
	 * If the request comes through SAM-R pipe instead LDAP
	 * interface, relax constrains on dNSHostName and
	 * servicePrincipalName attributes
	 */
	if (samr_request == NULL) {
		if (!ldb_msg_find_ldb_val(req->op.add.message, "dNSHostName")) {
			ldb_asprintf_errstring(ldb,
					       "%s - %s: Missing dNSHostName attribute in add computer request using elevated seMachineAccount privilege",
					       ldb_strerror(LDB_ERR_UNWILLING_TO_PERFORM),
					       __func__);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		if (!ldb_msg_find_ldb_val(req->op.add.message, "servicePrincipalName")) {
			ldb_asprintf_errstring(ldb,
					       "%s - %s: Missing servicePrincipalName attribute in add computer request using elevated seMachineAccount privilege",
					       ldb_strerror(LDB_ERR_UNWILLING_TO_PERFORM),
					       __func__);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	if (!ldb_msg_find_ldb_val(req->op.add.message, "userAccountControl")) {
		ldb_asprintf_errstring(ldb,
				       "%s - %s: Missing userAccountControl attribute in add computer request using elevated seMachineAccount privilege",
				       ldb_strerror(LDB_ERR_UNWILLING_TO_PERFORM),
				       __func__);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	} else {
		uac = ldb_msg_find_attr_as_uint(req->op.add.message, "userAccountControl", 0);
		if (!(uac & UF_WORKSTATION_TRUST_ACCOUNT)) {
			ldb_asprintf_errstring(ldb,
					       "%s - %s: Invalid userAccountControl attribute value in add computer request using elevated seMachineAccount privilege",
					       ldb_strerror(LDB_ERR_CONSTRAINT_VIOLATION),
					       __func__);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if (samr_request == NULL) {
			if (uac & ~(UF_WORKSTATION_TRUST_ACCOUNT | UF_ACCOUNTDISABLE)) {
				ldb_asprintf_errstring(ldb,
						       "%s - %s: Invalid userAccountControl attribute value in add computer request using elevated seMachineAccount privilege",
						       ldb_strerror(LDB_ERR_CONSTRAINT_VIOLATION),
						       __func__);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		} else {
			if (uac & ~(UF_WORKSTATION_TRUST_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)) {
				ldb_asprintf_errstring(ldb,
						       "%s - %s: Invalid userAccountControl attribute value in add computer request using elevated seMachineAccount privilege",
						       ldb_strerror(LDB_ERR_CONSTRAINT_VIOLATION),
						       __func__);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}
	}
	if (!ldb_msg_find_ldb_val(req->op.add.message, "sAMAccountName")) {
		ldb_asprintf_errstring(ldb,
				       "%s - %s: Missing sAMAccountName attribute in add computer request using elevated seMachineAccount privilege",
				       ldb_strerror(LDB_ERR_UNWILLING_TO_PERFORM),
				       __func__);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	if (!(uac & UF_ACCOUNTDISABLE) && !(uac & UF_PASSWD_NOTREQD)) {
		if (!ldb_msg_find_ldb_val(req->op.add.message, "unicodePwd")) {
			ldb_asprintf_errstring(ldb,
					       "%s - %s: Missing unicodePwd attribute in add computer request using elevated seMachineAccount privilege",
					       ldb_strerror(LDB_ERR_UNWILLING_TO_PERFORM),
					       __func__);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	/* Check the quota */
	creator_sid = &sinfo->security_token->sids[0];
	ret = acl_check_machine_quota(module, req, creator_sid);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	msg = ldb_msg_copy_shallow(req, req->op.add.message);
	if (msg == NULL) {
		return ldb_oom(ldb);
	}

	/* Append msDS-CreatorSID */
	creator_sid = &sinfo->security_token->sids[0];
	ndr_err = ndr_push_struct_blob(&data, msg, creator_sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ldb_operr(ldb);
	}
	ret = ldb_msg_add_steal_value(msg, "mS-DS-CreatorSID", &data);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Replace SD owner and group */
	sd_val = ldb_msg_find_ldb_val(req->op.add.message, "nTSecurityDescriptor");
	if (sd_val == NULL) {
		return ldb_operr(ldb);
	}

	sd = talloc_zero(msg, struct security_descriptor);
	if (sd == NULL) {
		return ldb_operr(ldb);
	}

	ndr_err = ndr_pull_struct_blob(sd_val, msg, sd, (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(sd);
		return ldb_operr(ldb);
	}
	ldb_msg_remove_attr(msg, "nTSecurityDescriptor");

	domain_sid = samdb_domain_sid(ldb);
	sd->group_sid = dom_sid_add_rid(sd, domain_sid, DOMAIN_RID_USERS);
	sd->owner_sid = dom_sid_add_rid(sd, domain_sid, DOMAIN_RID_ADMINS);
	sd->type &= ~(SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_SACL_AUTO_INHERITED);

	/* Remove SEC_STD_DELETE and SEC_ADS_DELETE_TREE from any ACE of the creator user */
	if (sd->dacl != NULL) {
		for (i = 0; i < sd->dacl->num_aces; i++) {
			struct security_ace *ace;
			ace = &sd->dacl->aces[i];
			if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED &&
			    dom_sid_equal(&ace->trustee, creator_sid)) {
				ace->access_mask &= ~(SEC_STD_DELETE | SEC_ADS_DELETE_TREE);
			}
		}
	}

	ndr_err = ndr_push_struct_blob(&data, msg, sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ldb_operr(ldb);
	}
	ret = ldb_msg_add_steal_value(msg, "nTSecurityDescriptor", &data);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_add_req(&add_req, ldb, req,
				msg,
				req->controls,
				req, dsdb_next_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, add_req);
}

static int acl_add(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *parent;
	struct ldb_context *ldb;
	const struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	struct ldb_control *as_system;
	struct ldb_message_element *el, *oc_el;
	unsigned int instanceType = 0;

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);
	if (as_system != NULL) {
		as_system->critical = 0;
	}

	if (dsdb_module_am_system(module) || as_system) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	parent = ldb_dn_get_parent(req, req->op.add.message->dn);
	if (parent == NULL) {
		return ldb_oom(ldb);
	}

	schema = dsdb_get_schema(ldb, req);
	if (!schema) {
		return ldb_operr(ldb);
	}

	oc_el = ldb_msg_find_element(req->op.add.message, "objectClass");
	if (oc_el == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "acl: unable to find objectClass on %s to obtain structural "
				       "objectclass (needed to check create child ACL rights)\n",
				       ldb_dn_get_linearized(req->op.add.message->dn));
		return ldb_module_done(req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
	}
	
	objectclass = dsdb_get_structural_oc_from_msg(schema, req->op.add.message);
	if (!objectclass) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "acl: unable to validate structural objectClass on %s (%d values provided)\n",
				       ldb_dn_get_linearized(req->op.add.message->dn),
				       oc_el->num_values);
		return ldb_module_done(req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
	}

	el = ldb_msg_find_element(req->op.add.message, "instanceType");
	if ((el != NULL) && (el->num_values != 1)) {
		ldb_set_errstring(ldb, "acl: the 'instanceType' attribute is single-valued!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	instanceType = ldb_msg_find_attr_as_uint(req->op.add.message,
						 "instanceType", 0);
	if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
		static const char *no_attrs[] = { NULL };
		struct ldb_result *partition_res;
		struct ldb_dn *partitions_dn;

		partitions_dn = samdb_partitions_dn(ldb, req);
		if (!partitions_dn) {
			ldb_set_errstring(ldb, "acl: CN=partitions dn could not be generated!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		ret = dsdb_module_search(module, req, &partition_res,
					 partitions_dn, LDB_SCOPE_ONELEVEL,
					 no_attrs,
					 DSDB_FLAG_NEXT_MODULE |
					 DSDB_FLAG_AS_SYSTEM |
					 DSDB_SEARCH_ONE_ONLY |
					 DSDB_SEARCH_SHOW_RECYCLED,
					 req,
					 "(&(nCName=%s)(objectClass=crossRef))",
					 ldb_dn_get_linearized(req->op.add.message->dn));

		if (ret == LDB_SUCCESS) {
			/* Check that we can write to the crossRef object MS-ADTS 3.1.1.5.2.8.2 */
			ret = dsdb_module_check_access_on_dn(module, req, partition_res->msgs[0]->dn,
							     SEC_ADS_WRITE_PROP,
							     &objectclass->schemaIDGUID, req);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "acl: ACL check failed on crossRef object %s: %s\n",
						       ldb_dn_get_linearized(partition_res->msgs[0]->dn),
						       ldb_errstring(ldb));
				return ret;
			}

			/*
			 * TODO: Remaining checks, like if we are
			 * the naming master etc need to be handled
			 * in the instanceType module
			 */
			return ldb_next_request(module, req);
		}

		/* Check that we can create a crossRef object MS-ADTS 3.1.1.5.2.8.2 */
		ret = dsdb_module_check_access_on_dn(module, req, partitions_dn,
						     SEC_ADS_CREATE_CHILD,
						     &objectclass->schemaIDGUID, req);
		if (ret == LDB_ERR_NO_SUCH_OBJECT &&
		    ldb_request_get_control(req, LDB_CONTROL_RELAX_OID))
		{
			/* Allow provision bootstrap */
			ret = LDB_SUCCESS;
		}
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb_module_get_ctx(module),
					       "acl: ACL check failed on CN=Partitions crossRef container %s: %s\n",
					       ldb_dn_get_linearized(partitions_dn), ldb_errstring(ldb));
			return ret;
		}

		/*
		 * TODO: Remaining checks, like if we are the naming
		 * master and adding the crossRef object need to be
		 * handled in the instanceType module
		 */
		return ldb_next_request(module, req);
	}

	ret = dsdb_module_check_access_on_dn(module, req, parent,
					     SEC_ADS_CREATE_CHILD,
					     &objectclass->schemaIDGUID, req);
	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		/* Check for privileges */
		return acl_add_privileges(module, req);
	}

	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "acl: unable to find or validate structural objectClass on %s\n",
				       ldb_dn_get_linearized(req->op.add.message->dn));
		return ret;
	}
	return ldb_next_request(module, req);
}

/* ckecks if modifications are allowed on "Member" attribute */
static int acl_check_self_membership(TALLOC_CTX *mem_ctx,
				     struct ldb_module *module,
				     struct ldb_request *req,
				     struct security_descriptor *sd,
				     struct dom_sid *sid,
				     const struct dsdb_attribute *attr,
				     const struct dsdb_class *objectclass)
{
	int ret;
	unsigned int i;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *user_dn;
	struct ldb_message_element *member_el;
	/* if we have wp, we can do whatever we like */
	if (acl_check_access_on_attribute(module,
					  mem_ctx,
					  sd,
					  sid,
					  SEC_ADS_WRITE_PROP,
					  attr, objectclass) == LDB_SUCCESS) {
		return LDB_SUCCESS;
	}
	/* if we are adding/deleting ourselves, check for self membership */
	ret = dsdb_find_dn_by_sid(ldb, mem_ctx, 
				  &acl_user_token(module)->sids[PRIMARY_USER_SID_INDEX], 
				  &user_dn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	member_el = ldb_msg_find_element(req->op.mod.message, "member");
	if (!member_el) {
		return ldb_operr(ldb);
	}
	/* user can only remove oneself */
	if (member_el->num_values == 0) {
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
	for (i = 0; i < member_el->num_values; i++) {
		if (strcasecmp((const char *)member_el->values[i].data,
			       ldb_dn_get_extended_linearized(mem_ctx, user_dn, 1)) != 0) {
			return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
	}
	ret = acl_check_extended_right(mem_ctx, sd, acl_user_token(module),
				       GUID_DRS_SELF_MEMBERSHIP,
				       SEC_ADS_SELF_WRITE,
				       sid);
	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		dsdb_acl_debug(sd, acl_user_token(module),
			       req->op.mod.message->dn,
			       true,
			       10);
	}
	return ret;
}

static int acl_check_password_rights(TALLOC_CTX *mem_ctx,
				     struct ldb_module *module,
				     struct ldb_request *req,
				     struct security_descriptor *sd,
				     struct dom_sid *sid,
				     const struct dsdb_class *objectclass,
				     bool userPassword)
{
	int ret = LDB_SUCCESS;
	unsigned int del_attr_cnt = 0, add_attr_cnt = 0, rep_attr_cnt = 0;
	struct ldb_message_element *el;
	struct ldb_message *msg;
	const char *passwordAttrs[] = { "userPassword", "clearTextPassword",
					"unicodePwd", "dBCSPwd", NULL }, **l;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	msg = ldb_msg_copy_shallow(tmp_ctx, req->op.mod.message);
	if (msg == NULL) {
		return ldb_module_oom(module);
	}
	for (l = passwordAttrs; *l != NULL; l++) {
		if ((!userPassword) && (ldb_attr_cmp(*l, "userPassword") == 0)) {
			continue;
		}

		while ((el = ldb_msg_find_element(msg, *l)) != NULL) {
			if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_DELETE) {
				++del_attr_cnt;
			}
			if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_ADD) {
				++add_attr_cnt;
			}
			if (LDB_FLAG_MOD_TYPE(el->flags) == LDB_FLAG_MOD_REPLACE) {
				++rep_attr_cnt;
			}
			ldb_msg_remove_element(msg, el);
		}
	}

	/* single deletes will be handled by the "password_hash" LDB module
	 * later in the stack, so we let it though here */
	if ((del_attr_cnt > 0) && (add_attr_cnt == 0) && (rep_attr_cnt == 0)) {
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	if (ldb_request_get_control(req,
				    DSDB_CONTROL_PASSWORD_CHANGE_OID) != NULL) {
		/* The "DSDB_CONTROL_PASSWORD_CHANGE_OID" control means that we
		 * have a user password change and not a set as the message
		 * looks like. In it's value blob it contains the NT and/or LM
		 * hash of the old password specified by the user.
		 * This control is used by the SAMR and "kpasswd" password
		 * change mechanisms. */
		ret = acl_check_extended_right(tmp_ctx, sd, acl_user_token(module),
					       GUID_DRS_USER_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
	}
	else if (rep_attr_cnt > 0 || (add_attr_cnt != del_attr_cnt)) {
		ret = acl_check_extended_right(tmp_ctx, sd, acl_user_token(module),
					       GUID_DRS_FORCE_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
	}
	else if (add_attr_cnt == 1 && del_attr_cnt == 1) {
		ret = acl_check_extended_right(tmp_ctx, sd, acl_user_token(module),
					       GUID_DRS_USER_CHANGE_PASSWORD,
					       SEC_ADS_CONTROL_ACCESS,
					       sid);
		/* Very strange, but we get constraint violation in this case */
		if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}
	if (ret != LDB_SUCCESS) {
		dsdb_acl_debug(sd, acl_user_token(module),
			       req->op.mod.message->dn,
			       true,
			       10);
	}
	talloc_free(tmp_ctx);
	return ret;
}


static int acl_modify(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_schema *schema;
	unsigned int i;
	const struct dsdb_class *objectclass;
	struct ldb_result *acl_res;
	struct security_descriptor *sd;
	struct dom_sid *sid = NULL;
	struct ldb_control *as_system;
	bool userPassword;
	TALLOC_CTX *tmp_ctx;
	const struct ldb_message *msg = req->op.mod.message;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		"objectSid",
		NULL
	};

	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);
	if (as_system != NULL) {
		as_system->critical = 0;
	}

	/* Don't print this debug statement if elements[0].name is going to be NULL */
	if (msg->num_elements > 0) {
		DEBUG(10, ("ldb:acl_modify: %s\n", msg->elements[0].name));
	}
	if (dsdb_module_am_system(module) || as_system) {
		return ldb_next_request(module, req);
	}

	tmp_ctx = talloc_new(req);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	ret = dsdb_module_search_dn(module, tmp_ctx, &acl_res, msg->dn,
				    acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED,
				    req);

	if (ret != LDB_SUCCESS) {
		goto fail;
	}

	userPassword = dsdb_user_password_support(module, req, req);

	schema = dsdb_get_schema(ldb, tmp_ctx);
	if (!schema) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error obtaining schema.");
	}

	ret = dsdb_get_sd_from_ldb_message(ldb, tmp_ctx, acl_res->msgs[0], &sd);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving security descriptor.");
	}
	/* Theoretically we pass the check if the object has no sd */
	if (!sd) {
		goto success;
	}

	objectclass = dsdb_get_structural_oc_from_msg(schema, acl_res->msgs[0]);
	if (!objectclass) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving object class for GUID.");
	}
	sid = samdb_result_dom_sid(req, acl_res->msgs[0], "objectSid");
	for (i=0; i < msg->num_elements; i++) {
		const struct ldb_message_element *el = &msg->elements[i];
		const struct dsdb_attribute *attr;

		/*
		 * This basic attribute existence check with the right errorcode
		 * is needed since this module is the first one which requests
		 * schema attribute information.
		 * The complete attribute checking is done in the
		 * "objectclass_attrs" module behind this one.
		 *
		 * NOTE: "clearTextPassword" is not defined in the schema.
		 */
		attr = dsdb_attribute_by_lDAPDisplayName(schema, el->name);
		if (!attr && ldb_attr_cmp("clearTextPassword", el->name) != 0) {
			ldb_asprintf_errstring(ldb, "acl_modify: attribute '%s' "
					       "on entry '%s' was not found in the schema!",
					       req->op.mod.message->elements[i].name,
				       ldb_dn_get_linearized(req->op.mod.message->dn));
			ret =  LDB_ERR_NO_SUCH_ATTRIBUTE;
			goto fail;
		}

		if (ldb_attr_cmp("nTSecurityDescriptor", el->name) == 0) {
			uint32_t sd_flags = dsdb_request_sd_flags(req, NULL);
			uint32_t access_mask = 0;

			if (sd_flags & (SECINFO_OWNER|SECINFO_GROUP)) {
				access_mask |= SEC_STD_WRITE_OWNER;
			}
			if (sd_flags & SECINFO_DACL) {
				access_mask |= SEC_STD_WRITE_DAC;
			}
			if (sd_flags & SECINFO_SACL) {
				access_mask |= SEC_FLAG_SYSTEM_SECURITY;
			}

			ret = acl_check_access_on_attribute(module,
							    tmp_ctx,
							    sd,
							    sid,
							    access_mask,
							    attr,
							    objectclass);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "Object %s has no write dacl access\n",
						       ldb_dn_get_linearized(msg->dn));
				dsdb_acl_debug(sd,
					       acl_user_token(module),
					       msg->dn,
					       true,
					       10);
				ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
				goto fail;
			}
		} else if (ldb_attr_cmp("member", el->name) == 0) {
			ret = acl_check_self_membership(tmp_ctx,
							module,
							req,
							sd,
							sid,
							attr,
							objectclass);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		} else if (ldb_attr_cmp("dBCSPwd", el->name) == 0) {
			/* this one is not affected by any rights, we should let it through
			   so that passwords_hash returns the correct error */
			continue;
		} else if (ldb_attr_cmp("unicodePwd", el->name) == 0 ||
			   (userPassword && ldb_attr_cmp("userPassword", el->name) == 0) ||
			   ldb_attr_cmp("clearTextPassword", el->name) == 0) {
			ret = acl_check_password_rights(tmp_ctx,
							module,
							req,
							sd,
							sid,
							objectclass,
							userPassword);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		} else if (ldb_attr_cmp("servicePrincipalName", el->name) == 0) {
			ret = acl_check_spn(tmp_ctx,
					    module,
					    req,
					    sd,
					    sid,
					    attr,
					    objectclass);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		} else if (ldb_attr_cmp("dNSHostName", el->name) == 0) {
			ret = acl_check_dnshostname(tmp_ctx,
					    module,
					    req,
					    sd,
					    sid,
					    attr,
					    objectclass);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		} else {
			ret = acl_check_access_on_attribute(module,
							    tmp_ctx,
							    sd,
							    sid,
							    SEC_ADS_WRITE_PROP,
							    attr,
							    objectclass);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(ldb_module_get_ctx(module),
						       "Object %s has no write property access\n",
						       ldb_dn_get_linearized(msg->dn));
				dsdb_acl_debug(sd,
					       acl_user_token(module),
					       msg->dn,
					       true,
					       10);
				ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
				goto fail;
			}
		}
	}

success:
	talloc_free(tmp_ctx);
	return ldb_next_request(module, req);
fail:
	talloc_free(tmp_ctx);
	return ret;
}

/* similar to the modify for the time being.
 * We need to consider the special delete tree case, though - TODO */
static int acl_delete(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *parent;
	struct ldb_context *ldb;
	struct ldb_dn *nc_root;
	struct ldb_control *as_system;
	const struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	struct security_descriptor *sd = NULL;
	struct dom_sid *sid = NULL;
	struct ldb_result *acl_res;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		"objectSid",
		NULL
	};

	if (ldb_dn_is_special(req->op.del.dn)) {
		return ldb_next_request(module, req);
	}

	as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);
	if (as_system != NULL) {
		as_system->critical = 0;
	}

	if (dsdb_module_am_system(module) || as_system) {
		return ldb_next_request(module, req);
	}

	DEBUG(10, ("ldb:acl_delete: %s\n", ldb_dn_get_linearized(req->op.del.dn)));

	ldb = ldb_module_get_ctx(module);

	parent = ldb_dn_get_parent(req, req->op.del.dn);
	if (parent == NULL) {
		return ldb_oom(ldb);
	}

	/* Make sure we aren't deleting a NC */

	ret = dsdb_find_nc_root(ldb, req, req->op.del.dn, &nc_root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ldb_dn_compare(nc_root, req->op.del.dn) == 0) {
		talloc_free(nc_root);
		DEBUG(10,("acl:deleting a NC\n"));
		/* Windows returns "ERR_UNWILLING_TO_PERFORM */
		return ldb_module_done(req, NULL, NULL,
				       LDB_ERR_UNWILLING_TO_PERFORM);
	}
	talloc_free(nc_root);

	ret = dsdb_module_search_dn(module, req, &acl_res,
				    req->op.del.dn, acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED, req);
	/* we sould be able to find the parent */
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl: failed to find object %s\n",
			  ldb_dn_get_linearized(req->op.rename.olddn)));
		return ret;
	}

	ret = dsdb_get_sd_from_ldb_message(ldb, req, acl_res->msgs[0], &sd);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}
	if (!sd) {
		return ldb_operr(ldb);
	}

	schema = dsdb_get_schema(ldb, req);
	if (!schema) {
		return ldb_operr(ldb);
	}

	sid = samdb_result_dom_sid(req, acl_res->msgs[0], "objectSid");

	objectclass = dsdb_get_structural_oc_from_msg(schema, acl_res->msgs[0]);
	if (!objectclass) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving object class for GUID.");
	}

	if (ldb_request_get_control(req, LDB_CONTROL_TREE_DELETE_OID)) {
		ret = acl_check_access_on_objectclass(module, req, sd, sid,
						      SEC_ADS_DELETE_TREE,
						      objectclass);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		return ldb_next_request(module, req);
	}

	/* First check if we have delete object right */
	ret = acl_check_access_on_objectclass(module, req, sd, sid,
					      SEC_STD_DELETE,
					      objectclass);
	if (ret == LDB_SUCCESS) {
		return ldb_next_request(module, req);
	}

	/* Nope, we don't have delete object. Lets check if we have delete
	 * child on the parent */
	ret = dsdb_module_check_access_on_dn(module, req, parent,
					     SEC_ADS_DELETE_CHILD,
					     &objectclass->schemaIDGUID,
					     req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, req);
}

static int acl_rename(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *oldparent;
	struct ldb_dn *newparent;
	const struct dsdb_schema *schema;
	const struct dsdb_class *objectclass;
	const struct dsdb_attribute *attr = NULL;
	struct ldb_context *ldb;
	struct security_descriptor *sd = NULL;
	struct dom_sid *sid = NULL;
	struct ldb_result *acl_res;
	struct ldb_dn *nc_root;
	struct ldb_control *as_system;
	TALLOC_CTX *tmp_ctx;
	const char *rdn_name;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		"objectSid",
		NULL
	};

	if (ldb_dn_is_special(req->op.rename.olddn)) {
		return ldb_next_request(module, req);
	}

	as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);
	if (as_system != NULL) {
		as_system->critical = 0;
	}

	DEBUG(10, ("ldb:acl_rename: %s\n", ldb_dn_get_linearized(req->op.rename.olddn)));
	if (dsdb_module_am_system(module) || as_system) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	tmp_ctx = talloc_new(req);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	oldparent = ldb_dn_get_parent(tmp_ctx, req->op.rename.olddn);
	if (oldparent == NULL) {
		return ldb_oom(ldb);
	}
	newparent = ldb_dn_get_parent(tmp_ctx, req->op.rename.newdn);
	if (newparent == NULL) {
		return ldb_oom(ldb);
	}

	/* Make sure we aren't renaming/moving a NC */

	ret = dsdb_find_nc_root(ldb, req, req->op.rename.olddn, &nc_root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (ldb_dn_compare(nc_root, req->op.rename.olddn) == 0) {
		talloc_free(nc_root);
		DEBUG(10,("acl:renaming/moving a NC\n"));
		/* Windows returns "ERR_UNWILLING_TO_PERFORM */
		return ldb_module_done(req, NULL, NULL,
				       LDB_ERR_UNWILLING_TO_PERFORM);
	}
	talloc_free(nc_root);

	/* Look for the parent */

	ret = dsdb_module_search_dn(module, tmp_ctx, &acl_res,
				    req->op.rename.olddn, acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED, req);
	/* we sould be able to find the parent */
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl: failed to find object %s\n",
			  ldb_dn_get_linearized(req->op.rename.olddn)));
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_get_sd_from_ldb_message(ldb, req, acl_res->msgs[0], &sd);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	if (!sd) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	schema = dsdb_get_schema(ldb, acl_res);
	if (!schema) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	sid = samdb_result_dom_sid(req, acl_res->msgs[0], "objectSid");

	objectclass = dsdb_get_structural_oc_from_msg(schema, acl_res->msgs[0]);
	if (!objectclass) {
		talloc_free(tmp_ctx);
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "acl_modify: Error retrieving object class for GUID.");
	}

	attr = dsdb_attribute_by_lDAPDisplayName(schema, "name");
	if (attr == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	ret = acl_check_access_on_attribute(module, tmp_ctx, sd, sid,
					    SEC_ADS_WRITE_PROP,
					    attr, objectclass);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Object %s has no wp on %s\n",
				       ldb_dn_get_linearized(req->op.rename.olddn),
				       attr->lDAPDisplayName);
		dsdb_acl_debug(sd,
			  acl_user_token(module),
			  req->op.rename.olddn,
			  true,
			  10);
		talloc_free(tmp_ctx);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	rdn_name = ldb_dn_get_rdn_name(req->op.rename.olddn);
	if (rdn_name == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	attr = dsdb_attribute_by_lDAPDisplayName(schema, rdn_name);
	if (attr == NULL) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}

	ret = acl_check_access_on_attribute(module, tmp_ctx, sd, sid,
					    SEC_ADS_WRITE_PROP,
					    attr, objectclass);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Object %s has no wp on %s\n",
				       ldb_dn_get_linearized(req->op.rename.olddn),
				       attr->lDAPDisplayName);
		dsdb_acl_debug(sd,
			  acl_user_token(module),
			  req->op.rename.olddn,
			  true,
			  10);
		talloc_free(tmp_ctx);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	if (ldb_dn_compare(oldparent, newparent) == 0) {
		/* regular rename, not move, nothing more to do */
		talloc_free(tmp_ctx);
		return ldb_next_request(module, req);
	}

	/* new parent should have create child */
	ret = dsdb_module_check_access_on_dn(module, req, newparent,
					     SEC_ADS_CREATE_CHILD,
					     &objectclass->schemaIDGUID, req);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "acl:access_denied renaming %s",
				       ldb_dn_get_linearized(req->op.rename.olddn));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* do we have delete object on the object? */
	ret = acl_check_access_on_objectclass(module, tmp_ctx, sd, sid,
					      SEC_STD_DELETE,
					      objectclass);
	if (ret == LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ldb_next_request(module, req);
	}
	/* what about delete child on the current parent */
	ret = dsdb_module_check_access_on_dn(module, req, oldparent,
					     SEC_ADS_DELETE_CHILD,
					     &objectclass->schemaIDGUID,
					     req);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "acl:access_denied renaming %s", ldb_dn_get_linearized(req->op.rename.olddn));
		talloc_free(tmp_ctx);
		return ldb_module_done(req, NULL, NULL, ret);
	}

	talloc_free(tmp_ctx);

	return ldb_next_request(module, req);
}

static int acl_search_update_confidential_attrs(struct acl_context *ac,
						struct acl_private *data)
{
	struct dsdb_attribute *a;
	uint32_t n = 0;

	if (data->acl_search) {
		/*
		 * If acl:search is activated, the acl_read module
		 * protects confidential attributes.
		 */
		return LDB_SUCCESS;
	}

	if ((ac->schema == data->cached_schema_ptr) &&
	    (ac->schema->loaded_usn == data->cached_schema_loaded_usn) &&
	    (ac->schema->metadata_usn == data->cached_schema_metadata_usn))
	{
		return LDB_SUCCESS;
	}

	data->cached_schema_ptr = NULL;
	data->cached_schema_loaded_usn = 0;
	data->cached_schema_metadata_usn = 0;
	TALLOC_FREE(data->confidential_attrs);

	if (ac->schema == NULL) {
		return LDB_SUCCESS;
	}

	for (a = ac->schema->attributes; a; a = a->next) {
		const char **attrs = data->confidential_attrs;

		if (!(a->searchFlags & SEARCH_FLAG_CONFIDENTIAL)) {
			continue;
		}

		attrs = talloc_realloc(data, attrs, const char *, n + 2);
		if (attrs == NULL) {
			TALLOC_FREE(data->confidential_attrs);
			return ldb_module_oom(ac->module);
		}

		attrs[n] = a->lDAPDisplayName;
		attrs[n+1] = NULL;
		n++;

		data->confidential_attrs = attrs;
	}

	data->cached_schema_ptr = ac->schema;
	data->cached_schema_loaded_usn = ac->schema->loaded_usn;
	data->cached_schema_metadata_usn = ac->schema->metadata_usn;

	return LDB_SUCCESS;
}

static int acl_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct acl_context *ac;
	struct acl_private *data;
	struct ldb_result *acl_res;
	static const char *acl_attrs[] = {
		"objectClass",
		"nTSecurityDescriptor",
		"objectSid",
		NULL
	};
	int ret;
	unsigned int i;

	ac = talloc_get_type(req->context, struct acl_context);
	data = talloc_get_type(ldb_module_get_private(ac->module), struct acl_private);
	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->constructed_attrs) {
			ret = dsdb_module_search_dn(ac->module, ac, &acl_res, ares->message->dn, 
						    acl_attrs,
						    DSDB_FLAG_NEXT_MODULE |
						    DSDB_FLAG_AS_SYSTEM |
						    DSDB_SEARCH_SHOW_RECYCLED,
						    req);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->allowedAttributes || ac->allowedAttributesEffective) {
			ret = acl_allowedAttributes(ac->module, ac->schema,
						    acl_res->msgs[0],
						    ares->message, ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->allowedChildClasses) {
			ret = acl_childClasses(ac->module, ac->schema,
					       acl_res->msgs[0],
					       ares->message,
					       "allowedChildClasses");
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->allowedChildClassesEffective) {
			ret = acl_childClassesEffective(ac->module, ac->schema,
							acl_res->msgs[0],
							ares->message, ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (ac->sDRightsEffective) {
			ret = acl_sDRightsEffective(ac->module,
						    acl_res->msgs[0],
						    ares->message, ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		if (data == NULL) {
			return ldb_module_send_entry(ac->req, ares->message,
						     ares->controls);
		}

		if (ac->am_system) {
			return ldb_module_send_entry(ac->req, ares->message,
						     ares->controls);
		}

		if (data->password_attrs != NULL) {
			for (i = 0; data->password_attrs[i]; i++) {
				if ((!ac->userPassword) &&
				    (ldb_attr_cmp(data->password_attrs[i],
						  "userPassword") == 0))
				{
						continue;
				}

				ldb_msg_remove_attr(ares->message, data->password_attrs[i]);
			}
		}

		if (ac->am_administrator) {
			return ldb_module_send_entry(ac->req, ares->message,
						     ares->controls);
		}

		ret = acl_search_update_confidential_attrs(ac, data);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		if (data->confidential_attrs != NULL) {
			for (i = 0; data->confidential_attrs[i]; i++) {
				ldb_msg_remove_attr(ares->message,
						    data->confidential_attrs[i]);
			}
		}

		return ldb_module_send_entry(ac->req, ares->message, ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, LDB_SUCCESS);

	}
	return LDB_SUCCESS;
}

static int acl_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct acl_context *ac;
	struct ldb_parse_tree *down_tree;
	struct ldb_request *down_req;
	struct acl_private *data;
	int ret;
	unsigned int i;

	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct acl_context);
	if (ac == NULL) {
		return ldb_oom(ldb);
	}
	data = talloc_get_type(ldb_module_get_private(module), struct acl_private);

	ac->module = module;
	ac->req = req;
	ac->am_system = dsdb_module_am_system(module);
	ac->am_administrator = dsdb_module_am_administrator(module);
	ac->constructed_attrs = false;
	ac->modify_search = true;
	ac->allowedAttributes = ldb_attr_in_list(req->op.search.attrs, "allowedAttributes");
	ac->allowedAttributesEffective = ldb_attr_in_list(req->op.search.attrs, "allowedAttributesEffective");
	ac->allowedChildClasses = ldb_attr_in_list(req->op.search.attrs, "allowedChildClasses");
	ac->allowedChildClassesEffective = ldb_attr_in_list(req->op.search.attrs, "allowedChildClassesEffective");
	ac->sDRightsEffective = ldb_attr_in_list(req->op.search.attrs, "sDRightsEffective");
	ac->userPassword = true;
	ac->schema = dsdb_get_schema(ldb, ac);

	ac->constructed_attrs |= ac->allowedAttributes;
	ac->constructed_attrs |= ac->allowedChildClasses;
	ac->constructed_attrs |= ac->allowedChildClassesEffective;
	ac->constructed_attrs |= ac->allowedAttributesEffective;
	ac->constructed_attrs |= ac->sDRightsEffective;

	if (data == NULL) {
		ac->modify_search = false;
	}
	if (ac->am_system) {
		ac->modify_search = false;
	}

	if (!ac->constructed_attrs && !ac->modify_search) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	if (!ac->am_system) {
		ac->userPassword = dsdb_user_password_support(module, ac, req);
	}

	ret = acl_search_update_confidential_attrs(ac, data);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	down_tree = ldb_parse_tree_copy_shallow(ac, req->op.search.tree);
	if (down_tree == NULL) {
		return ldb_oom(ldb);
	}

	if (!ac->am_system && data->password_attrs) {
		for (i = 0; data->password_attrs[i]; i++) {
			if ((!ac->userPassword) &&
			    (ldb_attr_cmp(data->password_attrs[i],
					  "userPassword") == 0))
			{
				continue;
			}

			ldb_parse_tree_attr_replace(down_tree,
						    data->password_attrs[i],
						    "kludgeACLredactedattribute");
		}
	}

	if (!ac->am_system && !ac->am_administrator && data->confidential_attrs) {
		for (i = 0; data->confidential_attrs[i]; i++) {
			ldb_parse_tree_attr_replace(down_tree,
						    data->confidential_attrs[i],
						    "kludgeACLredactedattribute");
		}
	}

	ret = ldb_build_search_req_ex(&down_req,
				      ldb, ac,
				      req->op.search.base,
				      req->op.search.scope,
				      down_tree,
				      req->op.search.attrs,
				      req->controls,
				      ac, acl_search_callback,
				      req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int acl_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_control *as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);

	/* allow everybody to read the sequence number */
	if (strcmp(req->op.extended.oid,
		   LDB_EXTENDED_SEQUENCE_NUMBER) == 0) {
		return ldb_next_request(module, req);
	}

	if (dsdb_module_am_system(module) ||
	    dsdb_module_am_administrator(module) || as_system) {
		return ldb_next_request(module, req);
	} else {
		ldb_asprintf_errstring(ldb,
				       "acl_extended: "
				       "attempted database modify not permitted. "
				       "User %s is not SYSTEM or an administrator",
				       acl_user_name(req, module));
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
}

static const struct ldb_module_ops ldb_acl_module_ops = {
	.name		   = "acl",
	.search            = acl_search,
	.add               = acl_add,
	.modify            = acl_modify,
	.del               = acl_delete,
	.rename            = acl_rename,
	.extended          = acl_extended,
	.init_context	   = acl_module_init
};

int ldb_acl_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_acl_module_ops);
}
