/*
   Unix SMB/CIFS implementation.

   endpoint server for the frstrans pipe

   Copyright (C) YOUR NAME HERE YEAR

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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_frstrans.h"
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/frstrans.h"
#include "lib/param/param.h"
#include "lib/param/loadparm.h"
#include "libds/common/roles.h"
#include "ldb.h"
#include "source4/dsdb/samdb/samdb.h"
#include "libds/common/flags.h"

enum replicationGroupType {
	OTHER=0,
	SYSVOL=1,
	PROTECTION=2,
	DISTRIBUTION=3
};

#define DCESRV_INTERFACE_FRSTRANS_BIND(call, iface) \
	dcesrv_interface_frstrans_bind(call, iface)
static NTSTATUS dcesrv_interface_frstrans_bind(struct dcesrv_call_state *dce_call,
					     const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_require_privacy(dce_call, iface);
}

/*
  frstrans_CheckConnectivity
*/
static WERROR dcesrv_frstrans_CheckConnectivity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_CheckConnectivity *r)
{
	r->out.result = WERR_OK;
	return r->out.result;
}

static const char* host_dn(struct ldb_context *ldb,
			   struct loadparm_context *lp_ctx,
			   TALLOC_CTX *mem_ctx)
{
	int err;
	const char *wk_guid;
	struct ldb_dn *wk_dn;
	struct ldb_result *res = NULL;
	const char* name = lpcfg_netbios_name(lp_ctx);
	static const char *attrs[] = {
		"distinguishedName",
		NULL
	};
	enum server_role role = lpcfg_server_role(lp_ctx);

	if (role == ROLE_ACTIVE_DIRECTORY_DC) {
		wk_guid = DS_GUID_DOMAIN_CONTROLLERS_CONTAINER;
	} else {
		wk_guid = DS_GUID_COMPUTERS_CONTAINER;
	}

	err = dsdb_wellknown_dn(ldb, mem_ctx, ldb_get_default_basedn(ldb),
				wk_guid, &wk_dn);
	if (err != LDB_SUCCESS) {
		return NULL;
	}

	err = ldb_search(ldb, mem_ctx, &res, wk_dn, LDB_SCOPE_SUBTREE,
			 attrs, "(name=%s)", name);
	if (err != LDB_SUCCESS || res->count != 1) {
		return NULL;
	}
	return ldb_msg_find_attr_as_string(res->msgs[0], "distinguishedName", NULL);
}

/*
  frstrans_EstablishConnection
*/
static WERROR dcesrv_frstrans_EstablishConnection(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_EstablishConnection *r)
{
	WERROR ret = WERR_OK;
	const char* replica_set_guid_txt = NULL;
	const char* connection_guid_txt = NULL;
	struct GUID_txt_buf txtguid1, txtguid2;
	int server_role;
	struct ldb_context *ldb;
	int ldbret;
	struct ldb_dn *domain_dn = NULL;
	struct ldb_dn *search_dn = NULL;
	struct ldb_dn *repl_dn = NULL;
	static const char *repl_attrs[] = {
		"msDFSR-ReplicationGroupType",
		"cn",
		NULL
	};
	enum replicationGroupType repl_type;
	const char *repl_group = NULL;
	const char *dn = NULL;
	struct ldb_result *res = NULL;
	static const char *conn_attrs[] = {
		"msDFSR-Enabled",
		NULL
	};
	int conn_enabled = 1;

	ldb = samdb_connect(mem_ctx,
			    dce_call->event_ctx,
			    dce_call->conn->dce_ctx->lp_ctx,
			    dce_call->conn->auth_state.session_info,
			    dce_call->conn->remote_address,
			    0);
	if (ldb == NULL) {
		ret = WERR_DS_UNAVAILABLE;
		goto out;
	}

	/* [MS-FRS2] 3.2.4.1.2: If the server is not a member of the specified
	   replication group it MUST fail the call with an implementation-defined
	   failure value.
	*/
	replica_set_guid_txt = GUID_buf_string(&(r->in.replica_set_guid), &txtguid1);
	connection_guid_txt = GUID_buf_string(&(r->in.connection_guid), &txtguid2);
	domain_dn = ldb_get_default_basedn(ldb);
	search_dn = ldb_dn_new_fmt(mem_ctx, ldb,
				   "CN=DFSR-GlobalSettings,CN=System,%s",
				   ldb_dn_get_linearized(domain_dn));

	ldbret = ldb_search(ldb, mem_ctx, &res, search_dn, LDB_SCOPE_ONELEVEL,
			    repl_attrs, "(objectGUID=%s)", replica_set_guid_txt);
	if (ldbret != LDB_SUCCESS || res->count != 1) {
		ret = WERR_FRS_ERROR_CONNECTION_INVALID;
		goto out;
	}
	repl_type = ldb_msg_find_attr_as_uint(res->msgs[0],
					      "msDFSR-ReplicationGroupType",
					      0);
	repl_group = ldb_msg_find_attr_as_string(res->msgs[0], "cn", NULL);
	if (repl_group == NULL) {
		ret = WERR_NOT_ENOUGH_MEMORY;
		goto out;
	}
	repl_dn = ldb_dn_new_fmt(mem_ctx, ldb,
				 "CN=Topology,CN=%s,CN=DFSR-GlobalSettings,CN=System,%s",
				 repl_group, ldb_dn_get_linearized(domain_dn));
	dn = host_dn(ldb, dce_call->conn->dce_ctx->lp_ctx, mem_ctx);

	ldbret = ldb_search(ldb, mem_ctx, &res, repl_dn, LDB_SCOPE_ONELEVEL, NULL,
			    "(&(objectClass=msDFSR-Member)(msDFSR-ComputerReference=%s))",
			    dn);
	if (ldbret != LDB_SUCCESS || res->count != 1) {
		ret = WERR_FRS_ERROR_CONNECTION_INVALID;
		goto out;
	}

	/* [MS-FRS2] 3.2.4.1.2: If the specified connection does not exist in the
	   specified replication group's configuration and the replication group's
	   type is not SYSVOL, then the server MUST fail the call with
	   FRS_ERROR_CONNECTION_INVALID.
	*/
	if (repl_type != SYSVOL) {
		ldbret = ldb_search(ldb, mem_ctx, &res, repl_dn, LDB_SCOPE_SUBTREE,
				    conn_attrs,
				    "(&(objectClass=msDFSR-Connection)(objectGUID=%s))",
				    connection_guid_txt);
		if (ldbret != LDB_SUCCESS || res->count != 1) {
			ret = WERR_FRS_ERROR_CONNECTION_INVALID;
			goto out;
		}
		conn_enabled = ldb_msg_find_attr_as_bool(res->msgs[0],
							 "msDFSR-Enabled",
							 1);
	}

	/* [MS-FRS2] 3.2.4.1.2: If the replication group's type is SYSVOL and the
	   specified connection does not exist in the specified replication group's
	   configuration and there is no Member object in the specified replication
	   group's configuration, the server MUST fail the request with
	   FRS_ERROR_CONNECTION_INVALID.
	*/
	/* SYSVOL share never has connections, and we already validated that the
	 * member object exists */

	/* [MS-FRS2] 3.2.4.1.2: If the replication group's type is SYSVOL and the
	   client is not a domain controller in the same domain as the server, or if
	   the server is not a domain controller, then the server MUST fail the call
	   with FRS_ERROR_CONNECTION_INVALID.
	*/
	server_role = lpcfg_server_role(dce_call->conn->dce_ctx->lp_ctx);
	if (repl_type == SYSVOL &&
	    server_role != ROLE_ACTIVE_DIRECTORY_DC) {
		ret = WERR_FRS_ERROR_CONNECTION_INVALID;
		goto out;
	}

	/* [MS-FRS2] 3.2.4.1.2: If the specified connection is disabled then the
	   server MUST fail the call with FRS_ERROR_CONNECTION_INVALID.
	*/
	if (!conn_enabled) {
		ret = WERR_FRS_ERROR_CONNECTION_INVALID;
		goto out;
	}

	/* [MS-FRS2] 3.2.4.1.2: If the server is not the specified connection's
	   outbound partner, or the client is not the connection's inbound partner
	   then the server MUST fail the call with FRS_ERROR_CONNECTION_INVALID.
	*/

	/* [MS-FRS2] 3.2.4.1.2: If the client's protocol version number is 0x00050001,
	   or if the client's protocol's major version number is not equal to the
	   server protocol's major version number, then the server MUST fail the call
	   with the FRS_ERROR_INCOMPATIBLE_VERSION failure value.
	*/
	if (r->in.downstream_protocol_version == 0x00050001 ||
	    (r->in.downstream_protocol_version & 0x00050000) != 0x00050000) {
		//return WERR_FRS_ERROR_INCOMPATIBLE_VERSION;
		ret = WERR_FRS_ERROR_CONNECTION_INVALID;
		goto out;
	}

out:
	r->out.upstream_protocol_version =
		talloc_zero(mem_ctx, enum frstrans_ProtocolVersion);
	*(r->out.upstream_protocol_version) = FRSTRANS_PROTOCOL_VERSION_W2K3R2;
	r->out.upstream_flags = talloc_zero(mem_ctx, uint32_t);
	*(r->out.upstream_flags) = 0;
	r->out.result = ret;
	return r->out.result;
}


/*
  frstrans_EstablishSession
*/
static WERROR dcesrv_frstrans_EstablishSession(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_EstablishSession *r)
{
	r->out.result = WERR_OK;
	return r->out.result;
}


/*
  frstrans_RequestUpdates
*/
static WERROR dcesrv_frstrans_RequestUpdates(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RequestUpdates *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RequestVersionVector
*/
static WERROR dcesrv_frstrans_RequestVersionVector(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RequestVersionVector *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_AsyncPoll
*/
static WERROR dcesrv_frstrans_AsyncPoll(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_AsyncPoll *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_REQUEST_RECORDS
*/
static void dcesrv_FRSTRANS_REQUEST_RECORDS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_REQUEST_RECORDS *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_UPDATE_CANCEL
*/
static void dcesrv_FRSTRANS_UPDATE_CANCEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_UPDATE_CANCEL *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RawGetFileData
*/
static WERROR dcesrv_frstrans_RawGetFileData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RawGetFileData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_GET_SIGNATURES
*/
static void dcesrv_FRSTRANS_RDC_GET_SIGNATURES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_RDC_GET_SIGNATURES *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_PUSH_SOURCE_NEEDS
*/
static void dcesrv_FRSTRANS_RDC_PUSH_SOURCE_NEEDS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_RDC_PUSH_SOURCE_NEEDS *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_GET_FILE_DATA
*/
static void dcesrv_FRSTRANS_RDC_GET_FILE_DATA(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_RDC_GET_FILE_DATA *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_RDC_CLOSE
*/
static WERROR dcesrv_frstrans_RdcClose(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RdcClose *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_InitializeFileTransferAsync
*/
static WERROR dcesrv_frstrans_InitializeFileTransferAsync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_InitializeFileTransferAsync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE
*/
static void dcesrv_FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE *r)
{
	DCESRV_FAULT_VOID(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RawGetFileDataAsync
*/
static WERROR dcesrv_frstrans_RawGetFileDataAsync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RawGetFileDataAsync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  frstrans_RdcGetFileDataAsync
*/
static WERROR dcesrv_frstrans_RdcGetFileDataAsync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct frstrans_RdcGetFileDataAsync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_frstrans_s.c"
