/*
   Unix SMB/CIFS mplementation.

   DFS Replication database

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
#include "dfsr_db.h"
#include "system/filesys.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/util_tdb.h"
#include "librpc/gen_ndr/ndr_frsblobs.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

struct dfsr_db {
	struct tdb_wrap *store;
};

struct dfsr_key {
	struct GUID guid;
	uint64_t version;
};

struct vv_key {
	struct GUID group;
	struct GUID set;
};

static int dfsr_db_destructor(struct dfsr_db *db);

/**
 * Open DFS-R Database
 */
struct dfsr_db *dfsr_db_init(TALLOC_CTX *mem_ctx, const char *base_path)
{
	struct dfsr_db *db;
	int tdb_flags;
	char *path;

	path = talloc_asprintf(mem_ctx, "%s/dfsrdb.tdb", base_path);
	if (path == NULL) {
		return NULL;
	}

	tdb_flags = TDB_DEFAULT | TDB_INCOMPATIBLE_HASH | TDB_SEQNUM;

	db = talloc(mem_ctx, struct dfsr_db);
	if (db == NULL) {
		return NULL;
	}

	db->store = tdb_wrap_open(db, path, 0, tdb_flags, O_RDWR|O_CREAT, 0600);

	TALLOC_FREE(path);
	if (db->store == NULL) {
		TALLOC_FREE(db);
		return NULL;
	}

	talloc_set_destructor(db, dfsr_db_destructor);

	return db;
}

static int dfsr_db_destructor(struct dfsr_db *db)
{
	return 0;
}

NTSTATUS dfsr_db_store(struct dfsr_db *db_ctx,
		       const struct GUID *uid_db_guid,
		       uint64_t uid_version,
		       const struct dfsr_db_record *record)
{
	TALLOC_CTX *frame;
	struct tdb_context *tdb = db_ctx->store->tdb;
	struct dfsr_key key;
	TDB_DATA tkey = tdb_null;
	TDB_DATA tdata = tdb_null;
	DATA_BLOB blob = data_blob_null;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	if (record == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	frame = talloc_stackframe();
	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	key.guid = *uid_db_guid;
	key.version = uid_version;
	tkey = make_tdb_data((const uint8_t *)&key, sizeof(struct dfsr_key));

	ndr_err = ndr_push_struct_blob(&blob, frame, record,
			(ndr_push_flags_fn_t)ndr_push_dfsr_db_record);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed ndr push: %s\n", ndr_errstr(ndr_err));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	tdata = make_tdb_data(blob.data, blob.length);
	if (tdb_store(tdb, tkey, tdata, TDB_REPLACE)) {
		struct GUID_txt_buf tmp_buf;

		status = map_nt_error_from_tdb(tdb_error(tdb));
		DBG_ERR("Error storing update {%s}-%lu: %s\n",
			GUID_buf_string(uid_db_guid, &tmp_buf), uid_version,
			tdb_errorstr(tdb));
	} else {
		status = NT_STATUS_OK;
	}
out:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS dfsr_db_fetch(struct dfsr_db *db_ctx,
		       TALLOC_CTX *mem_ctx,
		       const struct GUID *uid_db_guid,
		       uint64_t uid_version,
		       struct dfsr_db_record **record)
{
	struct tdb_context *tdb = db_ctx->store->tdb;
	TDB_DATA tkey = tdb_null;
	TDB_DATA tdata = tdb_null;
	DATA_BLOB blob = data_blob_null;
	struct dfsr_key key;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	if (record == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	key.guid = *uid_db_guid;
	key.version = uid_version;

	tkey = make_tdb_data((const uint8_t *)&key, sizeof(struct dfsr_key));
	tdata = tdb_fetch(tdb, tkey);
	if (tdata.dptr == NULL) {
		/* Key not found */
		*record = NULL;
		status = NT_STATUS_NOT_FOUND;
		goto out;
	}
	if (tdata.dsize == 0) {
		/* Key exists but no data attached */
		*record = NULL;
		status = NT_STATUS_NOT_FOUND;
		goto out;
	}

	*record = talloc_zero(mem_ctx, struct dfsr_db_record);
	if (*record == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	blob = data_blob_const(tdata.dptr, tdata.dsize);
	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, *record,
			(ndr_pull_flags_fn_t)ndr_pull_dfsr_db_record);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed ndr pull: %s\n", ndr_errstr(ndr_err));
		TALLOC_FREE(*record);
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	status = NT_STATUS_OK;
out:
	SAFE_FREE(tdata.dptr);

	return status;
}

NTSTATUS dfsr_db_store_vv(struct dfsr_db *db_ctx,
		const struct GUID *group,
		const struct GUID *set,
		const struct dfsr_db_vv_record *record)
{
	TALLOC_CTX *frame;
	struct tdb_context *tdb = db_ctx->store->tdb;
	struct vv_key key;
	TDB_DATA tkey = tdb_null;
	TDB_DATA tdata = tdb_null;
	DATA_BLOB blob = data_blob_null;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	if (record == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	frame = talloc_stackframe();
	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	key.group = *group;
	key.set = *set;
	tkey = make_tdb_data((const uint8_t *)&key, sizeof(struct vv_key));

	ndr_err = ndr_push_struct_blob(&blob, frame, record,
			(ndr_push_flags_fn_t)ndr_push_dfsr_db_vv_record);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed ndr push: %s\n", ndr_errstr(ndr_err));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	tdata = make_tdb_data(blob.data, blob.length);
	if (tdb_store(tdb, tkey, tdata, TDB_REPLACE)) {
		status = map_nt_error_from_tdb(tdb_error(tdb));
	} else {
		status = NT_STATUS_OK;
	}
out:
	TALLOC_FREE(frame);

	return status;
}

NTSTATUS dfsr_db_fetch_vv(struct dfsr_db *db_ctx,
		TALLOC_CTX *mem_ctx,
		const struct GUID *group,
		const struct GUID *set,
		struct dfsr_db_vv_record **record)
{
	struct tdb_context *tdb = db_ctx->store->tdb;
	TDB_DATA tkey = tdb_null;
	TDB_DATA tdata = tdb_null;
	DATA_BLOB blob = data_blob_null;
	struct vv_key key;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	if (record == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	key.group = *group;
	key.set = *set;

	tkey = make_tdb_data((const uint8_t *)&key, sizeof(struct vv_key));
	tdata = tdb_fetch(tdb, tkey);
	if (tdata.dptr == NULL) {
		/* Key not found */
		*record = NULL;
		status = NT_STATUS_NOT_FOUND;
		goto out;
	}
	if (tdata.dsize == 0) {
		/* Key exists but no data attached */
		*record = NULL;
		status = NT_STATUS_NOT_FOUND;
		goto out;
	}

	*record = talloc_zero(mem_ctx, struct dfsr_db_vv_record);
	if (*record == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	blob = data_blob_const(tdata.dptr, tdata.dsize);
	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, *record,
			(ndr_pull_flags_fn_t)ndr_pull_dfsr_db_vv_record);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed ndr pull: %s\n", ndr_errstr(ndr_err));
		TALLOC_FREE(*record);
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	status = NT_STATUS_OK;

out:
	SAFE_FREE(tdata.dptr);

	return status;
}
