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
#include "gen_ndr/ndr_frsblobs.h"
#include "gen_ndr/ndr_security.h"
#include "dfsr/dfsr_db.h"
#include "system/filesys.h"
#include "lib/compression/lzhuff_xpress.h"
#include "smbd/smbd.h"
#include "auth.h"
#include "lib/global_contexts.h"
#include "libcli/security/security.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR_MEET

struct dfsr_meet_state {
	struct imessaging_context *imsg_ctx;
	struct loadparm_context *lp_ctx;
	pid_t parent_pid;
	struct dfsr_db *db_ctx;
};

static NTSTATUS dfsr_meet_get_installing_path(TALLOC_CTX *mem_ctx,
		const char *installing_dir,
		const struct frstrans_Update *update,
		char **path)
{
	struct GUID_txt_buf tmp_buf1;

	if (path == NULL || update == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*path = talloc_asprintf(mem_ctx, "%s/%s_%lu", installing_dir,
			GUID_buf_string(&update->gsvn_db_guid, &tmp_buf1),
			update->gsvn_version);
	if (*path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dfsr_meet_get_smb_filename(TALLOC_CTX *mem_ctx,
		struct dfsr_db *db_ctx,
		struct connection_struct *conn,
		const struct frstrans_Update *update,
		struct smb_filename **fname)
{
	NTSTATUS status;
	struct dfsr_db_record *rec = NULL;

	if (update->uid_version != 1) {
		status = dfsr_db_fetch(db_ctx, mem_ctx,
				&update->parent_db_guid,
				update->parent_version, &rec);
		if (!NT_STATUS_IS_OK(status)) {
			struct GUID_txt_buf guid;
			DBG_ERR("Failed to fetch {%s}-v%lu record: %s\n",
				GUID_buf_string(&update->parent_db_guid, &guid),
				update->parent_version, nt_errstr(status));
			goto out;
		}

		status = dfsr_meet_get_smb_filename(mem_ctx, db_ctx, conn,
				rec->update, fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to build update path: %s\n",
				nt_errstr(status));
			goto out;
		}
	}

	if (update->uid_version == 1) {
		/* The root folder */
		*fname = synthetic_smb_fname(mem_ctx, ".", NULL, NULL, 0, 0);
		if (*fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		status = NT_STATUS_OK;
		goto out;
	}

	*fname = synthetic_smb_fname(mem_ctx,
				     talloc_asprintf(mem_ctx,
						     "%s/%s",
						     (*fname)->base_name,
						     update->name),
				     NULL, NULL, 0, 0);
	if (*fname == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(rec);

	return status;
}

static NTSTATUS dfsr_meet_uncompress_staged(TALLOC_CTX *mem_ctx,
		const char *input,
		const char *output)
{
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	int fd_in;
	int fd_out;
	char buffer[8192];
	ssize_t nread;
	ssize_t nwritten;
	off_t offset;

	DBG_DEBUG("Uncompressing '%s' to '%s'\n", input, output);

	fd_in = 0;
	fd_out = 0;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fd_in = open(input, O_RDONLY);
	if (fd_in == -1) {
		DBG_ERR("Failed to open staged file %s: %s\n",
			input, strerror(errno));
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	fd_out = open(output, O_RDWR | O_CREAT | O_TRUNC);
	if (fd_out == -1) {
		DBG_ERR("Failed to open install file %s: %s\n",
			output, strerror(errno));
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	/*
	 * [MS-FRS2] 3.2.4.1.14.2 The compressed data stream starts with
	 * a header ('F', 'R', 'S', 'X')
	 */
	nread = read(fd_in, buffer, 4);
	if (nread != 4) {
		DBG_ERR("Failed to read staged file header: %s\n",
			strerror(errno));
		status = map_nt_error_from_unix(errno);
		goto out;
	}
	if (memcmp(buffer, "FRSX", 4) != 0) {
		DBG_ERR("Invalid staged file signature\n");
		status = NT_STATUS_FILE_CORRUPT_ERROR;
		goto out;
	}
	offset = 4;

	/*
	 * [MS-FRS2] 3.2.4.1.14.2 The header is followed by a series of one
	 * or more XPRESS blocks. The maximum XPRESS block size is 8192
	 * bytes and the XPRESS block header is 12 bytes.
	 */
	while ((nread = read(fd_in, buffer, 8192)) > 0) {
		DATA_BLOB compressed;
		DATA_BLOB uncompressed;
		struct dfsr_xpress_block block;
		enum ndr_err_code ndr_err;

		if (nread < 0) {
			DBG_ERR("Failed to read staged file: %s\n",
				strerror(errno));
			status = map_nt_error_from_unix(errno);
			goto out;
		}

		compressed = data_blob_const(buffer, nread);
		ndr_err = ndr_pull_struct_blob(&compressed, tmp_ctx, &block,
			(ndr_pull_flags_fn_t)ndr_pull_dfsr_xpress_block);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_ERR("Failed to pull XPRESS blob: %s\n",
				ndr_errstr(ndr_err));
			status = ndr_map_error2ntstatus(ndr_err);
			goto out;
		}

		offset += (block.compressed_size + 12 /* header size */);

		/* Set the file offset to the beginning of the next block */
		if (lseek(fd_in, offset, SEEK_SET) < 0) {
			int saved_errno = errno;
			DBG_ERR("lseek() error: %s\n", strerror(saved_errno));
			status = map_nt_error_from_unix(saved_errno);
			goto out;
		}

		/*
		 * [MS-FRS2] 2.2.1.4.15 If the value of the block compressed
		 * size field is less than the value of the block uncompressed
		 * size field, then the data has been compressed
		 */
		if (block.compressed_size < block.uncompressed_size) {
			ssize_t usize;
			uncompressed = data_blob_talloc_zero(tmp_ctx,
					block.uncompressed_size);
			usize = lzhuff_xpress_decompress(block.data.data,
					block.data.length,
					uncompressed.data,
					uncompressed.length);
			if (usize != block.uncompressed_size) {
				DBG_ERR("Uncompressed block size does not "
					"match\n");
				status = NT_STATUS_FILE_CORRUPT_ERROR;
				goto out;
			}
		} else {
			uncompressed = block.data;
		}

		/* Write the uncompressed block to installing file */
		nwritten = write(fd_out, uncompressed.data,
				uncompressed.length);
		if (nwritten != uncompressed.length) {
			DBG_ERR("Failed to write on install file %s: %s\n",
				output, strerror(errno));
			status = map_nt_error_from_unix(errno);
			goto out;
		}

		/* Free the uncompressed blob and continue to next block */
		if (block.compressed_size < block.uncompressed_size) {
			data_blob_free(&uncompressed);
		}
	}

	status = NT_STATUS_OK;

out:
	if (fd_in > 0) {
		close(fd_in);
	}
	if (fd_out > 0) {
		close(fd_out);
	}

	TALLOC_FREE(tmp_ctx);

	return status;
}

static NTSTATUS dfsr_meet_store(TALLOC_CTX *mem_ctx,
				struct dfsr_db *db_ctx,
				struct frstrans_Update *update)
{
	struct dfsr_db_record *record = NULL;
	struct GUID_txt_buf guid;
	NTSTATUS status;

	status = dfsr_db_fetch(db_ctx, mem_ctx, &update->uid_db_guid,
			update->uid_version, &record);
	if (NT_STATUS_EQUAL(NT_STATUS_NOT_FOUND, status)) {
		record = talloc_zero(mem_ctx, struct dfsr_db_record);
		if (record == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to fetch {%s}-v%lu record: %s\n",
			GUID_buf_string(&update->uid_db_guid, &guid),
			update->uid_version, nt_errstr(status));
		goto out;
	}

	record->update = update;
	record->meet_installed = 1;
	if (update->present == 0) {
		record->fid.devid = 0;
		record->fid.inode = 0;
		record->fid.extid = 0;
	}

	DBG_DEBUG("Storing update {%s}-%lu\n",
		  GUID_buf_string(&update->gsvn_db_guid, &guid),
		  update->gsvn_version);
	status = dfsr_db_store(db_ctx, &update->uid_db_guid,
			update->uid_version, record);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to store {%s}-v%lu record: %s\n",
			GUID_buf_string(&update->uid_db_guid, &guid),
			update->uid_version, nt_errstr(status));
		goto out;
	}

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(record);

	return status;
}

static NTSTATUS dfsr_meet_stream_metadata(TALLOC_CTX *mem_ctx,
		struct dfsr_db *db_ctx,
		const struct frstrans_Update *update,
		struct connection_struct *conn,
		int fd_in,
		struct dfsr_stream_header *header,
		struct files_struct **_fsp,
		off_t *offset)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB in;
	ssize_t nread;
	enum ndr_err_code ndr_err;
	struct dfsr_metadata metadata;
	uint32_t file_attributes;
	uint32_t create_options;
	uint32_t disposition;
	struct dfsr_db_record *rec = NULL;
	struct smb_filename *smb_fname = NULL;
	struct files_struct *fsp = NULL;

	DBG_DEBUG("Unmarshalling metadata stream\n");

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	in = data_blob_talloc_zero(tmp_ctx, header->block_size);
	nread = read(fd_in, in.data, header->block_size);
	*offset += nread;

	ndr_err = ndr_pull_struct_blob(&in, tmp_ctx, &metadata,
			(ndr_pull_flags_fn_t)ndr_pull_dfsr_metadata);
	data_blob_free(&in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to pull metadata stream: %s\n",
			ndr_errstr(ndr_err));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	/* Check if this UID is already installed */
	status = dfsr_db_fetch(db_ctx, tmp_ctx, &update->uid_db_guid,
			update->uid_version, &rec);
	if (NT_STATUS_IS_OK(status)) {
		/* Build the stored update path in persistent storage */
		status = dfsr_meet_get_smb_filename(tmp_ctx, db_ctx, conn,
				rec->update, &smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to build update path: %s\n",
				nt_errstr(status));
			goto out;
		}
	} else if (NT_STATUS_EQUAL(NT_STATUS_NOT_FOUND, status)) {
		/* Build the new path in persistent storage */
		status = dfsr_meet_get_smb_filename(tmp_ctx, db_ctx, conn,
				update, &smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to build update path: %s\n",
				nt_errstr(status));
			goto out;
		}
	} else {
		struct GUID_txt_buf guid;
		DBG_ERR("Failed to fetch {%s}-v%lu record: %s\n",
			GUID_buf_string(&update->uid_db_guid, &guid),
			update->uid_version, nt_errstr(status));
		goto out;
	}

	/* Open the file */
	create_options = 0;
	disposition = FILE_OVERWRITE_IF;
	if (metadata.info.fileAttribute & FSCC_FILE_ATTRIBUTE_DIRECTORY) {
		create_options |= FILE_DIRECTORY_FILE;
		disposition = FILE_OPEN_IF;
	}

	file_attributes = metadata.info.fileAttribute;
	status = SMB_VFS_CREATE_FILE(
			conn,                   /* conn */
			NULL,                   /* req */
			smb_fname,       	/* fname */
			FILE_GENERIC_ALL,       /* access_mask */
			(FILE_SHARE_READ |	/* share_access */
			    FILE_SHARE_WRITE),
			disposition,            /* create_disposition */
			create_options,         /* create_options */
			file_attributes,        /* file_attributes */
			INTERNAL_OPEN_ONLY,     /* oplock_request */
			NULL,                   /* lease */
			0,                      /* allocation_size */
			0,                      /* private_flags */
			NULL,                   /* sd */
			NULL,                   /* ea_list */
			&fsp,                   /* result */
			NULL,                   /* pinfo */
			NULL, NULL);            /* create context */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to open or create file '%s': %s\n",
			smb_fname->base_name, nt_errstr(status));
		goto out;
	}

	/* Rename if reparented or renamed */
	if (rec && (GUID_compare(&rec->update->parent_db_guid,
				 &update->parent_db_guid) != 0 ||
		    rec->update->parent_version != update->parent_version ||
		    strcasecmp_m(rec->update->name, update->name) != 0))
	{
		struct smb_filename *new_smb_fname = NULL;
		const char *dst_original_lcomp = NULL;
		const char *newname = update->name;
		uint32_t ucf_flags = 0;

		/* Build the new path in persistent storage */
		status = dfsr_meet_get_smb_filename(tmp_ctx, db_ctx, conn,
				update, &new_smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to build update path: %s\n",
				nt_errstr(status));
			goto out;
		}

		DBG_DEBUG("Renaming (%s) '%s' -> '%s'\n",
			  fsp_fnum_dbg(fsp), fsp_str_dbg(fsp),
			  smb_fname_str_dbg(new_smb_fname));

		/*
		 * Set the original last component, since
		 * rename_internals_fsp() requires it.
		 */
		dst_original_lcomp = get_original_lcomp(new_smb_fname,
							conn,
							newname,
							ucf_flags);
		if (dst_original_lcomp == NULL) {
			DBG_ERR("No memory\n");
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		status = rename_internals_fsp(conn,
					      fsp,
					      new_smb_fname,
					      dst_original_lcomp,
					      0,
					      false);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to rename (%s) '%s' to '%s': %s\n",
				fsp_fnum_dbg(fsp), fsp_str_dbg(fsp),
				smb_fname_str_dbg(new_smb_fname),
				nt_errstr(status));
			goto out;
		}
	}

	/* TODO Set timestamps */

	*_fsp = talloc_move(mem_ctx, &fsp);

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(tmp_ctx);

	return status;
}

static NTSTATUS dfsr_meet_stream_security(TALLOC_CTX *mem_ctx,
		struct connection_struct *conn,
		int fd_in,
		struct dfsr_stream_header *header,
		struct files_struct *fsp,
		off_t *offset)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB in;
	ssize_t nread;
	enum ndr_err_code ndr_err;
	struct security_descriptor sd;

	DBG_DEBUG("Unmarshalling security stream\n");

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	in = data_blob_talloc_zero(tmp_ctx, header->block_size);
	nread = read(fd_in, in.data, header->block_size);
	*offset += nread;

	ndr_err = ndr_pull_struct_blob(&in, tmp_ctx, &sd,
			(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	data_blob_free(&in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to pull security stream: %s\n",
			ndr_errstr(ndr_err));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	status = SMB_VFS_FSET_NT_ACL(fsp, SECINFO_OWNER | SECINFO_GROUP |
			SECINFO_DACL, &sd);

out:
	TALLOC_FREE(tmp_ctx);

	return status;
}

static NTSTATUS dfsr_meet_stream_flatdata(TALLOC_CTX *mem_ctx,
		const struct frstrans_Update *update,
		int fd_in,
		struct files_struct *fsp,
		off_t *offset)
{
	NTSTATUS status;
	ssize_t remaining, nwritten;
	struct stat statbuf;
	int ret;

	DBG_DEBUG("Unmarshalling flat data stream\n");

	ret = fstat(fd_in, &statbuf);
	if (ret) {
		int saved_errno = errno;
		DBG_ERR("Failed fstat: %s\n", strerror(saved_errno));
		return map_nt_error_from_unix(saved_errno);
	}

	if (*offset >= statbuf.st_size) {
		/* Directory updates and empty files have no data */
		return NT_STATUS_OK;
	}

	/* TODO The flat data follows [MS-BKUP] 2.1. Skip header for now */
	*offset += 20;
	if (lseek(fd_in, *offset, 0) < 0) {
		int saved_errno = errno;
		DBG_ERR("Failed lseek: %s\n", strerror(saved_errno));
		status = map_nt_error_from_unix(saved_errno);
		goto out;
	}

	remaining = statbuf.st_size - (*offset);
	do {
		nwritten = SMB_VFS_RECVFILE(fd_in, fsp, -1, remaining);
		if (nwritten == -1) {
			int saved_errno = errno;
			DBG_ERR("Failed recvfile: %s\n",
				strerror(saved_errno));
			status = map_nt_error_from_unix(saved_errno);
			goto out;
		}
		*offset += nwritten;
		remaining -= nwritten;
	} while (remaining > 0);

	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS dfsr_meet_unmarshal(TALLOC_CTX *mem_ctx,
				    struct dfsr_db *db_ctx,
				    const struct frstrans_Update *update,
				    struct connection_struct *conn,
				    const char *installing_path)
{
	NTSTATUS status;
	int fd_in = 0;
	off_t offset = 0;
	ssize_t nread = 0;
	struct files_struct *fsp = NULL;

	if (installing_path == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DBG_DEBUG("Unmarshalling '%s'\n", installing_path);

	/* Unmarshal the decompressed streams */
	fd_in = open(installing_path, O_RDONLY);
	if (fd_in == -1) {
		int saved_errno = errno;
		DBG_ERR("Failed to open file %s: %s\n",
			installing_path, strerror(saved_errno));
		status = map_nt_error_from_unix(saved_errno);
		goto out;
	}

	do {
		DATA_BLOB in;
		struct dfsr_stream_header streamhdr;
		enum ndr_err_code ndr_err;

		/* Read the stream header */
		in = data_blob_talloc_zero(mem_ctx,
				sizeof(struct dfsr_stream_header));
		nread = read(fd_in, in.data, in.length);
		if (nread < 0) {
			DBG_ERR("Failed to read install file: %s\n",
				strerror(errno));
			status = map_nt_error_from_unix(errno);
			goto out;
		}

		offset += nread;
		ndr_err = ndr_pull_struct_blob(&in, mem_ctx, &streamhdr,
			(ndr_pull_flags_fn_t)ndr_pull_dfsr_stream_header);
		data_blob_free(&in);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_ERR("Failed to pull stream header: %s\n",
				ndr_errstr(ndr_err));
			status = ndr_map_error2ntstatus(ndr_err);
			goto out;
		}

		/*
		 * Handle the stream. It is not specified, but they seems
		 * to be always in the same order: metadata, security and
		 * flat data.
		 */
		switch (streamhdr.type) {
		case MS_TYPE_META_DATA:
			status = dfsr_meet_stream_metadata(mem_ctx, db_ctx,
					update, conn, fd_in, &streamhdr, &fsp,
					&offset);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("Failed to handle metadata "
					"stream: %s\n", nt_errstr(status));
				goto out;
			}
			break;
		case MS_TYPE_SECURITY_DATA:
			status = dfsr_meet_stream_security(mem_ctx, conn,
					fd_in, &streamhdr, fsp, &offset);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("Failed to handle security "
					"stream: %s\n", nt_errstr(status));
				goto out;
			}
			break;
		case MS_TYPE_FLAT_DATA:
			status = dfsr_meet_stream_flatdata(mem_ctx, update,
					fd_in, fsp, &offset);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("Failed to handle flat data "
					"stream: %s\n", nt_errstr(status));
				goto out;
			}
			break;
		default:
			break;
		}

		if (lseek(fd_in, offset, SEEK_SET) < 0) {
			int saved_errno = errno;
			DBG_ERR("Failed lseek: %s\n", strerror(saved_errno));
			status = map_nt_error_from_unix(saved_errno);
			goto out;
		}
	} while (nread > 0);

	status = NT_STATUS_OK;

out:
	if (fd_in > 0) {
		close(fd_in);
	}

	if (fsp != NULL) {
		NTSTATUS status2;
		status2 = close_file(NULL, fsp, NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(status2)) {
			DBG_ERR("Failed to close file: %s\n",
				nt_errstr(status2));
		}
	}

	return status;
}

static NTSTATUS dfsr_meet_get_conn(const char *service,
		struct conn_struct_tos **out)
{
	NTSTATUS status;
	int snum = -1;

	if (out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = create_conn_struct_tos(global_messaging_context(),
			snum, "/", get_session_info_system(), out);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to connect: %s\n", nt_errstr(status));
		return status;
	}

	/* Ignore read-only and share restrictions */
	(*out)->conn->read_only = false;
	(*out)->conn->share_access = SEC_RIGHTS_FILE_ALL;

	return NT_STATUS_OK;
}

static NTSTATUS dfsr_meet_install_update_internal(TALLOC_CTX *mem_ctx,
		struct dfsr_meet_state *state,
		const char *staged_file,
		const char *installing_dir,
		const char *root_dir,
		struct frstrans_Update *update)
{
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	char *installing_path;
	struct conn_struct_tos *conn = NULL;
	struct smb_filename *smb_dname = NULL;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Create a conn struct to go through VFS layer when installing the
	 * update. Will be allocated in current talloc_tos(). */
	status = dfsr_meet_get_conn("", &conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to create connection: %s\n",
			nt_errstr(status));
		goto out;
	}

	/* Switch to root directory */
	smb_dname = synthetic_smb_fname(tmp_ctx, root_dir, NULL, NULL, 0, 0);
	if (smb_dname == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (vfs_ChDir(conn->conn, smb_dname) == -1) {
		int saved_errno = errno;
		DBG_ERR("Failed to change to directory %s: %s\n",
			smb_dname->base_name, strerror(saved_errno));
		status = map_nt_error_from_unix(saved_errno);
		goto out;
	}

	/* Check if this update is a tombstone pertaining to a deletion */
	if (update->present == 0) {
		/* Store the tombstone */
		goto store;
	}

	/*
	 * [MS-FRS2] Section 3.2.4.1.14 File data is transferred over the wire
	 * in a format that is composed of two layers:
	 * 1. A stream of file data that consists of a custom marshaled format
	 * 2. An encapsulation of the marshaled file data stream using the
	 *    compressed data format. Even if the marshaled file data stream
	 *    is not compressed by the server, it is still encapsulated using
	 *    the compressed data format
	 */

	/* Build the installing file path */
	status = dfsr_meet_get_installing_path(tmp_ctx, installing_dir, update,
			&installing_path);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to build installing path: %s\n",
			nt_errstr(status));
		goto out;
	}

	/* Uncompress the staged file to installing area */
	status = dfsr_meet_uncompress_staged(tmp_ctx, staged_file,
			installing_path);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to uncompress staged update: %s\n",
			nt_errstr(status));
		goto out;
	}

	/* Unmarshal the streams */
	status = dfsr_meet_unmarshal(tmp_ctx, state->db_ctx, update,
			conn->conn, installing_path);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to unmarshal staged update: %s\n",
			nt_errstr(status));
		goto out;
	}

store:
	status = dfsr_meet_store(tmp_ctx, state->db_ctx, update);

out:
	if (installing_path != NULL && strlen(installing_path) > 0) {
		int rc = unlink(installing_path);
		if (rc == -1) {
			if (errno != ENOENT) {
				DBG_ERR("Failed to delete installing file "
					"'%s': %s\n",
					installing_path,
					strerror(errno));
			}
		}
	}

	if (conn != NULL) {
		SMB_VFS_DISCONNECT(conn->conn);
	}

	TALLOC_FREE(tmp_ctx);

	return status;
}

static void dfsr_meet_install_update(struct imessaging_context *imsg_ctx,
				     void *private_data,
				     uint32_t msg_type,
				     struct server_id src,
				     size_t num_fds,
				     int *fds,
				     DATA_BLOB *blob)
{
	TALLOC_CTX *tmp_ctx;
	struct dfsr_meet_install_update request;
	struct dfsr_meet_update_installed response;
	enum ndr_err_code ndr_err;
	struct dfsr_meet_state *state;
	DATA_BLOB b = data_blob_null;
	struct GUID_txt_buf txtguid;

	state = talloc_get_type(private_data, struct dfsr_meet_state);

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		DBG_ERR("No memory\n");

		/* Just send an empty response, will be considered an error */
		imessaging_send(imsg_ctx, src, MSG_DFSR_MEET_UPDATE_INSTALLED,
				&b);
		return;
	}

	ndr_err = ndr_pull_struct_blob(blob, tmp_ctx, &request,
		(ndr_pull_flags_fn_t)ndr_pull_dfsr_meet_install_update);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to pull meet update: %s\n",
			ndr_errstr(ndr_err));
		response.result = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	DBG_DEBUG("Installing update {%s}-v%lu\n",
		  GUID_buf_string(&request.update->gsvn_db_guid, &txtguid),
		  request.update->gsvn_version);

	response.result = dfsr_meet_install_update_internal(tmp_ctx, state,
			request.staged_file, request.installing_dir,
			request.root_dir, request.update);

out:
	ndr_err = ndr_push_struct_blob(&b, tmp_ctx, &response,
		(ndr_push_flags_fn_t)ndr_push_dfsr_meet_update_installed);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to push meet installed: %s\n",
			ndr_errstr(ndr_err));

		/* Just send an empty response, will be considered an error */
		b.data = NULL;
		b.length = 0;
	}

	imessaging_send(imsg_ctx, src, MSG_DFSR_MEET_UPDATE_INSTALLED, &b);

	talloc_free(tmp_ctx);
}

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
	state->db_ctx = dfsr_db_init(state, lp_state_directory());
	if (tevent_req_nomem(state->db_ctx, req)) {
		return tevent_req_post(req, ev);
	}

	status = imessaging_register(imsg_ctx, state,
			MSG_DFSR_MEET_INSTALL_UPDATE,
			dfsr_meet_install_update);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

NTSTATUS dfsr_meet_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
