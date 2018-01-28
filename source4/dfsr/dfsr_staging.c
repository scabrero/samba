/*
   Unix SMB/CIFS mplementation.

   DFS Replication service

   Copyright (C) Matthieu Patou <mat@matws.net> 2013-2014
   Copyright (C) Samuel Cabrero <scabrero@suse.de> 2018

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
#include "system/filesys.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

NTSTATUS dfsrsrv_staging_get_path(TALLOC_CTX *mem_ctx,
				  const char *staging_dir,
				  const struct frstrans_Update *update,
				  char **path)
{
	struct GUID_txt_buf tmp_buf1;
	struct GUID_txt_buf tmp_buf2;

	if (path == NULL || update == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*path = talloc_asprintf(mem_ctx, "%s/%s/%s_%lu",
				staging_dir,
				GUID_buf_string(&update->content_set_guid,
						&tmp_buf1),
				GUID_buf_string(&update->gsvn_db_guid,
						&tmp_buf2),
				update->gsvn_version);
	if (*path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

NTSTATUS dfsrsrv_staging_write_buffer(TALLOC_CTX *mem_ctx,
				      const char *staging_file,
				      const uint8_t *buffer,
				      uint32_t buffer_size,
				      bool append)
{
	TALLOC_CTX *tmp_ctx;
	int flags = 0;
	int fd = 0;
	int ret = 0;
	size_t w_size;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	flags = O_CREAT | O_RDWR;
	if (append == false) {
		flags |= O_TRUNC;
	} else {
		flags |= O_APPEND;
	}

	fd = open(staging_file, flags, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		DBG_ERR("Unable to create staging file %s: %s\n",
			staging_file, strerror(errno));
		talloc_free(tmp_ctx);
		return NT_STATUS_FILE_INVALID;
	}

	if (buffer_size != 0) {
		w_size = write(fd, buffer, buffer_size);

		if (w_size != buffer_size) {
			DBG_ERR("Unable to write %u bytes on staging file %s: "
				"%s\n", buffer_size, staging_file,
				strerror(errno));
			close(fd);
			talloc_free(tmp_ctx);
			return NT_STATUS_UNEXPECTED_IO_ERROR;
		}
	}

	ret = close(fd);
	if (ret != 0) {
		DBG_ERR("Unable to close %s: %s\n", staging_file,
			strerror(errno));
		talloc_free(tmp_ctx);
		return NT_STATUS_FILE_INVALID;
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}
