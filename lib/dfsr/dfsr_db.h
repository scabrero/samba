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

#ifndef _LIB_DFSR_DFSR_DB_H_
#define _LIB_DFSR_DFSR_DB_H_

#include "librpc/gen_ndr/frsblobs.h"

struct GUID;
struct dfsr_db;

struct dfsr_db *dfsr_db_init(TALLOC_CTX *mem_ctx, const char *base_path);

NTSTATUS dfsr_db_store(struct dfsr_db *db_ctx,
		const struct GUID *uid_db_guid,
		uint64_t uid_version,
		const struct dfsr_db_record *record);

NTSTATUS dfsr_db_fetch(struct dfsr_db *db_ctx,
		TALLOC_CTX *mem_ctx,
		const struct GUID *uid_db_guid,
		uint64_t uid_version,
		struct dfsr_db_record **record);

#endif /* _LIB_DFSR_DFSR_DB_H_ */
