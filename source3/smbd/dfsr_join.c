/*
   Unix SMB/CIFS implementation.

   DFS Replication server

   Copyright (C) David Mulder <dmulder@suse.com> 2018

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
#include "dfsr_join.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/param/param.h"
#include "source4/lib/messaging/irpc.h"
#include "gen_ndr/ndr_frsblobs.h"
#include "gen_ndr/ndr_security.h"
#include "dfsr/dfsr_db.h"
#include "system/filesys.h"
#include "lib/compression/lzhuff_xpress.h"
#include "smbd/smbd.h"
#include "auth.h"
#include "libcli/security/security.h"

NTSTATUS dfsr_send_file_update(struct files_struct *fsp,
			       DATA_BLOB in_data,
			       uint64_t in_offset)
{
	return NT_STATUS_OK;
}
