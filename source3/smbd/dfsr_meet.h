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


#ifndef _SOURCE3_SMBD_DFSR_MEET_H_
#define _SOURCE3_SMBD_DFSR_MEET_H_

#include <tevent.h>

struct tevent_req *dfsr_meet_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  pid_t parent_pid);
NTSTATUS dfsr_meet_recv(struct tevent_req *req);

#endif /* _SOURCE3_SMBD_DFSR_MEET_H_ */
