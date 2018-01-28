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

#ifndef _dfsr_SERVICE_H_
#define _dfsr_SERVICE_H_

#include "librpc/gen_ndr/ndr_frstrans_c.h"

#define REPLICA_GROUP_TYPE_SYSVOL	1

struct ldb_dn;

enum dfsr_connection_state {
	CONNECTION_STATE_DISCONNECTED,
	CONNECTION_STATE_CONNECTED,
	CONNECTION_STATE_POLLING
};

enum dfsr_session_state {
	SESSION_STATE_RESTART,
	SESSION_STATE_IN_SESSION,
	SESSION_STATE_REQUESTING_VV,
	SESSION_STATE_POLL_AGAIN,
	SESSION_STATE_REQUESTING_UPDATES
};

struct dfsrsrv_session {
	struct dfsrsrv_session *prev, *next;

	enum dfsr_session_state state;

	/* the connection this session belongs to */
	struct dfsrsrv_connection *conn;

	/* the content set this session belongs to */
	struct dfsrsrv_content_set *set;

	/* the tevent request running the session */
	struct tevent_req *req;
};

struct dfsrsrv_connection {
	struct dfsrsrv_connection *prev, *next;

	struct GUID guid;
	bool enabled;

	/* the binding for the outgoing connection */
	struct dcerpc_binding *binding;

	/* the replication group this connection belongs to */
	struct dfsrsrv_replication_group *group;

	/* the state of this connection */
	enum dfsr_connection_state state;

	/* the sessions running on this connection */
	struct dfsrsrv_session *sessions;

	/* the tevent request running the connection */
	struct tevent_req *req;
};

struct dfsrsrv_content_set {
	struct dfsrsrv_content_set *prev, *next;

	struct GUID guid;
	const char *name;
	bool enabled;
	bool read_only;

	/* Local paths of this set */
	const char *conflict_path;
	const char *staging_path;
	const char *installing_path;
	const char *root_path;

	/* What we know about this content set */
	struct frstrans_VersionVector *known_vv;
	uint32_t known_vv_count;

	/* replication group this content set belongs to */
	struct dfsrsrv_replication_group *group;
};

struct dfsrsrv_replication_group {
	struct dfsrsrv_replication_group *prev, *next;

	struct GUID guid;
	const char *name;
	int type;

	/* list of content sets this server is subscribed */
	struct dfsrsrv_content_set *sets;

	/* list of connections to other members to replicate from
	 * following the group topology */
	struct dfsrsrv_connection *connections;
};

struct dfsrsrv_update {
	struct dfsrsrv_update *prev, *next;
	struct frstrans_Update *update;

	struct tevent_req *req;
};

struct dfsrsrv_vv_queue {
	struct dfsrsrv_vv_queue *prev, *next;

	struct frstrans_VersionVector *vv;
	uint32_t vv_count;

	struct dfsrsrv_update *pending_updates;
	struct dfsrsrv_update *current_update;

	struct dfsrsrv_content_set *set;
	struct dfsrsrv_connection *conn;
	struct dcerpc_pipe *pipe;
};

struct dfsrsrv_service {
	/* the whole dfsr service is in one task */
	struct task_server *task;

	/* the time the service was started */
	struct timeval startup_time;

	/* system session info with machine account credentials */
	struct auth_session_info *system_session_info;

	/* a connection to the local samdb */
	struct ldb_context *samdb;

	/* some stuff for periodic processing */
	struct {
		/* the interval between to periodic runs */
		uint32_t interval;

		/* the timestamp for the next event */
		struct timeval next_event;

		/* here we have a reference to the timed event
		 * the schedules the periodic stuff */
		struct tevent_timer *te;
	} periodic;

	struct {
		/*
		 * here we have a reference to the immidicate event that was
		 * scheduled after receive a batch of updates
		 */
		struct tevent_immediate *im;
	} pending;

	struct {
		/* Current version vector being processed */
		struct dfsrsrv_vv_queue *current_vv;

		/* List of version vectors pending to be processed */
		struct dfsrsrv_vv_queue *pending_vv;
	} process_queue;

	/* list of replication groups this server is subscriber */
	struct dfsrsrv_replication_group *subscriptions;
};

#include "dfsr/dfsr_service_proto.h"

#endif /* _dfsr_SERVICE_H_ */
