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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DFSR

NTSTATUS dfsrsrv_update_known_vv(struct dfsrsrv_content_set *set,
		struct frstrans_VersionVector *vv,
		uint32_t vv_count)
{
	int i, j;
	struct GUID_txt_buf txtguid1, txtguid2;

	for (i = 0; i < vv_count; i++) {
		bool found = false;

		for (j = 0; j < set->known_vv_count; j++) {
			if (memcmp(&vv[i].db_guid, &set->known_vv[j].db_guid,
					sizeof(struct GUID)) == 0) {
				found = true;

				if (vv[i].high > set->known_vv[j].high) {
					set->known_vv[j].high = vv[i].high;
				}
				if (vv[i].low < set->known_vv[j].low) {
					set->known_vv[j].low = vv[i].low;
				}
				break;
			}
		}

		if (!found) {
			set->known_vv = talloc_realloc(set, set->known_vv,
					struct frstrans_VersionVector,
					set->known_vv_count + 1);
			if (set->known_vv == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			set->known_vv[set->known_vv_count].db_guid =
					vv[i].db_guid;
			set->known_vv[set->known_vv_count].low = vv[i].low;
			set->known_vv[set->known_vv_count].high = vv[i].high;
			set->known_vv_count += 1;
		}
	}

	DBG_INFO("Content set {%s} known version vectors updated to:\n",
		 GUID_buf_string(&set->guid, &txtguid1));
	for (i = 0; i < set->known_vv_count; i++) {
		DBG_INFO("\t{%s} - [%lu, %lu]\n",
			 GUID_buf_string(&set->known_vv[i].db_guid, &txtguid2),
			 set->known_vv[i].low,
			 set->known_vv[i].high);
	}

	return NT_STATUS_OK;
}

NTSTATUS dfsrsrv_calculate_delta_vectors(TALLOC_CTX *mem_ctx,
					 struct frstrans_VersionVector *in,
					 uint32_t in_count,
					 struct frstrans_VersionVector **out,
					 uint32_t *out_count,
					 struct frstrans_VersionVector *known,
					 uint32_t known_count)
{
	uint32_t i, j;
	struct frstrans_VersionVector *tmp_out = NULL;
	uint32_t tmp_count = 0;

	if (out == NULL || out_count == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i = 0; i < in_count; i++) {
		bool found = false;
		for (j = 0; j < known_count; j++) {
			int res;
			res = GUID_compare(&in[i].db_guid, &known[j].db_guid);
			if (res != 0) {
				continue;
			}

			/* Same guid */
			found = true;

			/* Check high */
			if (known[j].high >= in[i].high) {
				/* We know already every thing */
				break;
			} else {
				tmp_out = talloc_realloc(mem_ctx,
						tmp_out,
						struct frstrans_VersionVector,
						tmp_count + 1);
				if (tmp_out == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
				tmp_out[tmp_count] = in[i];
				tmp_out[tmp_count].low = known[i].high;
				tmp_count++;
				break;
			}
		}

		if (!found) {
			tmp_out = talloc_realloc(mem_ctx,
					tmp_out,
					struct frstrans_VersionVector,
					tmp_count + 1);
			if (tmp_out == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			tmp_out[tmp_count] = in[i];
			tmp_count++;
		}
	}

	*out = tmp_out;
	*out_count = tmp_count;

	return NT_STATUS_OK;
}

NTSTATUS dfsrsrv_lexicofilter_vector(TALLOC_CTX *mem_ctx,
				     struct GUID dbguid, uint64_t version,
				     struct frstrans_VersionVector *in,
				     uint32_t in_count,
				     struct frstrans_VersionVector **out,
				     uint32_t *out_count)
{
	uint32_t i;
	struct frstrans_VersionVector *tmp = NULL;
	uint32_t tmp_count = 0;
	struct GUID_txt_buf txtguid1;

	if (out == NULL || out_count == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_INFO("Filtering version vectors by {%s}-%lu\n",
		 GUID_buf_string(&dbguid, &txtguid1), version);

	for (i = 0; i < in_count; i++) {
		/* [MS-FRS2] 3.3.4.6.2 GUIDs are compared using a
		 * lexicographic left-to-right comparison of each byte, where
		 * each byte is treated as an unsigned 8-bit number. The
		 * C-standard routine, memcmp, can for instance be used to
		 * realize this ordering as a positive return value from this
		 * routine stipulates that a GUID is lexicographically
		 * largest */
		int res = memcmp(&in[i].db_guid, &dbguid, sizeof(struct GUID));
		if (res < 0) {
			/* Lexicographically less so we ignore it */
			continue;
		} else if (res > 0) {
			/* Lexicographically more so we keep it */
			tmp = talloc_realloc(mem_ctx, tmp,
					struct frstrans_VersionVector,
					tmp_count + 1);
			if (tmp == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			tmp[tmp_count] = in[i];
			tmp_count++;
			continue;
		} else {
			/* Equal, let's see if the high is > version */
			if (in[i].high > version) {
				tmp = talloc_realloc(mem_ctx, tmp,
						struct frstrans_VersionVector,
						tmp_count + 1);
				if (tmp == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
				tmp[tmp_count] = in[i];
				tmp[tmp_count].low = version;
				tmp_count++;
			}
			continue;
		}
	}

	/* If everything is filtered, return an allocated vector to avoid
	 * ndr NULL [ref] pointer error, but keep count to 0 */
	if (tmp == NULL) {
		tmp = talloc_zero(mem_ctx, struct frstrans_VersionVector);
		if (tmp == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tmp_count = 0;
	}

	*out = tmp;
	*out_count = tmp_count;

	return NT_STATUS_OK;
}

NTSTATUS dfsrsrv_vv_copy(TALLOC_CTX *mem_ctx,
			 struct frstrans_VersionVector *in,
			 struct frstrans_VersionVector **out,
			 uint32_t count)
{
	struct frstrans_VersionVector *tmp;
	uint32_t i;

	if (out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	tmp = talloc_array(mem_ctx, struct frstrans_VersionVector, count);
	if (tmp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < count; i++) {
		tmp[i] = in[i];
	}

	*out = tmp;

	return NT_STATUS_OK;
}
