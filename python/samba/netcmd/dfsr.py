# implement samba_tool dfsr commands
#
# Copyright Samuel Cabrero <scabrero@suse.de> 2018
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import samba.getopt as options
import ldb
from samba.samdb import SamDB
from samba.auth import system_session
from samba.netcmd import (
    SuperCommand,
    Command,
    Option,
    )
from operator import attrgetter

class DfsrCommand(Command):
    def __init__(self):
        Command.__init__(self)

    def group_type_to_str(self, group_type):
        if group_type == "0":
            return "OTHER"
        if group_type == "1":
            return "SYSVOL"
        if group_type == "2":
            return "PROTECTION"
        if group_type == "3":
            return "DISTRIBUTION"
        return "UNKNOWN"

    def print_group(self, group_name=None):
        sfilter = "(objectClass=msDFSR-ReplicationGroup)"
        if group_name:
            sfilter = "(&(objectClass=msDFSR-ReplicationGroup)" \
                      "(name=%s))" % (group_name)

        dn = "CN=DFSR-GlobalSettings,CN=System,%s" % self.samdb.domain_dn()
        res = self.samdb.search(dn, scope=ldb.SCOPE_SUBTREE,
                                expression=sfilter,
                                attrs=["objectGUID", "name", "description",
                                       "msDFSR-ReplicationGroupType"])
        for msg in res:
            self.outf.write("%-11s : %s\n" % (
                "Name", str(msg.get('name'))))
            self.outf.write("%-11s : %s\n" % (
                "Domain", self.samdb.domain_dns_name()))
            self.outf.write("%-11s : %s\n" % (
                "Identifier", ndr_unpack(misc.GUID,
                                         msg.get('objectGUID', idx=0))))
            self.outf.write("%-11s : %s\n" % (
                "Type", self.group_type_to_str(
                    msg.get("msDFSR-ReplicationGroupType", idx=0))))
            self.outf.write("%-11s : %s\n" % (
                "Description", str(msg.get('description'))))
            self.outf.write("\n")
        return

class cmd_dfsr_group_list(DfsrCommand):
    """List all DFS-R groups."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("--group-name", help="Show the provided group",
               type=str, dest="group_name"),
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, group_name=None, sambaopts=None, credopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        self.samdb = SamDB(url=H, session_info=system_session(),
                           credentials=creds, lp=lp)

        self.print_group(group_name=group_name)

class cmd_dfsr_group(SuperCommand):
    """DFS Replication (DFS-R) group management."""

    subcommands = {}
    subcommands["list"] = cmd_dfsr_group_list()

class cmd_dfsr(SuperCommand):
    """DFS Replication (DFS-R) management"""

    subcommands = {}
    subcommands["group"] = cmd_dfsr_group()
