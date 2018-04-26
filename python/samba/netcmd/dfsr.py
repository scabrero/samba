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
from samba.ndr import ndr_unpack, ndr_pack, ndr_print
from samba.dcerpc import misc
from samba.netcmd import (
    SuperCommand,
    Command,
    CommandError,
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

    def print_folder(self, group_msg, folder_name=None):
        sfilter = "(objectClass=msDFSR-ContentSet)"
        if folder_name:
            sfilter = "(&(objectClass=msDFSR-ContentSet)" \
                      "(name=%s))" % folder_name
        res = self.samdb.search(group_msg.dn, scope=ldb.SCOPE_SUBTREE,
                                expression=sfilter,
                                attrs=["name", "objectGUID", "description",
                                       "msDFSR-FileFilter",
                                       "msDFSR-DirectoryFilter"])
        if (len(res) == 0):
            return

        for folder_msg in res:
            self.outf.write("%-17s : %s\n" % ("Group Name",
                str(group_msg.get('name'))))
            self.outf.write("%-17s : %s\n" % ("Folder Name",
                str(folder_msg.get('name'))))
            self.outf.write("%-17s : %s\n" % ("Domain",
                self.samdb.domain_dns_name()))
            self.outf.write("%-17s : %s\n" % ("Identifier",
                ndr_unpack(misc.GUID, folder_msg.get('objectGUID', idx=0))))
            self.outf.write("%-17s : %s\n" % ("Description",
                str(folder_msg.get('description'))))
            self.outf.write("%-17s : %s\n" % ("File Filter",
                str(folder_msg.get('msDFSR-FileFilter'))))
            self.outf.write("%-17s : %s\n" % ("Directory Filter",
                str(folder_msg.get('msDFSR-DirectoryFilter'))))
            self.outf.write("\n")
        return

    def print_group_folders(self, group_name=None, folder_name=None):
        sfilter = "(objectClass=msDFSR-ReplicationGroup)"
        if group_name:
            sfilter = "(&(objectClass=msDFSR-ReplicationGroup)" \
                      "(name=%s))" % group_name

        base_dn = "CN=DFSR-GlobalSettings,CN=System,%s" % (
                  self.samdb.domain_dn())
        res = self.samdb.search(base_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=sfilter,
                                attrs=["name"])
        for group_msg in res:
            self.print_folder(group_msg, folder_name=folder_name)
        return

    def print_group_member(self, group_msg, topology_msg, member_msg,
                           computer_msg):
        # Search inbound connections
        sfilter = "(objectClass=msDFSR-Connection)"
        res = self.samdb.search(member_msg.dn, scope=ldb.SCOPE_SUBTREE,
                                expression=sfilter,
                                attrs=[])
        inbound_conn = len(res)

        # Search outbound connections
        sfilter = "(&(objectClass=msDFSR-Connection)" \
                  "(fromServer=%s))" % member_msg.dn
        res = self.samdb.search(topology_msg.dn, scope=ldb.SCOPE_SUBTREE,
                                expression=sfilter,
                                attrs=[])
        outbound_conn = len(res)

        self.outf.write("%-20s : %s\n" % ("Group Name",
            str(group_msg.get('name'))))
        self.outf.write("%-20s : %s\n" % ("Computer Name",
            str(computer_msg.get('name'))))
        self.outf.write("%-20s : %s\n" % ("Domain", self.samdb.domain_dns_name()))
        self.outf.write("%-20s : %s\n" % ("Identifier",
            ndr_unpack(misc.GUID, member_msg.get("objectGUID", idx=0))))
        self.outf.write("%-20s : %s\n" %
                ("Description", str(member_msg.get("msDFSR-Keywords"))))
        self.outf.write("%-20s : %s\n" %
                ("Dns Name", str(computer_msg.get("dNSHostName", idx=0))))
        self.outf.write("%-20s : %s\n" %
                ("Inbound connections", inbound_conn))
        self.outf.write("%-20s : %s\n" %
                ("Outbound connections", outbound_conn))
        self.outf.write("\n")

    def print_group_members(self, group_msg, computer_name=None):
        # Search topology
        sfilter = "(objectClass=msDFSR-Topology)"
        res = self.samdb.search(group_msg.dn, scope=ldb.SCOPE_SUBTREE,
                           expression=sfilter, attrs=[])
        assert(len(res) == 1)

        topology_msg = res[0]

        # Search members
        res = self.samdb.search(topology_msg.dn, scope=ldb.SCOPE_SUBTREE,
                           expression="(objectClass=msDFSR-Member)",
                           attrs=["objectGUID", "msDFSR-ComputerReference"])
        if (len(res) == 0):
            return

        for member_msg in res:
            sfilter = "(objectClass=computer)"
            if computer_name:
                sfilter = "(&(objectClass=computer)" \
                          "(name=%s))" % computer_name
            computer_dn = ldb.Dn(self.samdb,
                    member_msg.get("msDFSR-ComputerReference", idx=0))
            res2 = self.samdb.search(computer_dn, scope=ldb.SCOPE_BASE,
                                expression=sfilter,
                                attrs=["name", "dNSHostName"])
            if (len(res2) == 0):
                continue

            computer_msg = res2[0]

            self.print_group_member(group_msg, topology_msg, member_msg,
                                    computer_msg)
        return

    def print_members(self, group_name=None, computer_name=None):
        # Search group
        sfilter = "(objectClass=msDFSR-ReplicationGroup)"
        if group_name:
            sfilter = "(&(objectClass=msDFSR-ReplicationGroup)" \
                      "(name=%s))" % group_name
        dfsr_dn = "CN=DFSR-GlobalSettings,CN=System,%s" % (
                  self.samdb.domain_dn())
        res = self.samdb.search(dfsr_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=sfilter, attrs=["name"])
        for group_msg in res:
            self.print_group_members(group_msg, computer_name=computer_name)
        return

    def print_computer_subscription(self, group_msg, computer_msg,
                                    subscriber_msg, folder_name=None):
        # Get folder subscriptions
        sfilter = "(objectClass=msDFSR-Subscription)"
        res = self.samdb.search(subscriber_msg.dn, scope=ldb.SCOPE_SUBTREE,
                           expression=sfilter,
                           attrs=["objectGUID",
                                  "msDFSR-ContentSetGuid",
                                  "msDFSR-RootPath",
                                  "msDFSR-StagingPath",
                                  "msDFSR-StagingSizeInMb",
                                  "msDFSR-ConflictPath",
                                  "msDFSR-ConflictSizeInMb",
                                  "msDFSR-ReadOnly",
                                  "msDFSR-Enabled",
                                  "msDFSR-Options"])
        for msg in res:
            folder_guid = msg.get("msDFSR-ContentSetGuid", idx=0)
            folder_guid = self.samdb.guid2hexstring(folder_guid)

            # Search folder
            sfilter = "(&(objectClass=msDFSR-ContentSet)" \
                      "(ObjectGUID=%s))" % folder_guid
            if folder_name:
                sfilter = "(&(objectClass=msDFSR-ContentSet)" \
                          "(ObjectGUID=%s)" \
                          "(name=%s))" % (folder_guid, folder_name)
            res2 = self.samdb.search(group_msg.dn, scope=ldb.SCOPE_SUBTREE,
                                     expression=sfilter, attrs=["name"])
            if (len(res2) == 0):
                continue

            folder_msg = res2[0]

            read_only = msg.get("msDFSR-ReadOnly", idx=0)
            if read_only == 1:
                read_only = True
            else:
                read_only = False

            enabled = msg.get("msDFSR-Enabled", idx=0)
            if enabled == 1:
                enabled = True
            else:
                enabled = False

            primary = msg.get("msDFSR-Options", idx=0)
            if int(primary) & 0x1:
                primary = True
            else:
                primary = False

            self.outf.write("%-28s : %s\n" % ("Group Name",
                str(group_msg.get('name'))))
            self.outf.write("%-28s : %s\n" % ("Computer Name",
                str(computer_msg.get('name'))))
            self.outf.write("%-28s : %s\n" % ("Folder Name",
                str(folder_msg.get('name'))))
            self.outf.write("%-28s : %s\n" % ("Domain",
                self.samdb.domain_dns_name()))
            self.outf.write("%-28s : %s\n" % ("Identifier",
                ndr_unpack(misc.GUID, msg.get("objectGUID", idx=0))))
            self.outf.write("%-28s : %s\n" %
                ("Distinguished Name", str(msg.dn)))
            self.outf.write("%-28s : %s\n" %
                ("Root Path", str(msg.get("msDFSR-RootPath"))))
            self.outf.write("%-28s : %s\n" %
                ("Staging Path", str(msg.get("msDFSR-StagingPath", idx=0))))
            self.outf.write("%-28s : %s\n" %
                ("Staging Quota (in MB)", str(msg.get("msDFSR-StagingSizeInMb"))))
            self.outf.write("%-28s : %s\n" %
                ("Conflict Path", str(msg.get("msDFSR-ConflictPath", idx=0))))
            self.outf.write("%-28s : %s\n" %
                ("Conflict Quota (in MB)", str(msg.get("msDFSR-ConflictSizeInMB"))))
            self.outf.write("%-28s : %s\n" %
                ("Primary Member", str(primary)))
            self.outf.write("%-28s : %s\n" %
                ("Read Only", str(read_only)))
            self.outf.write("%-28s : %s\n" %
                ("Enabled", str(enabled)))
            self.outf.write("\n")

        return

    def print_group_subscription(self, group_msg, folder_name=None,
                                 computer_name=None):
        group_guid = self.samdb.guid2hexstring(group_msg.get("objectGUID", idx=0))

        # Get the members
        sfilter = "(objectClass=msDFSR-Member)"
        res = self.samdb.search(group_msg.dn, scope=ldb.SCOPE_SUBTREE,
                                expression=sfilter,
                                attrs=["msDFSR-ComputerReference"])
        for member in res:
            computer_dn = member.get("msDFSR-ComputerReference", idx=0)
            sfilter = "(objectClass=computer)"
            if computer_name:
                sfilter = "(&(objectClass=computer)(name=%s))" % computer_name
            computer_res = self.samdb.search(computer_dn, scope=ldb.SCOPE_BASE,
                                             expression=sfilter,
                                             attrs=["name"])
            if (len(computer_res) == 0):
                continue

            computer_msg = computer_res[0]

            # Search local settings
            sfilter = "(objectClass=msDFSR-LocalSettings)"
            res2 = self.samdb.search(computer_msg.dn, scope=ldb.SCOPE_SUBTREE,
                                     expression=sfilter, attrs=[])
            if (len(res2) == 0):
                continue

            dfsr_local_dn = res2[0].dn

            # Search subcription to replica group
            sfilter = "(&(objectClass=msDFSR-Subscriber)" \
                      "(msDFSR-ReplicationGroupGuid=%s))" % group_guid
            res2 = self.samdb.search(dfsr_local_dn, scope=ldb.SCOPE_SUBTREE,
                                     expression=sfilter, attrs=[])
            if (len(res2) == 0):
                continue

            for subscriber_msg in res2:
                self.print_computer_subscription(group_msg, computer_msg,
                                                 subscriber_msg,
                                                 folder_name=folder_name)
        return

    def print_subscription(self, group_name=None, folder_name=None,
                           computer_name=None):
        # Search group
        base_dn = "CN=DFSR-GlobalSettings,CN=System,%s" % self.samdb.domain_dn()
        sfilter = "(objectClass=msDFSR-ReplicationGroup)"
        if group_name:
            sfilter = "(&(objectClass=msDFSR-ReplicationGroup)" \
                      "(name=%s))" % (group_name)
        res = self.samdb.search(base_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=sfilter, attrs=["name", "objectGUID"])

        if (len(res) == 0):
            raise Exception('Unable to find replication groups')

        for group in res:
            self.print_group_subscription(group,
                                          folder_name=folder_name,
                                          computer_name=computer_name)
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

class cmd_dfsr_group_create(DfsrCommand):
    """Create a new DFS-R group."""

    synopsis = "%prog <group_name> [options]"

    takes_args = ["group_name"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--type", help="Replication group type",
               type=int, dest="group_type", default=0),
        Option("--description", help="Group's description",
               type=str, dest="description"),
       ]

    def run(self, group_name, group_type=0, credopts=None, sambaopts=None,
            versionopts=None, H=None, description=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        self.samdb = SamDB(url=H, session_info=system_session(),
                           credentials=creds, lp=lp)

        try:
            self.samdb.dfsr_group_create(group_name, group_type=group_type,
                                         description=description)
            self.print_group(group_name=group_name)
        except Exception as e:
            raise CommandError('Failed to create replication group "%s"' %
                               group_name, e)
        return

class cmd_dfsr_folder_list(DfsrCommand):
    """List DFS-R group folders."""

    synopsis = "%prog <group_name> [options]"

    takes_args = []

    takes_options = [
        Option("--group-name", help="Show folders for the provided group only",
               type=str, dest="group_name"),
        Option("--folder-name", help="Show the provided folder only",
               type=str, dest="folder_name"),
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, group_name=None, folder_name=None, sambaopts=None,
            credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        self.samdb = SamDB(url=H, session_info=system_session(),
                           credentials=creds, lp=lp)

        self.print_group_folders(group_name=group_name,
                                 folder_name=folder_name)
        return

class cmd_dfsr_folder_create(DfsrCommand):
    """Create a new DFS-R folder."""

    synopsis = "%prog <group_name> <folder_name> [options]"

    takes_args = ["group_name", "folder_name"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--description", help="Folder's description",
               type=str, dest="description"),
        Option("--file-filter", help="A comma-separated list of 0 or more "
                                     "wildcard file name filters. Any file "
                                     "whose name matches any of the filters "
                                     "will be excluded from replication. The "
                                     "value should contain, at a minimum, "
                                     "'*.tmp,*.bak, ~*'",
               type=str, dest="file_filter"),
        Option("--directory-filter", help="A comma-separated list of 0 or "
                                          "more wildcard folder name filters. "
                                          "Any folder whose name matches any "
                                          "of the filters will be excluded "
                                          "from replication.",
               type=str, dest="directory_filter"),
       ]

    def run(self, group_name, folder_name, description=None, file_filter=None,
            directory_filter=None, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        self.samdb = SamDB(url=H, session_info=system_session(),
                           credentials=creds, lp=lp)

        try:
            self.samdb.dfsr_folder_create(group_name, folder_name,
                                          description=description,
                                          file_filter=file_filter,
                                          directory_filter=directory_filter)
        except Exception as e:
            raise CommandError('Failed to create replicated folder "%s"' %
                               folder_name, e)
        self.print_group_folders(group_name=group_name,
                                 folder_name=folder_name)
        return

class cmd_dfsr_member_list(DfsrCommand):
    """List DFS-R group members."""

    synopsis = "%prog [options]"

    takes_args = []

    takes_options = [
        Option("--group-name", help="List members for this group only",
               type=str, dest="group_name"),
        Option("--computer-name", help="List this computer membership only",
               type=str, dest="computer_name"),
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, group_name=None, computer_name=None, sambaopts=None,
            credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        self.samdb = SamDB(url=H, session_info=system_session(),
                           credentials=creds, lp=lp)
        self.print_members(group_name=group_name, computer_name=computer_name)
        return

class cmd_dfsr_member_add(DfsrCommand):
    """Add DFS-R member to replication group."""

    synopsis = "%prog <group_name> <computer_name> [options]"

    takes_args = ["group_name", "computer_name"]

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--description", help="Member's description",
               type=str, dest="description"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, group_name, computer_name, description=None,
            sambaopts=None, credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        self.samdb = SamDB(url=H, session_info=system_session(),
                           credentials=creds, lp=lp)

        try:
            self.samdb.dfsr_member_add(group_name, computer_name,
                                       description=description)
        except Exception as e:
            raise CommandError('Failed to add computer "%s"' %
                               (computer_name), e)
        self.print_members(group_name=group_name, computer_name=computer_name)
        return

class cmd_dfsr_subscription_list(DfsrCommand):
    """List DFS-R replication group member subscriptions."""

    synopsis = "%prog [options]"

    takes_args = []

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--group-name", help="List subscriptions for this group only",
               type=str, dest="group_name"),
        Option("--folder-name", help="List subscriptions for this folder only",
               type=str, dest="folder_name"),
        Option("--computer-name", help="List subscriptions for this computer only",
               type=str, dest="computer_name")
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }


    def run(self, group_name=None, folder_name=None, computer_name=None,
            sambaopts=None, credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        self.samdb = SamDB(url=H, session_info=system_session(),
                           credentials=creds, lp=lp)

        self.print_subscription(group_name=group_name,
                                folder_name=folder_name,
                                computer_name=computer_name)

        return

class cmd_dfsr_group(SuperCommand):
    """DFS Replication (DFS-R) group management."""

    subcommands = {}
    subcommands["list"] = cmd_dfsr_group_list()
    subcommands["create"] = cmd_dfsr_group_create()

class cmd_dfsr_folder(SuperCommand):
    """DFS Replication (DFS-R) folder management."""

    subcommands = {}
    subcommands["list"] = cmd_dfsr_folder_list()
    subcommands["create"] = cmd_dfsr_folder_create()

class cmd_dfsr_member(SuperCommand):
    """DFS Replication (DFS-R) member management."""

    subcommands = {}
    subcommands["list"] = cmd_dfsr_member_list()
    subcommands["add"] = cmd_dfsr_member_add()

class cmd_dfsr_subscription(SuperCommand):
    """DFS Replication (DFS-R) subscription management."""

    subcommands = {}
    subcommands["list"] = cmd_dfsr_subscription_list()

class cmd_dfsr(SuperCommand):
    """DFS Replication (DFS-R) management"""

    subcommands = {}
    subcommands["group"] = cmd_dfsr_group()
    subcommands["folder"] = cmd_dfsr_folder()
    subcommands["member"] = cmd_dfsr_member()
    subcommands["subscription"] = cmd_dfsr_subscription()
