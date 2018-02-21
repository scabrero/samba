# Unix SMB/CIFS implementation.
# Copyright (C) Samuel Cabrero  <scabrero@suse.de> 2018
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

import os
import sys
from samba import credentials, param, smb
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.param import LoadParm
from samba.tests import TestCase
from time import sleep
import samba.getopt as options
import optparse

from samba import credentials, param

parser = optparse.OptionParser("dfsr.py <server name> <client name> <share>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()
lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
if len(args) < 3:
    parser.print_usage()
    sys.exit(1)

server_name = args[0]
client_name = args[1]
share_name = args[2]

class DFSRClientTests(TestCase):

    def assertExists(self, fname, present):
        for i in range(0, 100):
            repl = self.client_conn.chkpath(fname)
            if present:
                if not repl:
                    sleep(0.1)
                    continue
            else:
                if repl:
                    sleep(0.1)
                    continue
        if present:
            self.assertTrue(repl)
        else:
            self.assertTrue(not repl)

    def assertContent(self, fname, content):
        data = "WRONG!"
        for i in range(0, 100):
            try:
                data = self.client_conn.loadfile(fname)
            except Exception:
                sleep(0.1)
                continue
        self.assertEquals(data, content)

    def setUp(self):
        super(DFSRClientTests, self).setUp()
        self.lp = lp
        self.creds = creds
        self.server_name = server_name
        self.client_name = client_name
        self.share_name = share_name
        self.server_conn = smb.SMB(server_name, share_name, lp=self.lp, creds=self.creds)
        self.client_conn = smb.SMB(client_name, share_name, lp=self.lp, creds=self.creds)
        self.testroot = "dfsr-tests"
        try:
            self.server_conn.deltree(self.testroot)
        except Exception:
            pass
        self.assertExists(self.testroot, False)

        self.server_conn.mkdir(self.testroot)
        self.assertExists(self.testroot, True)

    def test_basic_operations(self):
        # Create some folders
        folders = [ "folder-0",
                    "folder-0\\folder-1",
                    "folder-0\\folder-2",
                    "folder-3",
                    "folder-3\\folder-4",
                    "folder-3\\folder-5"]

        for f in folders:
            fname = "%s\\%s" % (self.testroot, f)
            self.server_conn.mkdir(fname)
            self.assertExists(fname, True)

        # Create some files
        for i in range(6):
            text = "test %d" % i
            fname = "%s\\test-%d.txt" % (self.testroot, i)
            self.server_conn.savefile(fname, text)
            self.assertContent(fname, text)

        # Move files around
        for i in range(6):
            text = "test %d" % i
            src_fname = "%s\\test-%d.txt" % (self.testroot, i)
            dst_fname = "%s\\%s\\test-%d.txt" % (self.testroot, folders[i], i)
            self.server_conn.rename(src_fname, dst_fname)
            self.assertExists(src_fname, False)
            self.assertContent(dst_fname, text)

        # Move folders around
        src_fname = "%s\\folder-0\\folder-1" % self.testroot
        dst_fname = "%s\\folder-1" % self.testroot
        self.assertContent("%s\\test-1.txt" % src_fname, "test 1")
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)
        self.assertContent("%s\\test-1.txt" % dst_fname, "test 1")

        src_fname = "%s\\folder-0" % self.testroot
        dst_fname = "%s\\folder-1\\folder-0" % self.testroot
        self.assertContent("%s\\test-0.txt" % src_fname, "test 0")
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)
        self.assertContent("%s\\test-0.txt" % dst_fname, "test 0")
        self.assertContent("%s\\folder-2\\test-2.txt" % dst_fname, "test 2")

        src_fname = "%s\\folder-3\\folder-4" % self.testroot
        dst_fname = "%s\\folder-3\\folder-5\\folder-4" % self.testroot
        self.assertContent("%s\\test-4.txt" % src_fname, "test 4")
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)
        self.assertContent("%s\\test-4.txt" % dst_fname, "test 4")

        src_fname = "%s\\folder-1\\folder-0\\folder-2" % self.testroot
        dst_fname = "%s\\folder-3\\folder-5\\folder-4\\folder-2" % self.testroot
        self.assertContent("%s\\test-2.txt" % src_fname, "test 2")
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)
        self.assertContent("%s\\test-2.txt" % dst_fname, "test 2")

        folders = [ "folder-1",
                    "folder-1\\folder-0",
                    "folder-3",
                    "folder-3\\folder-5",
                    "folder-3\\folder-5\\folder-4",
                    "folder-3\\folder-5\\folder-4\\folder-2" ]

        # Rename folders
        src_fname = "%s\\folder-1" % (self.testroot)
        dst_fname = "%s\\folder-1-renamed" % (self.testroot)
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)

        src_fname = "%s\\folder-1-renamed\\folder-0" % (self.testroot)
        dst_fname = "%s\\folder-1-renamed\\folder-0-renamed" % (self.testroot)
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)

        src_fname = "%s\\folder-3" % (self.testroot)
        dst_fname = "%s\\folder-3-renamed" % (self.testroot)
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)

        src_fname = "%s\\folder-3-renamed\\folder-5\\folder-4" % (self.testroot)
        dst_fname = "%s\\folder-3-renamed\\folder-5\\folder-4-renamed" % (self.testroot)
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)

        src_fname = "%s\\folder-3-renamed\\folder-5\\folder-4-renamed\\folder-2" % (self.testroot)
        dst_fname = "%s\\folder-3-renamed\\folder-5\\folder-4-renamed\\folder-2-renamed" % (self.testroot)
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)

        src_fname = "%s\\folder-3-renamed\\folder-5" % (self.testroot)
        dst_fname = "%s\\folder-3-renamed\\folder-5-renamed" % (self.testroot)
        self.server_conn.rename(src_fname, dst_fname)
        self.assertExists(src_fname, False)
        self.assertExists(dst_fname, True)

        folders = [ "folder-1-renamed\\folder-0-renamed",
                    "folder-1-renamed",
                    "folder-3-renamed\\folder-5-renamed\\folder-4-renamed\\folder-2-renamed",
                    "folder-3-renamed",
                    "folder-3-renamed\\folder-5-renamed\\folder-4-renamed",
                    "folder-3-renamed\\folder-5-renamed" ]
        for f in folders:
            self.assertExists("%s\\%s" % (self.testroot, f), True)

        # Rename files
        for i in range(6):
            src_fname = "%s\\%s\\test-%d.txt" % (self.testroot, folders[i], i)
            dst_fname = "%s\\%s\\test-%d-renamed.txt" % (self.testroot, folders[i], i)
            self.assertContent(src_fname, "test %d" % i)
            self.server_conn.rename(src_fname, dst_fname)
            self.assertExists(src_fname, False)
            self.assertContent(dst_fname, "test %d" % i)

        # Delete some files
        for i in range(2):
            fname = "%s\\%s\\test-%d-renamed.txt" % (self.testroot, folders[i], i)
            self.assertContent(fname, "test %d" % i)
            self.server_conn.unlink(fname)
            self.assertExists(fname, False)

        # Delete folders
        for i in range(2):
            fname = "%s\\%s" % (self.testroot, folders[i])
            self.assertExists(fname, True)
            self.server_conn.rmdir(fname)
            self.assertExists(fname, False)

        # Delete trees
        fname = "%s\\folder-3-renamed" % self.testroot
        self.assertExists(fname, True)
        self.server_conn.deltree(fname)
        for i in range(6):
            self.assertExists(folders[i], False)

    def tearDown(self):
        self.server_conn.deltree(self.testroot)
        pass

TestProgram(module=__name__, opts=subunitopts)
