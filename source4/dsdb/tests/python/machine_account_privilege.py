#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This tests the SeMachineAccountPrivilege which allows a regular user to
# join computers to the domain
#
# Copyright Samuel Cabrero 2014 <samuelcabrero@kernevil.me>
#

import optparse
import sys
import unittest
import samba
import samba.getopt as options
import samba.tests
import ldb

from subunit.run import SubunitTestRunner
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import samr, security, lsa
from samba.credentials import Credentials
from samba.ndr import ndr_unpack
from samba.tests import delete_force
from samba import gensec, sd_utils
from samba.credentials import DONT_USE_KERBEROS

parser = optparse.OptionParser("machine_account_privilege.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]
if not "://" in host:
    ldaphost = "ldap://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start+3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

class MachineAccountPrivilegeTests(samba.tests.TestCase):

    def get_creds(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS) # kinit is too expensive to use in a tight loop
        return creds_tmp

    def setUp(self):
        super(MachineAccountPrivilegeTests, self).setUp()
        self.admin_creds = creds
        self.admin_samdb = SamDB(url=ldaphost,
                                 session_info=system_session(), 
                                 credentials=self.admin_creds, lp=lp)
        self.unpriv_user = "testuser1"
        self.unpriv_user_pw = "samba123@"
        self.unpriv_creds = self.get_creds(self.unpriv_user, self.unpriv_user_pw)
        self.admin_samdb.newuser(self.unpriv_user, self.unpriv_user_pw)
        self.sd_utils = sd_utils.SDUtils(self.admin_samdb)

        self.samdb = SamDB(url=ldaphost, credentials=self.unpriv_creds, lp=lp)
        self.domain_sid = security.dom_sid(self.samdb.get_domain_sid())
        self.base_dn = self.samdb.domain_dn()

        self.samr = samr.samr("ncacn_ip_tcp:%s[sign]" % host, lp, self.unpriv_creds)
        self.samr_handle = self.samr.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.samr_domain = self.samr.OpenDomain(self.samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED, self.domain_sid)
        
        self.computername = "testcomputer1"

    def tearDown(self):
        super(MachineAccountPrivilegeTests, self).tearDown()
	delete_force(self.admin_samdb, "CN=%s,CN=Computers,%s" % (self.computername, self.base_dn))
	delete_force(self.admin_samdb, "CN=%s,CN=Users,%s" % (self.unpriv_user, self.base_dn))

    def test_add_computer_samr(self):
	account = lsa.String()
	account.string = "%s$" % self.computername
        acct_flags = samr.ACB_WSTRUST
        access_mask = 0xe00500b0
        (user_handle, granted_access, rid) = self.samr.CreateUser2(
			self.samr_domain, account, acct_flags, access_mask)
	
        res = self.admin_samdb.search("CN=Computers,%s" % self.base_dn,
                                expression="(samAccountName=%s)" % account.string,
				attrs=["nTSecurityDescriptor"])
        self.assertNotEqual(len(res), 0)
        
	desc = res[0]["nTSecurityDescriptor"][0]
        desc = ndr_unpack(security.descriptor, desc, allow_remaining=True)
	self.assertTrue(str(desc.owner_sid) == "%s-512" % self.domain_sid)
	self.assertTrue(str(desc.group_sid) == "%s-513" % self.domain_sid)
        sddl = self.sd_utils.get_sd_as_sddl(res[0].dn)
        self.assertEqual(sddl, "")

    def test_add_computer_ldap(self):
        dn = "CN=%s,CN=Computers,%s" % (self.computername, self.base_dn)
        samaccountname = "%s$" % self.computername
        domainname = ldb.Dn(self.samdb, self.samdb.domain_dn()).canonical_str().replace("/", "")
        dnshostname = "%s.%s" % (self.computername, domainname)
        uac = samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT + samba.dsdb.UF_ACCOUNTDISABLE
        msg = ldb.Message.from_dict(self.samdb, {
            "dn": dn,
            "objectclass": "computer",
            "sAMAccountName": samaccountname,
            "userAccountControl": str(uac),
            "dNSHostName": dnshostname,
            "servicePrincipalName": ["HOST/%s" % dnshostname,
                                     "HOST/%s" % self.computername]})
        self.samdb.add(msg)

        res = self.admin_samdb.search("CN=Computers,%s" % self.base_dn,
                                      expression="(samAccountName=%s)" % samaccountname,
                                      attrs=["nTSecurityDescriptor"])
        self.assertNotEqual(len(res), 0)
        
	desc = res[0]["nTSecurityDescriptor"][0]
        desc = ndr_unpack(security.descriptor, desc, allow_remaining=True)
	self.assertTrue(str(desc.owner_sid) == "%s-512" % self.domain_sid)
	self.assertTrue(str(desc.group_sid) == "%s-513" % self.domain_sid)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(MachineAccountPrivilegeTests)).wasSuccessful():
    rc = 1

sys.exit(rc)
