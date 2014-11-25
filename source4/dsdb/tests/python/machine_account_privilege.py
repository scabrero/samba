#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This tests the SeMachineAccountPrivilege which allows a regular user to
# join computers to the domain
#
# Copyright Samuel Cabrero 2014 <samuelcabrero@kernevil.me>
# Copyright Andrew Bartlett 2014 <abartlet@samba.org>
#
# Licenced under the GPLv3 
#

import optparse
import sys
import unittest
import samba
import samba.getopt as options
import samba.tests
import ldb
import base64

from subunit.run import SubunitTestRunner
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import samr, security, lsa
from samba.credentials import Credentials
from samba.ndr import ndr_unpack
from samba.tests import delete_force
from samba import gensec, sd_utils
from samba.credentials import DONT_USE_KERBEROS
from ldb import SCOPE_BASE, LdbError
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from Crypto.Hash import MD4

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

    def setMachineQuota(self, quota):
        m = Message()
        m.dn = Dn(self.admin_samdb, self.base_dn)
        m["e1"] = MessageElement(str(quota), FLAG_MOD_REPLACE, "ms-DS-MachineAccountQuota")
        self.admin_samdb.modify(m)
        self.quota = quota 

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
        res = self.admin_samdb.search("CN=%s,CN=Users,%s" % (self.unpriv_user, self.admin_samdb.domain_dn()),
                                      scope=SCOPE_BASE,
                                      attrs=["objectSid"])
        self.assertEqual(len(res), 1)
            
        self.unpriv_user_sid = ndr_unpack(security.dom_sid, res[0]["objectSid"][0])

        self.samdb = SamDB(url=ldaphost, credentials=self.unpriv_creds, lp=lp)
        self.domain_sid = security.dom_sid(self.samdb.get_domain_sid())
        self.base_dn = self.samdb.domain_dn()

        self.samr = samr.samr("ncacn_ip_tcp:%s[sign]" % host, lp, self.unpriv_creds)
        self.samr_handle = self.samr.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.samr_domain = self.samr.OpenDomain(self.samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED, self.domain_sid)

        self.sd_utils = sd_utils.SDUtils(self.admin_samdb)
        self.setMachineQuota(3)

        self.computernames = []
        for i in range(0, self.quota + 1):
            self.computernames.append("testcomputer-%d" % i)

	res = self.admin_samdb.search("CN=Computers,%s" % (self.base_dn),
                                      scope=SCOPE_BASE,
                                      attrs=["nTSecurityDescriptor"])
        self.assertEqual(len(res), 1)
        desc = res[0]["nTSecurityDescriptor"][0]
        self.container_desc = ndr_unpack(security.descriptor, desc, allow_remaining=True)

    def tearDown(self):
        super(MachineAccountPrivilegeTests, self).tearDown()
        for computername in self.computernames:
            delete_force(self.admin_samdb, "CN=%s,CN=Computers,%s" % (computername, self.base_dn))
        delete_force(self.admin_samdb, "CN=%s,CN=Users,%s" % (self.unpriv_user, self.base_dn))

    def check_computer_account(self, sid=None, computername=None, dnshostname=None):
        def arcfour_encrypt(key, data):
            from Crypto.Cipher import ARC4
            c = ARC4.new(key)
            return c.encrypt(data)

        def string_to_array(string):
            blob = [0] * len(string)
            for i in range(len(string)):
                blob[i] = ord(string[i])
            return blob

        attrs=["nTSecurityDescriptor", "mS-DS-CreatorSID", "objectSID", "dnsHostName",
               "servicePrincipalName", "objectClass", "objectCategory"]
        
        if sid is not None:
	        print "Checking %s" % sid
	        res = self.admin_samdb.search("<SID=%s>" % sid,
	                                      scope=SCOPE_BASE,
                                              attrs=attrs)
	else:
	        print "Checking %s" % computername
	        res = self.admin_samdb.search("CN=%s,CN=Computers,%s" % (computername, self.base_dn),
	                                      scope=SCOPE_BASE,
	                                      attrs=attrs)
	
        self.assertNotEqual(len(res), 0)
        print res[0]
        self.assertTrue("mS-DS-CreatorSID" in res[0])
        creator_sid = ndr_unpack(security.dom_sid, res[0]["ms-DS-CreatorSID"][0])
	(creator_domain_sid, creator_rid) = creator_sid.split()
        self.assertEqual(creator_sid, self.unpriv_user_sid)
        
        self.assertTrue("objectSid" in res[0])
	account_sid = ndr_unpack(security.dom_sid, res[0]["objectSID"][0])
	(account_domain_sid, account_rid) = account_sid.split()
	self.assertEqual(account_domain_sid, self.domain_sid)

        self.assertTrue("nTSecurityDescriptor" in res[0])
        desc = res[0]["nTSecurityDescriptor"][0]
        desc = ndr_unpack(security.descriptor, desc, allow_remaining=True)
        self.assertTrue(str(desc.owner_sid) == "%s-512" % self.domain_sid)
        self.assertTrue(str(desc.group_sid) == "%s-513" % self.domain_sid)

        if dnshostname:
            self.assertTrue("dNSHostName" in res[0])
            self.assertEqual(res[0]["dNSHostName"][0], dnshostname)
            self.assertTrue("servicePrincipalName" in res[0])
        else:
            self.assertFalse("dNSHostName" in res[0])
            self.assertFalse("servicePrincipalName" in res[0])
            
        reference = 'O:DAG:DUD:(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;' + str(self.unpriv_user_sid) + ')(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;' + str(self.unpriv_user_sid) + ')(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;' + str(self.unpriv_user_sid) + ')(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)(A;;RPCRLCLORC;;;' + str(self.unpriv_user_sid) + ')(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;CCDC;;;PS)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;CIID;LC;;;RU)(A;CIID;RPWPCRCCLCLORCWOWDSDSW;;;BA)S:(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)'
        w2k8r2_reference = 'O:DAG:DUD:(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;' + str(self.unpriv_user_sid) + ')(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;' + str(self.unpriv_user_sid) + ')(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;' + str(self.unpriv_user_sid) + ')(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;' + str(self.unpriv_user_sid) + ')(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)(A;;RPCRLCLORC;;;' + str(self.unpriv_user_sid) + ')(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;CCDC;;;PS)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;CIID;LC;;;RU)(A;CIID;RPWPCRCCLCLORCWOWDSDSW;;;BA)S:(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)'
        sddl = desc.as_sddl(self.domain_sid)
	self.assertEqual(w2k8r2_reference, sddl)

        # Assert password set over LDAP
        newpwd = unicode('"' + 'thatsAcomplPASS2' + '"', 'utf-8').encode('utf-16-le')
        m = Message()
        m.dn = Dn(self.samdb, "CN=%s,CN=Computers,%s" % (computername, self.base_dn))
        m["e1"] = MessageElement(newpwd, FLAG_MOD_REPLACE, "unicodePwd")
        self.samdb.modify(m)

        # Assert password set over SAM-R
        newpwd = unicode('"' + 'thatsAcomplPASS3' + '"', 'utf-8').encode('utf-16-le')
	h = MD4.new()
        h.update(newpwd)
        nt_hash = arcfour_encrypt(self.samr.session_key, h.digest())

	samr_user = self.samr.OpenUser(self.samr_domain, security.SEC_FLAG_MAXIMUM_ALLOWED, account_rid)
        user_info = samr.UserInfo18()
	user_info.nt_pwd.hash = string_to_array(nt_hash)
	user_info.nt_pwd_active = True;
	user_info.lm_pwd_active = False;

        self.samr.SetUserInfo(samr_user, 18, user_info)
        self.samr.Close(samr_user)

    def test_add_computer_samr(self):
        idx = 0
        for computername in self.computernames:
            print "Adding computer account %s" % computername
            samaccountname = "%s$" % computername
            account = lsa.String()
            account.string = samaccountname
            acct_flags = samr.ACB_WSTRUST
            access_mask = 0xe00500b0
         
            try:
                (user_handle, granted_access, rid) = self.samr.CreateUser2(
                            self.samr_domain, account, acct_flags, access_mask)
                idx += 1
            except RuntimeError, (enum, estr):
		# Windows machines return NT_STATUS_QUOTA_EXCEEDDED, samba NT_STATUS_ACCESS_DENIED
                if (enum == -1073741756 or enum == -1073741790) and idx == self.quota:
                    return
                else:
	            raise
            self.check_computer_account(sid=security.dom_sid("%s-%d" % (self.domain_sid, rid)),
					computername=computername)

    def add_computer_ldap(self, computername, pwd):
        dn = "CN=%s,CN=Computers,%s" % (computername, self.base_dn)
        samaccountname = "%s$" % computername
        domainname = ldb.Dn(self.samdb, self.samdb.domain_dn()).canonical_str().replace("/", "")
        dnshostname = "%s.%s" % (computername, domainname)

        uac = samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT
        msg = ldb.Message.from_dict(self.samdb, {
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "dNSHostName": dnshostname,
                "servicePrincipalName": ["HOST/%s" % dnshostname,
                                         "HOST/%s" % computername]})
        if pwd is None:
            uac |= samba.dsdb.UF_ACCOUNTDISABLE
        else:
            pwd = unicode('"' + pwd + '"', 'utf-8').encode('utf-16-le')
            msg["unicodePwd"] = pwd

        msg["userAccountControl"] = str(uac)

        print "Adding computer account %s" % computername
        self.samdb.add(msg)

    def test_add_computer_ldap_disabled(self):
        idx = 0
        for computername in self.computernames:
            try:
                self.add_computer_ldap(computername, None)
                idx += 1
            except LdbError, (enum, estr):
                if enum == ldb.ERR_UNWILLING_TO_PERFORM and idx == self.quota: 
                    return           
                else:
                    raise
            domainname = ldb.Dn(self.samdb, self.samdb.domain_dn()).canonical_str().replace("/", "")
            dnshostname = "%s.%s" % (computername, domainname)
            self.check_computer_account(computername=computername, dnshostname=dnshostname)

    def test_add_computer_ldap_enabled(self):
        idx = 0
        for computername in self.computernames:
            try:
                self.add_computer_ldap(computername, "thatsAcomplPASS1")
                idx += 1
            except LdbError, (enum, estr):
                if enum == ldb.ERR_UNWILLING_TO_PERFORM and idx == self.quota: 
                    return
                else:
                    raise
            domainname = ldb.Dn(self.samdb, self.samdb.domain_dn()).canonical_str().replace("/", "")
            dnshostname = "%s.%s" % (computername, domainname)
            self.check_computer_account(computername=computername, dnshostname=dnshostname)

    
runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(MachineAccountPrivilegeTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
