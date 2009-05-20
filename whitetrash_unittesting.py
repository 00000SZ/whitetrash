#!/usr/bin/env python

# Author: gregsfdev@users.sourceforge.net
# License: GPL
#
# This file is part of Whitetrash.
# 
#     Whitetrash is free software; you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation; either version 2 of the License, or
#     (at your option) any later version.
# 
#     Whitetrash is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
# 
#     You should have received a copy of the GNU General Public License
#     along with Whitetrash; if not, write to the Free Software
#     Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

import unittest
from configobj import ConfigObj
from whitetrash import WTSquidRedirector
from whitetrash import WTSquidRedirectorCached
from whitetrash_cert_server import get_domain,get_cert,get_certfilepath
from exceptions import TypeError
import httplib
import MySQLdb
import os
import blacklistcache

class WhitetrashTest(unittest.TestCase):

    def setUp(self):
        self.config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]

class CertServerTest(WhitetrashTest):

    def setUp(self):
        super(CertServerTest, self).setUp() 
        testdomains = ["testing.whitetrash.sf.net","whitetrash.sf.net"]
        for dom in testdomains:
            cert = get_certfilepath(dom)
            if os.path.exists(cert):
                os.unlink(cert)

    def testGetDomain(self):
        self.assertEqual(("*.","com.au"),get_domain("blah.com.au"))        
        self.assertEqual(("*.","blah.blah.com.au"),get_domain("blah.blah.blah.com.au"))        
        self.assertEqual(("","blah.com"),get_domain("blah.com"))        

    def testGetCert(self):
        """Check certs get created.  THe first label of the domains supplied will be stripped and wildcarded"""

        assert(os.path.exists(self.config["dynamic_certs_dir"]))
        get_cert("blah.testing.whitetrash.sf.net")
        assert(os.path.exists(os.path.join(self.config["dynamic_certs_dir"],"net/sf/whitetrash/testing.whitetrash.sf.net.pem")))
        get_cert("whitetrash.sf.net")
        assert(os.path.exists(os.path.join(self.config["dynamic_certs_dir"],"net/sf.net.pem")))

    def testGetCertFilePath(self):
        """Get file path, get_certfilepath assumes first label has already been stripped."""

        self.assertEqual(get_certfilepath("whitetrash.sf.net"),os.path.join(self.config["dynamic_certs_dir"],"net/sf/whitetrash.sf.net.pem"))
        self.assertEqual(get_certfilepath("com.au"),os.path.join(self.config["dynamic_certs_dir"],"au/com.au.pem"))

class RedirectorTest(WhitetrashTest):

    def setUp(self):
        super(RedirectorTest, self).setUp() 
        self.cleancur=self.getDBCleanupCursor(self.config)

    def getDBCleanupCursor(self,config):
        """Return a cursor with permissions to delete test entries from the database"""
        dbh = MySQLdb.Connect(user = config['DATABASE_CLEANUP_USER'],
                                    passwd = config['DATABASE_CLEANUP_PASSWORD'],
                                    db = config['DATABASE_NAME'],
                                    unix_socket = config['DATABASE_UNIX_SOCKET'],
                                    use_unicode = False
                                    )
        return dbh.cursor()

class SquidRedirectorUnitTests(RedirectorTest):

    def setUp(self):
        super(SquidRedirectorUnitTests, self).setUp() 
        self.wt_redir=WTSquidRedirector(self.config)
        self.cleancur.execute("delete from whitelist_whitelist where username='wt_unittesting'")
        self.wt_redir.cursor.execute("insert into whitelist_whitelist set domain='alreadywhitelisted.whitetrash.sf.net',date_added=NOW(),username='wt_unittesting',protocol=%s,url='http://sdlkj',comment='whitetrash testing',enabled=1,hitcount=20,last_accessed=NOW(),client_ip='192.168.1.1'", (self.wt_redir.PROTOCOL_CHOICES["HTTP"]))

    def testURLParsing(self):

        squid_inputs=[
                        "http://whitetrash.sf.net/ 10.10.9.60/- greg GET",
                        "whitetrash.sf.net:443 10.10.9.60/- greg CONNECT",
                        "http://'or1=1--.com 10.10.9.60/something.com.au - GET",
                        "http://testwhitetrash.sf.net bad baduser 10.10.9.60/- greg GET",
                        "testwhitetrash.sf.net 10.10.9.60/- greg GET",
                        "whitetrash.sf.net:443 10.10.9.60/- greg CO##ECT",
                        "http://whitetrash.sf.aaaanet/ 10.10.9.60/- greg GET",
                        ]
        squid_inputs_results=[True,True,False,False,False,False,False]
        squid_inputs_results_url=["%s://whitetrash/whitelist/addentry?url=http%%3A//whitetrash.sf.net/&domain=whitetrash.sf.net" % self.wt_redir.wtproto,
            "whitetrash.sf.net.sslwhitetrash:3456",
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            ]

        for i in range(len(squid_inputs)):
            res=self.wt_redir.parseSquidInput(squid_inputs[i])
            self.assertEqual(res,squid_inputs_results[i],
                                    "Got %s, Expected %s for %s" %(res,squid_inputs_results[i],squid_inputs[i]))
            self.assertEqual(self.wt_redir.fail_url,squid_inputs_results_url[i],
                                    "Got %s, Expected %s for %s" %(self.wt_redir.fail_url,
                                    squid_inputs_results_url[i],squid_inputs[i]))

    def testGetWhitelistID(self):
        #Get the ID for an entry we know is whitelisted
        thisid=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "alreadywhitelisted.whitetrash.sf.net","whitetrash.sf.net",wild=False)
        (proto,domain)=self.wt_redir.get_proto_domain(thisid)
        self.assertEqual(proto,self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                        "Got %s, Expected %s for protocol" % (proto,self.wt_redir.PROTOCOL_CHOICES["HTTP"]))
        self.assertEqual(domain,"alreadywhitelisted.whitetrash.sf.net",
                        "Got %s, Expected alreadywhitelisted.whitetrash.sf.net" % (domain))

    def testEnableNonExistantDomainID(self):
        whitelist_id=99999
        test=self.wt_redir.get_proto_domain(whitelist_id)
        self.assertFalse(test,"Tried to pick a whitelist_id that didn't exist (%s), but already in database" % (whitelist_id))
        self.assertRaises(ValueError,lambda: self.wt_redir.enable_domain(whitelist_id))

    def testEnableDomain(self):
        self.wt_redir.add_disabled_domain("disabled.testwhitetrash.sf.net",
                                        self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                        "wt_unittesting",
                                        "http%3A//www.testwhitetrash.sf.net/FAQ",
                                        "192.168.3.1")

        (thisid,enabled)=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "www.disabled.testwhitetrash.sf.net","disabled.testwhitetrash.sf.net",wild=True)
        self.assertFalse(enabled,"This domain was added disabled, should be false")

        #do this twice to exercise memcache
        (thisid,enabled)=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "www.disabled.testwhitetrash.sf.net","disabled.testwhitetrash.sf.net",wild=True)
        self.assertFalse(enabled,"This domain was added disabled, should be false")

        self.wt_redir.enable_domain(thisid)
        (thisid,enabled)=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "www.disabled.testwhitetrash.sf.net","disabled.testwhitetrash.sf.net",wild=True)
        self.assertTrue(enabled,"This domain should be enabled.")

    def testAddToWhitelist(self):
        self.wt_redir.add_to_whitelist("insertme.new.whitetrash.sf.net",
                                        self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                        "wt_unittesting",
                                        "http%3A//www.whitetrash.sf.net/FAQ",
                                        "192.168.3.1")

        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                              "insertme.new.whitetrash.sf.net",
                                              "new.whitetrash.sf.net",wild=False):
            self.fail("Domain not added")

        if self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                                "www.new.whitetrash.sf.net","new.whitetrash.sf.net",wild=True):
            self.fail("Should return empty because wild was not inserted")

    def testGetWhitelistID(self):

        self.wt_redir.cursor.execute("insert into whitelist_whitelist set domain='testwild.whitetrash.sf.net',date_added=NOW(),username='wt_unittesting',protocol=%s,url='http://sdlkj',comment='whitetrash testing',enabled=1,hitcount=1,last_accessed=NOW(),client_ip='192.168.1.1'", (self.wt_redir.PROTOCOL_CHOICES["HTTP"]))

        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                                "www.testwild.whitetrash.sf.net","testwild.whitetrash.sf.net",wild=True):
            self.fail("Did not return wild whitelist id")
        self.wt_redir.url_domain_only="images.testwild.whitetrash.sf.net"
        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                                "www.testwild.whitetrash.sf.net",
                                                "testwild.whitetrash.sf.net",wild=False):
            self.fail("Did not return whitelist id")

    def testWhitelistCheckingRedirectPOST(self):
        """When receiving a POST for a non-whitelisted domain, redirector should respond
        with a 302: indicating client should go request the form with a GET"""

        self.wt_redir.fail_url=self.wt_redir.http_fail_url
        form="302:%s\n" % self.wt_redir.http_fail_url
        url="http%3A//www.whitetrash.sf.net/FAQ"
        orig_url="http://testwhitetrash.sf.net"
        ip="192.168.1.1"
        method="POST"
        proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        self.wt_redir.auto_add_all=False

        dom="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,form))

    def testSafeBrowsing(self):
        if self.config["safebrowsing"].upper() == "TRUE":
            url="http%3A//malware.testing.google.test/testing/malware/"
            orig_url="http://malware.testing.google.test/testing/malware/"
            ip="192.168.1.1"
            method="GET"
            proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
            self.wt_redir.auto_add_all=False
            dom="malware.testing.google.test"
            self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),
                                        (False,'302:https://whitetrash/whitelist/attackdomain=malware.testing.google.test\n'))
            proto=self.wt_redir.PROTOCOL_CHOICES["SSL"]
            self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),
                                        (False,'302:https://whitetrash/whitelist/attackdomain=malware.testing.google.test\n'))


    def testSafeBrowsingURL(self):
        url = self.wt_redir.get_sb_fail_url(blacklistcache.PHISHING,"phishing.domain.com")
        self.assertEqual(url,"%s://%s/whitelist/forgerydomain=%s" % 
                                    (self.wt_redir.wtproto,self.config["whitetrash_domain"],"phishing.domain.com"))
        url = self.wt_redir.get_sb_fail_url(blacklistcache.MALWARE,"malware.domain.com")
        self.assertEqual(url,"%s://%s/whitelist/attackdomain=%s" % 
                                    (self.wt_redir.wtproto,self.config["whitetrash_domain"],"malware.domain.com"))
        
    def testWhitelistChecking(self):
        self.wt_redir.fail_url=self.wt_redir.http_fail_url
        form=self.wt_redir.http_fail_url+"\n"
        url="http%3A//www.whitetrash.sf.net/FAQ"
        orig_url="http://testwhitetrash.sf.net"
        ip="192.168.1.1"
        method="GET"
        proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        self.wt_redir.auto_add_all=False

        dom="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,form),
                        "No testwhitetrash.sf.net domains should be in the whitelist")

        self.wt_redir.auto_add_all=True
        #Auto add is enabled so should always return true
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"))
        dom="www.thing.anothertestwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"))

        dom="images.thing.anothertestwhitetrash.sf.net"
        self.wt_redir.auto_add_all=False
        #We added www.thing.anothertestwhitetrash.sf.net so this should be wildcarded
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"))

        dom="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"),
                        "We added this so it should be true")

        dom="this.another.testwhitetrash.sf.net"
        orig_url="http://testwhitetrash.sf.net/blah.js"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,self.wt_redir.dummy_content_url+"\n"),
                        "The orig_url ends in known non-html content so give back dummy url")

        proto=self.wt_redir.PROTOCOL_CHOICES["SSL"]
        self.wt_redir.fail_url=self.wt_redir.ssl_fail_url
        form=self.wt_redir.ssl_fail_url+"\n"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,form),
                        "This domain not whitelisted for SSL so we should get the form")

        self.wt_redir.auto_add_all=True
        dom="ssltestwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"),
                        "Auto add ssl domain")

        dom="testwhitetrash.sf.net"
        self.wt_redir.auto_add_all=False
        #generate an error by destroying the protocol choices dictionary 
        self.wt_redir.PROTOCOL_CHOICES={}
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,"%s://whitetrash/whitelist/error=Error%%20checking%%20domain%%20in%%20whitelist\n" % self.wt_redir.wtproto))
       
    def tearDown(self):
        self.cleancur.execute("delete from whitelist_whitelist where username='wt_unittesting'")
        self.cleancur.execute("delete from whitelist_whitelist where domain like '%testwhitetrash.sf.net'")

class CachedSquidRedirectorUnitTests(SquidRedirectorUnitTests):

    def setUp(self):
        super(CachedSquidRedirectorUnitTests, self).setUp() 
        self.wt_redir=WTSquidRedirectorCached(self.config)
        self.wt_redir.cache.flush_all()

    def testRepeatedGet(self):
        """Make two gets to make sure the cache is used
        The first get will grab from the DB.  The second will grab from the cache, so we want to test that.
        """
        self.testAddToWhitelist()
        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                              "insertme.new.whitetrash.sf.net",
                                              "new.whitetrash.sf.net",wild=False):
            self.fail("Domain insertme.new.whitetrash.sf.net not added")

        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                              "insertme.new.whitetrash.sf.net",
                                              "new.whitetrash.sf.net",wild=False):
            self.fail("Second get failed where first succeeded.  Problem with memcache.")

def allTests():
    config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
    #Only run the memcache tests if memcache is enabled.
    if config["use_memcached"].upper()=="TRUE":
        print("Running: CachedSquidRedirectorUnitTests, SquidRedirectorUnitTests, CertServerTest")
        return unittest.TestSuite((unittest.makeSuite(CachedSquidRedirectorUnitTests),
                                    unittest.makeSuite(SquidRedirectorUnitTests),
                                    unittest.makeSuite(CertServerTest),
                                    ))
    else:
        print("Running: SquidRedirectorUnitTests, CertServerTest")
        return unittest.TestSuite((unittest.makeSuite(SquidRedirectorUnitTests),
                                    unittest.makeSuite(CertServerTest),
                                    ))


if __name__ in ('main', '__main__'):
    unittest.main(defaultTest="allTests")


