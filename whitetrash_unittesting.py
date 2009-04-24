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
import httplib
import MySQLdb

class RedirectorTest(unittest.TestCase):

    def setUp(self):
        self.config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
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
        squid_inputs_results_url=["http://whitetrash/whitelist/addentry?url=http%3A//whitetrash.sf.net/&domain=whitetrash.sf.net",
            "sslwhitetrash:80",
            "http://whitetrash/whitelist/error?error=Bad%20request%20logged.%20%20See%20your%20sysadmin%20for%20assistance.\n",
            "http://whitetrash/whitelist/error?error=Bad%20request%20logged.%20%20See%20your%20sysadmin%20for%20assistance.\n",
            "http://whitetrash/whitelist/error?error=Bad%20request%20logged.%20%20See%20your%20sysadmin%20for%20assistance.\n",
            "http://whitetrash/whitelist/error?error=Bad%20request%20logged.%20%20See%20your%20sysadmin%20for%20assistance.\n",
            "http://whitetrash/whitelist/error?error=Bad%20request%20logged.%20%20See%20your%20sysadmin%20for%20assistance.\n",
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


    def testEnableDomain(self):
        self.wt_redir.add_disabled_domain("disabled.testwhitetrash.sf.net",
                                        self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                        "wt_unittesting",
                                        "http%3A//www.testwhitetrash.sf.net/FAQ",
                                        "192.168.3.1")

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


    def testWhitelistChecking(self):
        self.wt_redir.fail_url=self.wt_redir.http_fail_url
        form=self.wt_redir.http_fail_url+"\n"
        url="http%3A//www.whitetrash.sf.net/FAQ"
        orig_url="http://testwhitetrash.sf.net"
        ip="192.168.1.1"
        proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        self.wt_redir.auto_add_all=False

        dom="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(False,form),
                        "No testwhitetrash.sf.net domains should be in the whitelist")

        self.wt_redir.auto_add_all=True
        #Auto add is enabled so should always return true
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(True,"\n"))
        dom="www.thing.anothertestwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(True,"\n"))

        dom="images.thing.anothertestwhitetrash.sf.net"
        self.wt_redir.auto_add_all=False
        #We added www.thing.anothertestwhitetrash.sf.net so this should be wildcarded
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(True,"\n"))

        dom="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(True,"\n"),
                        "We added this so it should be true")

        dom="this.another.testwhitetrash.sf.net"
        orig_url="http://testwhitetrash.sf.net/blah.js"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(False,self.wt_redir.dummy_content_url+"\n"),
                        "The orig_url ends in known non-html content so give back dummy url")

        proto=self.wt_redir.PROTOCOL_CHOICES["SSL"]
        self.wt_redir.fail_url=self.wt_redir.ssl_fail_url
        form=self.wt_redir.ssl_fail_url+"\n"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(False,form),
                        "This domain not whitelisted for SSL so we should get the form")

        self.wt_redir.auto_add_all=True
        dom="ssltestwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(True,"\n"),
                        "Auto add ssl domain")

        dom="testwhitetrash.sf.net"
        self.wt_redir.auto_add_all=False
        #generate an error by destroying the protocol choices dictionary 
        self.wt_redir.PROTOCOL_CHOICES={}
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url,ip),(False,"http://whitetrash/whitelist/error?error=Error%20checking%20domain%20in%20whitelist\n"))
       
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
    return unittest.TestSuite((unittest.makeSuite(CachedSquidRedirectorUnitTests),
                                unittest.makeSuite(SquidRedirectorUnitTests),
                                ))

if __name__ in ('main', '__main__'):
    unittest.main(defaultTest="allTests")


