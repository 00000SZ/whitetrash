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
from whitetrash_db.configobj import ConfigObj
from whitetrash import WTSquidRedirector
from whitetrash import WTSquidRedirectorCached
import httplib

class SquidRedirectorUnitTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.wt_redir=WTSquidRedirector(config)
        self.wt_redir.cursor.execute("delete from whitelist_whitelist where username='wt_unittesting'")
        
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
        squid_inputs_results_url=["http://whitetrash/whitelist/getform?url=http%3A//whitetrash.sf.net/&clientaddr=10.10.9.60&domain=whitetrash.sf.net",
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

    def testAddToWhitelist(self):
        self.wt_redir.add_to_whitelist("insertme.new.whitetrash.sf.net",
                                        self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                        "wt_unittesting",
                                        "http%3A//www.whitetrash.sf.net/FAQ")

        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
        	                                  "insertme.new.whitetrash.sf.net",
        	                                  "new.whitetrash.sf.net"):
            self.fail("Domain not added")

        if self.wt_redir.get_whitelist_id_wild(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
        	                                    "new.whitetrash.sf.net"):
            self.fail("Should return empty because wild was not inserted")

    def testGetWhitelistID(self):

        self.wt_redir.cursor.execute("insert into whitelist_whitelist set domain='testwild.whitetrash.sf.net',date_added=NOW(),username='wt_unittesting',protocol=%s,original_request='http://sdlkj',comment='whitetrash testing',enabled=1,hitcount=1,last_accessed=NOW()", (self.wt_redir.PROTOCOL_CHOICES["HTTP"]))

        if not self.wt_redir.get_whitelist_id_wild(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
        	                                    "testwild.whitetrash.sf.net"):
            self.fail("Did not return wild whitelist id")
        self.wt_redir.url_domain_only="images.testwild.whitetrash.sf.net"
        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
        	                                    "www.testwild.whitetrash.sf.net",
        	                                    "testwild.whitetrash.sf.net"):
            self.fail("Did not return whitelist id")


    def testWhitelistChecking(self):
        self.wt_redir.fail_url=self.wt_redir.http_fail_url
        form=self.wt_redir.http_fail_url+"\n"
        url="http%3A//www.whitetrash.sf.net/FAQ"
        orig_url="http://testwhitetrash.sf.net"
        proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        self.wt_redir.auto_add_all=False

        dom="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(False,form),
                        "No testwhitetrash.sf.net domains should be in the whitelist")

        self.wt_redir.auto_add_all=True
        #Auto add is enabled so should always return true
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(True,"\n"))
        dom="www.thing.anothertestwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(True,"\n"))

        dom="images.thing.anothertestwhitetrash.sf.net"
        self.wt_redir.auto_add_all=False
        #We added www.thing.anothertestwhitetrash.sf.net so this should be wildcarded
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(True,"\n"))

        dom="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(True,"\n"),
                        "We added this so it should be true")

        dom="this.another.testwhitetrash.sf.net"
        orig_url="http://testwhitetrash.sf.net/blah.js"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(False,self.wt_redir.dummy_content_url+"\n"),
                        "The orig_url ends in known non-html content so give back dummy url")

        proto=self.wt_redir.PROTOCOL_CHOICES["SSL"]
        self.wt_redir.fail_url=self.wt_redir.ssl_fail_url
        form=self.wt_redir.ssl_fail_url+"\n"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(False,form),
                        "This domain not whitelisted for SSL so we should get the form")

        self.wt_redir.auto_add_all=True
        dom="ssltestwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(True,"\n"),
                        "Auto add ssl domain")

        dom="testwhitetrash.sf.net"
        self.wt_redir.auto_add_all=False
        #generate an error by destroying the protocol choices dictionary 
        self.wt_redir.PROTOCOL_CHOICES={}
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,url,orig_url),(False,"http://whitetrash/whitelist/error?error=Error%20checking%20domain%20in%20whitelist\n"))
       
    def tearDown(self):
        self.wt_redir.cursor.execute("delete from whitelist_whitelist where username='wt_unittesting'")
        self.wt_redir.cursor.execute("delete from whitelist_whitelist where domain like '%testwhitetrash.sf.net'")

class CachedSquidRedirectorUnitTests(SquidRedirectorUnitTests):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.wt_redir=WTSquidRedirectorCached(config)
        self.wt_redir.cursor.execute("delete from whitelist_whitelist where username='wt_unittesting'")
        self.wt_redir.cache.flush_all()

    def testRepeatedGet(self):
        """Make two gets to make sure the cache is used
        The first get will grab from the DB.  The second will grab from the cache, so we want to test that.
        """
        self.testAddToWhitelist()
        if not self.wt_redir.get_whitelist_id(): self.fail("Domain insertme.new.whitetrash.sf.net not added")
        if self.wt_redir.get_whitelist_id_wild(): self.fail("Should return empty because wild was not inserted")
        self.wt_redir.url_domain_only="notinwhitelist.sf.net"
        if self.wt_redir.get_whitelist_id(): self.fail("Should return empty, notinwhitelist.sf.net not inserted")

def allTests():
    return unittest.TestSuite((unittest.makeSuite(CachedSquidRedirectorUnitTests),
                                unittest.makeSuite(SquidRedirectorUnitTests),
                                ))

if __name__ in ('main', '__main__'):
    unittest.main(defaultTest="allTests")


