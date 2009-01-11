#!/usr/bin/env python

import unittest
from whitetrash_db.configobj import ConfigObj
from whitetrash import WTSquidRedirector
from whitetrash import WTSquidRedirectorCached
import httplib


class SquidRedirectorUnitTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.wt_redir=WTSquidRedirector(config)
        self.wt_redir.clientident="wt_unittesting"
        self.wt_redir.cursor.execute("delete from whitelist_whitelist where username='wt_unittesting'")
        
    def testURLParsing(self):

        squid_inputs=["http://whitetrash.sf.net/ 10.10.9.60/- greg GET",
                        "whitetrash.sf.net:443 10.10.9.60/- greg CONNECT "]
        squid_inputs_results=[True,True]
        squid_inputs_results_url=["http://whitetrash/whitelist/getform?url=http%3A//whitetrash.sf.net/&clientaddr=10.10.9.60&domain=whitetrash.sf.net", "sslwhitetrash:80"]

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
                                        self.wt_redir.clientident,
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
        self.wt_redir.url_domain_only="testwhitetrash.sf.net"
        self.wt_redir.fail_url=""
        self.wt_redir.newurl_safe="http%3A//www.whitetrash.sf.net/FAQ"
        self.wt_redir.original_url="http://testwhitetrash.sf.net"
        self.wt_redir.protocol=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        self.wt_redir.auto_add_all=False
        self.assertEqual(self.wt_redir.check_whitelist_db(),False)
        self.wt_redir.auto_add_all=True
        self.assertEqual(self.wt_redir.check_whitelist_db(),True)
        self.wt_redir.url_domain_only="notintestwhitetrash.sf.net"
        self.wt_redir.auto_add_all=False
        self.assertEqual(self.wt_redir.check_whitelist_db(),False)
        self.wt_redir.url_domain_only="testwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(),True)
        self.wt_redir.protocol=self.wt_redir.PROTOCOL_CHOICES["SSL"]
        self.assertEqual(self.wt_redir.check_whitelist_db(),False)
        self.wt_redir.auto_add_all=True
        self.wt_redir.url_domain_only="ssltestwhitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(),True)
       
    def tearDown(self):
        self.wt_redir.cursor.execute("delete from whitelist_whitelist where username='wt_unittesting'")
        self.wt_redir.cursor.execute("delete from whitelist_whitelist where domain like '%testwhitetrash.sf.net'")

class CachedSquidRedirectorUnitTests(SquidRedirectorUnitTests):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.wt_redir=WTSquidRedirectorCached(config)
        self.wt_redir.clientident="wt_unittesting"
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


