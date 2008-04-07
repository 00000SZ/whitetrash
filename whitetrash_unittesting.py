#!/usr/bin/env python

import unittest
from whitetrash_db.configobj import ConfigObj
from whitetrash import WTSquidRedirector

class SquidRedirectorUnitTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.wt_redir=WTSquidRedirector(config)
        self.wt_redir.clientident="wt_unittesting"
        self.wt_redir.cursor.execute("delete from whitelist where username='wt_unittesting'")
        
    def testURLParsing(self):

        squid_inputs=["http://whitetrash.sf.net/ 10.10.9.60/- greg GET",
                        "whitetrash.sf.net:443 10.10.9.60/- greg CONNECT "]
        squid_inputs_results=[True,True]
        squid_inputs_results_url=["http://whitetrash/addentry?url=http%3A//whitetrash.sf.net/&clientaddr=10.10.9.60&clientident=greg&domain=whitetrash.sf.net", "whitetrash:8000"]

        for i in range(len(squid_inputs)):
            res=self.wt_redir.parseSquidInput(squid_inputs[i])
            self.assertEqual(res,squid_inputs_results[i],
                                    "Got %s, Expected %s for %s" %(res,squid_inputs_results[i],squid_inputs[i]))
            self.assertEqual(self.wt_redir.fail_url,squid_inputs_results_url[i],
                                    "Got %s, Expected %s for %s" %(self.wt_redir.fail_url,
                                    squid_inputs_results_url[i],squid_inputs[i]))

    def testWhitelistChecking(self):
        self.wt_redir.url_domain_only="test.whitetrash.sf.net"
        self.wt_redir.fail_url=""
        self.wt_redir.newurl_safe="http%3A//www.whitetrash.sf.net/FAQ"
        self.wt_redir.protocol="HTTP"
        self.wt_redir.auto_add_all=False
        self.assertEqual(self.wt_redir.check_whitelist_db(),False)
        self.wt_redir.auto_add_all=True
        self.assertEqual(self.wt_redir.check_whitelist_db(),True)
        self.wt_redir.url_domain_only="notinwhitelist.sf.net"
        self.wt_redir.auto_add_all=False
        self.assertEqual(self.wt_redir.check_whitelist_db(),False)
        self.wt_redir.url_domain_only="test.whitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(),True)
        self.wt_redir.protocol="SSL"
        self.assertEqual(self.wt_redir.check_whitelist_db(),False)
        self.wt_redir.auto_add_all=True
        self.wt_redir.url_domain_only="ssl.whitetrash.sf.net"
        self.assertEqual(self.wt_redir.check_whitelist_db(),True)
       
    def tearDown(self):
        self.wt_redir.cursor.execute("delete from whitelist where username='wt_unittesting'")

if __name__ in ('main', '__main__'):
    unittest.main()


