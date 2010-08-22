#!/usr/bin/env python

import unittest
import sys
from os.path import join,realpath,dirname
sys.path.append(join(dirname(realpath(__file__)),"../../"))

from redirector.common import RedirectMap


class RedirectMapTests(unittest.TestCase):
    
    def setUp(self):
        RedirectMap.redirect_to_ssl = False

    def testSimpleURL(self):
        params = {"url": "http://www.example.com/"}#,
        url = RedirectMap(**params)
        self.assertTrue(url, "Create URL %(url)s failed" % params)

#    def testBadDomain(self):
#        params = {"url": "http://wwwexamplecom/"}#,
#        self.assertRaises(AssertionError, RedirectMap, **params)

#    def testBadProtocol(self):
#        params = {"url": "ssh://www.example.com/"}#,
#        self.assertRaises(AssertionError, RedirectMap, **params)

#    def testDomainParsing(self):
#        params = {"url": "http://www.example.com/"}#,
#        redirect = RedirectMap(**params)
#        self.assertEqual(redirect.requested_domain, "www.example.com", "Domain parsing failed for %(url)s" % params)
        
#    def testProtocolParsing(self):
#        params = {"url": "http://www.example.com/"}#,
#        redirect = RedirectMap(**params)
#        self.assertEqual(redirect.requested_protocol, "http", "Protocol parsing failed for %(url)s" % params)

    def testRedirects(self):
        params = {"url": "http://www.example.com/section/action?query=string"}#,
        redirect = RedirectMap(**params)
        add_url = "http://whitetrash/addentry?"\
                  "url=http://www.example.com/section/action?query=string&"\
                  "domain=www.example.com"
        phish_url = "http://whitetrash/whitelist/"\
                    "forgerydomain=http://www.example.com/section/action?query=string"
        malware_url = "http://whitetrash/whitelist/"\
                      "attackdomain=http://www.example.com/section/action?query=string"
        empty_url = "http://blockedwhitetrash/empty"
        error_url = "http://whitetrash/error"
        static_error_url = "http://whitetrash/error"
        self.assertEqual(redirect.add_site_url(), add_url, "Redirect failed for adding %(url)s" % params)
        self.assertEqual(redirect.blocked_phishing_url(), phish_url, "Redirect failed for blocked phishing site %(url)s" % params)
        self.assertEqual(redirect.blocked_malicious_url(), malware_url, "Redirect failed for blocked malicious site %(url)s" % params)
        self.assertEqual(redirect.empty_content_url(), empty_url, "Redirect failed for non-html site %(url)s" % params)
        #self.assertEqual(redirect.error_url(), error_url, "SSL redirect failed for error msg site %(url)s" % params)
        self.assertEqual(redirect.http_error_url, static_error_url, "SSL redirect failed for error msg site %(url)s" % params)

    def testSSLRedirects(self):
        RedirectMap.redirect_to_ssl = True
        params = {"url": "http://www.example.com/section/action?query=string"}#,
        redirect = RedirectMap(**params)
        add_url = "302:https://www.example.com.sslwhitetrash:443/addentry?"
        phish_url = "302:https://whitetrash/whitelist/"\
                    "forgerydomain=http://www.example.com/section/action?query=string"
        malware_url = "302:https://whitetrash/whitelist/"\
                      "attackdomain=http://www.example.com/section/action?query=string"
        empty_url = "302:https://blockedwhitetrash/empty"
        error_url = "302:https://whitetrash/error"
        static_error_url = "http://whitetrash/error"
        self.assertEqual(redirect.add_site_url(), add_url, "SSL redirect failed for adding %(url)s" % params)
        self.assertEqual(redirect.blocked_phishing_url(), phish_url, "SSL redirect failed for blocked phishing site %(url)s" % params)
        self.assertEqual(redirect.blocked_malicious_url(), malware_url, "SSL redirect failed for blocked malicious site %(url)s" % params)
        self.assertEqual(redirect.empty_content_url(), empty_url, "SSL redirect failed for non-html site %(url)s" % params)
        #self.assertEqual(redirect.error_url(), error_url, "SSL redirect failed for error msg site %(url)s" % params)
        self.assertEqual(redirect.http_error_url, static_error_url, "SSL redirect failed for error msg site %(url)s" % params)

    def testSSLRedirectsiFailure(self):
        RedirectMap.redirect_to_ssl = False
        params = {"url": "http://www.example.com/section/action?query=string"}#,
        redirect = RedirectMap(**params)
        add_url = "302:https://whitetrash/addentry?"\
                  "url=http://www.example.com/section/action?query=string&"\
                  "domain=www.example.com"
        phish_url = "302:https://whitetrash/whitelist/"\
                    "forgerydomain=http://www.example.com/section/action?query=string"
        malware_url = "302:https://whitetrash/whitelist/"\
                      "attackdomain=http://www.example.com/section/action?query=string"
        empty_url = "302:https://blockedwhitetrash/empty"
        error_url = "302:https://whitetrash/error"
        static_error_url = "http://whitetrash/error"
        self.assertNotEqual(redirect.add_site_url(), add_url, "Redirect failed for adding %(url)s" % params)
        self.assertNotEqual(redirect.blocked_phishing_url(), phish_url, "Redirect failed for blocked phishing site %(url)s" % params)
        self.assertNotEqual(redirect.blocked_malicious_url(), malware_url, "Redirect failed for blocked malicious site %(url)s" % params)
        self.assertNotEqual(redirect.empty_content_url(), empty_url, "Redirect failed for non-html site %(url)s" % params)
        #self.assertEqual(redirect.error_url(), error_url, "SSL redirect failed for error msg site %(url)s" % params)
        self.assertEqual(redirect.http_error_url, static_error_url, "SSL redirect failed for error msg site %(url)s" % params)

def allTests():
    return unittest.TestSuite(unittest.makeSuite(RedirectMapTests))

if __name__=='__main__':
    unittest.main(defaultTest="allTests")
