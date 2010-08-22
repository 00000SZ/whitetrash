#!/usr/bin/env python

# Author: gregsfdev@users.sourceforge.net
#         cford@users.sourceforge.net
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

from contextlib import nested
from tempfile import TemporaryFile

from configobj import ConfigObj
from nose.plugins.attrib import attr

import sys
from os.path import join,realpath,dirname
sys.path.append(join(dirname(realpath(__file__)),"../../"))
from redirector import squid
from redirector.common import RedirectMap
from django_site.whitetrash.whitelist.models import Whitelist

class RedirectHandlerTests(unittest.TestCase):
    """
    Tests the ins and outs of whitetrash.RedirectHandler
    """

    stdin_file = "/tmp/whitetrash-testing-stdin"
    stdout_file = "/tmp/whitetrash-testing-stdout"

    def setUp(self):
        squid.whitetrash_config = ConfigObj("../../whitetrash.conf")["DEFAULT"]
        self.stdin = TemporaryFile()
        self.stdout = TemporaryFile()

    def test_as_context_manager(self):
        """
        Make sure the basic __enter__ and __exit__ of RedirectHandler work
        """
        with squid.RedirectHandler() as redirect:
            self.assertTrue(redirect)
        self.assertTrue(redirect)

    def test_read_request(self):
        input = "http://whitetrash.sf.net/ 10.10.9.60/- greg GET"
        url = "http://whitetrash.sf.net/"
        client_ip = "10.10.9.60"
        http_method = "GET"
        protocol = Whitelist.get_protocol_choice("HTTP")

        self.write_stdin(input)
        with squid.RedirectHandler(self.stdin, self.stdout) as redirect:
            redirect.read_request()
            self.assertEqual(redirect.request.url, url, "Parsing URL from squid input failed")
            self.assertEqual(redirect.request.client_ip, client_ip, "Parsing IP address from squid input failed")
            self.assertEqual(redirect.request.http_method, http_method, "Parsing HTTP method from squid input failed")
            self.assertEqual(redirect.protocol, protocol, "Parsing protocol from squid input failed")

    def test_invalid_url_in_request(self):
        """
        Tests that requests for "bad" urls are sent to the error page.
        "Good" urls are defined as satisfying the default domain_regex from whitetrash.conf and using
        a supported protocol (hardcoded in RedirectHandler._validate_request()
        Some domains which don't match the default domain regular expression:
         - more than 6 subdomains (i.e. everything apart from the top-level domain)
         - any subdomain that's longer than 50 characters
         - any top-level domain that's longer than 6 characters (longest is .museum)
        Supported protocols are currently only HTTP and HTTPS
        """
        expected = {"ssh://whitetrash.sf.net/ 10.133.9.60/- greg GET": RedirectMap.http_error_url,
                    "http://this.is.way.too.many.subdomains.to.be.reasonable.net/ " \
                    "10.133.9.60/- greg GET": RedirectMap.http_error_url, 
                    "http://0123456789-0123456789-0123456789-0123456789-0123456789.net/ " \
                    "10.133.9.60/- greg GET": RedirectMap.http_error_url,
                    "http://whitetrash.sf.tldfail/ 10.133.9.60/- greg GET": RedirectMap.http_error_url}
        self.write_stdin(expected.keys())
        with squid.RedirectHandler(self.stdin, self.stdout) as redirect:
            redirect.read_request()
            redirects = self.read_redirects()
            num_tests = 0
            for input, ouput in redirects:
                self.assertEqual(output, expected[input], "Squid input with bad client IP was accepted")
                num_tests += 1
            self.assertEqual(num_tests, len(redirects), "%s tests expected, only %s ran" % (len(redirects), num_tests))

    def test_invalid_ip_in_request(self):
        expected = {"http://whitetrash.sf.net/ 10.1333.9.60/- greg GET": RedirectMap.http_error_url,
                    "http://whitetrash.sf.net/ 10.1a.9.60/- greg GET": RedirectMap.http_error_url,
                    "http://whitetrash.sf.net/              greg GET": RedirectMap.http_error_url}
        self.write_stdin(expected.keys())
        with squid.RedirectHandler(self.stdin, self.stdout) as redirect:
            redirect.read_request()
            redirects = self.read_redirects()
            num_tests = 0
            for input, ouput in redirects:
                self.assertEqual(output, expected[input], "Squid input with bad client IP was accepted")
                num_tests += 1
            self.assertEqual(num_tests, len(redirects), "%s tests expected, only %s ran" % (len(redirects), num_tests))

    def test_invalid_http_method_in_request(self):
        expected = {"http://whitetrash.sf.net/ 10.133.9.60/- greg TRACE": RedirectMap.http_error_url,
                    "http://whitetrash.sf.net/ 10.133.9.60/- greg ": RedirectMap.http_error_url}
        self.write_stdin(expected.keys())
        with squid.RedirectHandler(self.stdin, self.stdout) as redirect:
            redirect.read_request()
            redirects = self.read_redirects()
            num_tests = 0
            for input, ouput in redirects:
                self.assertEqual(output, expected[input], "Squid input with bad client IP was accepted")
                num_tests += 1
            self.assertEqual(num_tests, len(redirects), "%s tests expected, only %s ran" % (len(redirects), num_tests))

    @attr("database")
    def test_should_allow_whitelisted_domains(self):
        expected = {"http://whitetrash.sf.net/ 10.133.9.60/- greg GET": "http://whitetrash.sf.net/",
                    "http://www.google.com/ 10.133.9.60/- greg ": "http://www.google.com/"}
        self.write_stdin(expected.keys())
        with squid.RedirectHandler(self.stdin, self.stdout) as redirect:
            redirect.read_request()
            redirect.evaluate_request()
            redirects = self.read_redirects()
            num_tests = 0
            for input, ouput in redirects:
                self.assertEqual(output, expected[input], "Whitelisted URL was not correctly forwarded")
                num_tests += 1
            self.assertEqual(num_tests, len(redirects), "%s tests expected, only %s ran" % (len(redirects), num_tests))

    def write_stdin(self, input):
        """
        Writes a single string or a list of strings as "\n" terminated lines
        to self.stdin
        """
        # Accept strings and lists as input
        if type(input) is str:
            input = [input]

        for line in input:
            self.stdin.write(line + "\n")
        # Go back to the start of the file so that the Redirector can read from it
        self.stdin.seek(0)

    def read_redirects(self):
        # Go back to the start of the files for reading
        self.stdin.seek(0)
        self.stdout.seek(0)

        redirects = {}
        for input, output in zip(self.stdin, self.stdout):
            redirects.update({input: output})
        return redirects

    def tearDown(self):
        self.stdin.close()
        self.stdout.close()
        
def alltests():
    return unittest.TestSuite((unittest.makeSuite(RedirectHandlerTests),))

if __name__=="__main__":
    unittest.main(defaultTest="alltests")
