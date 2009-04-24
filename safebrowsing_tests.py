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
from safebrowsing import *

class BlacklistCacheTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("whitetrash.conf")["DEFAULT"]
        self.cache = BlacklistCache(config)

    def testMalwareVersion1(self):
        self.cache.malware_version = 1
        self.assertEqual(self.cache.malware_version, 1, "Cache did not save version")

    def testMalwareVersion2(self):
        self.assertEqual(self.cache.malware_version, -1, "Cache did not initialize version")

    def testPhishingVersion1(self):
        self.cache.phishing_version = 1
        self.assertEqual(self.cache.phishing_version, 1, "Cache did not save version")

    def testPhishingVersion2(self):
        self.assertEqual(self.cache.phishing_version, -1, "Cache did not initialize version")



class SafeBrowsingManagerTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.cache = BlacklistCache(config)
        d = dict(apikey = config["safebrowsing_api_key"],
                 malware_version = self.cache.malware_version,
                 phishing_version = self.cache.phishing_version)
        self.mgr = SafeBrowsingManager(**d)

    def testInit(self):
        self.assertEqual(self.mgr.malware.version, self.cache.malware_version, "Malware Update/Manager version mismatch")
        self.assertEqual(self.mgr.phishing.version, self.cache.phishing_version, "Phishing Update/Manager version mismatch")

    def testUpdateVersioning(self):
        self.mgr.do_updates()
        self.assert_(self.mgr.malware.version > 0, "Malware list did not update version")
        self.assert_(self.mgr.phishing.version > 0, "Phishing list did not update version")

    def testUpdateSuccess(self):
        malware_success  = False
        phishing_success = False

        self.mgr.do_updates()
        for entry in self.mgr.get_lists():
            if entry["hash"]:
                if entry["type"] == "MALWARE":
                    malware_success = True
                if entry["type"] == "PHISHING":
                    phishing_success = True
        self.assertTrue(malware_success,  "Malware updates failed")
        self.assertTrue(phishing_success, "Phishing updates failed")

def allTests():
    return unittest.TestSuite((unittest.makeSuite(BlacklistCacheTests),
                                unittest.makeSuite(SafeBrowsingManagerTests),
                                ))

if __name__ in ('main', '__main__'):
    unittest.main(defaultTest="allTests")


