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

import cmemcache

from safebrowsing import *

class BlacklistCacheTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.cache = BlacklistCache(config)
        self.raw_cache = cmemcache.Client(config["memcache_servers"].split(","))

        self.mgr = SafeBrowsingManager(config["safebrowsing_api_key"])
        self.mgr.do_updates()

    def testMalwareVersion1(self):
        """Test that the malware blacklist version can be set"""
        self.cache.malware_version = 1
        self.assertEqual(self.cache.malware_version, 1, "Cache did not save version")

    def testMalwareVersion2(self):
        """Test that the malware blacklist version is automatically set to -1"""
        self.assertEqual(self.cache.malware_version, -1, "Cache did not initialize version to -1")

    def testPhishingVersion1(self):
        """Test that the phishing blacklist version can be set"""
        self.cache.phishing_version = 1
        self.assertEqual(self.cache.phishing_version, 1, "Cache did not save version")

    def testPhishingVersion2(self):
        """Test that the phishing blacklist version is automatically set to -1"""
        self.assertEqual(self.cache.phishing_version, -1, "Cache did not initialize version to -1")

    def testMalwareEntry1(self):
        """Test the the malware blacklist is correctly loaded into the cache"""
        self.raw_cache.flush_all()
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        for d in self.mgr.get_lists():
            if d["type"] == MALWARE:
                self.assertTrue(self.raw_cache.get(d["hash"]), "Malware entry %s failed to update in cache" % d["hash"])

    def testPhishingEntry1(self):
        """Test the the phishing blacklist is correctly loaded into the cache"""
        self.raw_cache.flush_all()
        self.cache.update(self.mgr.get_lists(), self.mgr.phishing.version, self.mgr.phishing.version)
        for d in self.mgr.get_lists():
            if d["type"] == PHISHING:
                self.assertTrue(self.raw_cache.get(d["hash"]), "Phishing entry %s failed to update in cache" % d["hash"])


class SafeBrowsingManagerTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.cache = BlacklistCache(config)
        self.mgr = SafeBrowsingManager(config["safebrowsing_api_key"])

    def testInit1(self):
        """Test that both the blacklist manager and blacklist cache are initialising list versions to the same value"""
        self.assertEqual(self.mgr.malware.version, self.cache.malware_version, "Malware Update/Manager version mismatch")
        self.assertEqual(self.mgr.phishing.version, self.cache.phishing_version, "Phishing Update/Manager version mismatch")

    def testInit2(self):
        """Test that both the blacklist manager is initialising list versions to -1"""
        self.assertEqual(self.mgr.malware.version, -1, "Blacklist Manager version was not initialised to -1")
        self.assertEqual(self.mgr.phishing.version, -1, "Blacklist Manager version was not initialised to -1")

    def testUpdateVersioning1(self):
        """Test that both the blacklist manager is updating list versions"""
        self.mgr.do_updates()
        self.assertTrue(self.mgr.malware.version > 0, "Malware list did not update version")
        self.assertTrue(self.mgr.phishing.version > 0, "Phishing list did not update version")

    def testUpdateVersioning2(self):
        """Test that both the blacklist manager is updating list versions"""
        self.mgr.do_updates(3, 4)
        self.assertTrue(self.mgr.malware.version > 3, "Malware list did not update version")
        self.assertTrue(self.mgr.phishing.version > 4, "Phishing list did not update version")

    def testUpdateVersioning3(self):
        """Test that both the blacklist manager is updating list versions"""
        self.mgr.do_updates(3, 4)
        self.mgr.do_updates()
        self.assertTrue(self.mgr.malware.version > 3, "Malware list did not update version")
        self.assertTrue(self.mgr.phishing.version > 4, "Phishing list did not update version")

    def testUpdateSuccess(self):
        """Test that both the blacklist manager is getting at least one malware and one phishing result during an update"""
        malware_success  = False
        phishing_success = False

        self.mgr.do_updates()
        for entry in self.mgr.get_lists():
            if entry["hash"]:
                if entry["type"] == MALWARE:
                    malware_success = True
                if entry["type"] == PHISHING:
                    phishing_success = True
        self.assertTrue(malware_success,  "Malware updates failed")
        self.assertTrue(phishing_success, "Phishing updates failed")

    def testTypicalUseCase1(self):
        """A more thorough test corresponding to a typical use of the blacklist manager"""
        self.mgr.do_updates()

        self.assertTrue(self.mgr.malware.version > 0, "Malware list did not update version")
        self.assertTrue(self.mgr.phishing.version > 0, "Phishing list did not update version")
        self.assertTrue(len(self.mgr) > 0, "Update failed")
        m_version = self.mgr.malware.version
        p_version = self.mgr.phishing.version

        self.mgr.do_updates(self.mgr.malware.version, self.mgr.phishing.version)

        self.assertTrue(self.mgr.malware.version >= m_version, "Malware list did not update version")
        self.assertTrue(self.mgr.phishing.version >= p_version, "Phishing list did not update version")
        self.assertTrue(len(self.mgr) > 0, "Update failed")


def allTests():
    return unittest.TestSuite((unittest.makeSuite(BlacklistCacheTests),
                               unittest.makeSuite(SafeBrowsingManagerTests),
                               ))

def display_warning():
    import time
    import sys

    print "----------------------------- WARNING ------------------------"
    print "Some of these tests will flush memcache completely"
    print "Do not continue if you are running this on a production system"
    print "--------------------------------------------------------------"

    print "Continuing tests in",
    for i in xrange(10,0,-1):
        print i,
        sys.stdout.flush()
        time.sleep(1)
    print

if __name__ in ('main', '__main__'):
    display_warning()
   
    unittest.main(defaultTest="allTests")

