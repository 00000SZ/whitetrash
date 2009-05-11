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
from hashlib import md5

import cmemcache

from safebrowsing import *
from blacklistcache import *

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

    def testMalwareRawEntry1(self):
        """Test that the malware blacklist is correctly loaded into the cache"""
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        for d in self.mgr.get_lists():
            if d["type"] == MALWARE:
                self.assertTrue(self.raw_cache.get(d["hash"]), "Malware entry %s failed to update in cache" % d["hash"])

    def testPhishingRawEntry1(self):
        """Test that the phishing blacklist is correctly loaded into the cache"""
        self.cache.update(self.mgr.get_lists(), self.mgr.phishing.version, self.mgr.phishing.version)
        for d in self.mgr.get_lists():
            if d["type"] == PHISHING:
                self.assertTrue(self.raw_cache.get(d["hash"]), "Phishing entry %s failed to update in cache" % d["hash"])

    def testMalwareEntry1(self):
        """Test the malware blacklist gives a positive result for a known bad url (without URLHasher)"""
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        result = self.raw_cache.get(md5("malware.testing.google.test/testing/malware/").hexdigest())
        self.assertTrue(result.startswith("m"), "Malware blacklist lookup failed. Lookup: %s" % result)

    def testMalwareEntry2(self):
        """Test that the malware blacklist gives a positive result for a known bad url (with URLHasher)"""
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        result = self.cache.check_url("http://malware.testing.google.test/testing/malware/")
        self.assertEqual(result, MALWARE, "Malware blacklist lookup failed. Lookup: %s" % result)
 
    def testMalwareEntry3(self):
        """Test that the malware blacklist gives a positive result for a known bad url (with URLHasher)"""
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        result = self.cache.check_url("http://obfuscated.malware.testing.google.test/testing/malware/")
        self.assertEqual(result, MALWARE, "Malware blacklist lookup failed. Lookup: %s" % result)

    def testMalwareEntry4(self):
        """Test that the malware blacklist gives a positive result for a known bad url (with URLHasher)"""
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        result = self.cache.check_url("http://malware.testing.google.test/testing/malware/obfuscated.html")
        self.assertEqual(result, MALWARE, "Malware blacklist lookup failed. Lookup: %s" % result)

    def testMalwareEntry5(self):
        """Test that the malware blacklist gives a positive result for a known bad url (with URLHasher)"""
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        result = self.cache.check_url("http://malware.testing.google.test/testing/malware/obfuscated.html?obfu=1")
        self.assertEqual(result, MALWARE, "Malware blacklist lookup failed. Lookup: %s" % result)

    def testMalwareEntry6(self):
        """Test that the malware blacklist gives a positive result for a known bad url (with URLHasher)"""
        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
        result = self.cache.check_url("http://obfuscated.malware.testing.google.test/testing/malware/obfuscated.html?obfu=1")
        self.assertEqual(result, MALWARE, "Malware blacklist lookup failed. Lookup: %s" % result)

#    def testMalwareEntryAndRemoval1(self):
#        """Test that an update with a redacted url is correctly reflected in the cache"""
#        url = "www.example.com"
#        self.mgr.malware = MockSafeBrowsingUpdate(MALWARE, -1)
#        self.mgr.malware.file.append_add(url)
#        self.mgr.do_updates()
#
#        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
#        result = self.cache.check_url(url)
#        self.assertEqual(result, MALWARE, "Malware blacklist lookup failed. Lookup: %s" % result)
#        self.assertEqual(self.mgr.malware.file.version, self.cache.malware_version, "Malware blacklist version update failed.")
#        
#        self.mgr.malware.file = MockUpdateFile(MALWARE, is_update=True)
#        self.mgr.malware.file.append_remove(url)
#        self.mgr.do_updates()
#        
#        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
#        result = self.cache.check_url(url)
#        self.assertEqual(result, None, "Malware blacklist lookup failed. Lookup: %s" % result)
#        self.assertEqual(self.mgr.malware.file.version, self.cache.malware_version, "Malware blacklist version update failed.")

    def tearDown(self):
        self.raw_cache.flush_all()

def allTests():
    return unittest.TestSuite((unittest.makeSuite(BlacklistCacheTests),
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

