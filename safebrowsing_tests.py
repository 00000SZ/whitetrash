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

#    def testSimpleAdd1(self):
#        """Test that the cache sucessfully updates one entry"""
#        self.mgr.add_malware_update("test")
#        self.mgr.revoke_malware_update("test")
#        self.cache.update(self.mgr.get_lists(), self.mgr.malware.version, self.mgr.phishing.version)
#        self.assertEqual(result, MALWARE, "Malware blacklist lookup failed. Lookup: %s" % result)

    def tearDown(self):
        self.raw_cache.flush_all()

#class ManagerProxy(SafeBrowsingManager):
#    def __init__(self):
#        super(ManagerProxy, self).__init__()
#
#    def set_malware_add(self, raw_entry):
#        self.malware.new_hashes.append(md5(raw_entry))
#
#    def add_phishing_entry(self, raw_entry):
#        self.phishing.new_hashes.append(md5(raw_entry))
#
#    def del_malware_entry(self, raw_entry):
#        self.malware.old_hashes.append(md5(raw_entry))
#
#    def del_phishing_entry(self, raw_entry):
#        self.phishing.old_hashes.append(md5(raw_entry))



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

class SafeBrowsingUpdateTests(unittest.TestCase):

    def setUp(self):
        pass
#    def setUp(self):
#        self.sbu = SafeBrowsingUpdate(MALWARE, -1)
#
#    def testSimpleAdd1(self):
#        url = "www.example.com"
#        malware_list = create_patched_updater(self.sbu)
#        hash = malware_list.append_add(url)
#
#        self.sbu.update_list("")
#        self.assertTrue(hash in self.sbu.new_hashes, "Simple one line update failed")
#
#    def testSimpleAdd2(self):
#        url1 = "www.example1.com"
#        url2 = "www.example2.com"
#        malware_list = create_patched_updater(self.sbu)
#        hash1 = malware_list.append_add(url1)
#        hash2 = malware_list.append_add(url2)
#
#        self.sbu.update_list("")
#        self.assertTrue(hash1 in self.sbu.new_hashes, "Simple two line update failed")
#        self.assertTrue(hash2 in self.sbu.new_hashes, "Simple two line update failed")
#
#    def testSimpleRemove1(self):
#        url = "www.example.com"
#        malware_list = create_patched_updater(self.sbu)
#        hash = malware_list.append_remove(url)
#
#        self.sbu.update_list("")
#        self.assertTrue(hash in self.sbu.old_hashes, "Simple one line update failed")
#
#    def testSimpleRemove2(self):
#        url1 = "www.example1.com"
#        url2 = "www.example2.com"
#        malware_list = create_patched_updater(self.sbu)
#        hash1 = malware_list.append_remove(url1)
#        hash2 = malware_list.append_remove(url2)
#
#        self.sbu.update_list("")
#        self.assertTrue(hash1 in self.sbu.old_hashes, "Simple two line update failed")
#        self.assertTrue(hash2 in self.sbu.old_hashes, "Simple two line update failed")
#
#    def testUpdateOfSameVersion1(self):
#        url1 = "www.example1.com"
#        url2 = "www.example2.com"
#        malware_list = create_patched_updater(self.sbu)[0]
#        hash1 = malware_list.append_add(url1)
#        hash2 = malware_list.append_add(url2)
#
#        self.sbu.update_list("")
#        self.assertTrue(hash1 in self.sbu.new_hashes, "Simple two line update failed")
#        self.assertTrue(hash2 in self.sbu.new_hashes, "Simple two line update failed")
#
#        malware_list = create_patched_updater(update=True)[0]
#        hash1 = malware_list.append_remove(url1)
#
#        self.sbu.update_list("")
#        self.assertTrue(hash1 not in self.sbu.new_hashes, "Simple two line update failed")
#        self.assertTrue(hash2 in self.sbu.new_hashes, "Simple two line update failed")
#
#
#def create_patched_updater(type=None, version=None, update=False):
#    if type:
#        if version:
#            sbu = SafeBrowsingUpdate(type, version)
#        sbu = SafeBrowsingUpdate(type, 1)
#    mock_update = FauxRawUpdate(sbu.type, is_update=update)
#    def mock(self):
#        return mock_update
#    sbu.retrieve_update = mock
#    return mock_update

    def testSimpleAdd2(self):
        url1 = "www.example1.com"
        url2 = "www.example2.com"

        update_file = MockUpdateFile(MALWARE)
        update = MockedSafeBrowsingUpdate(update_file, MALWARE, -1)

        hash1 = update_file.append_add(url1)
        hash2 = update_file.append_add(url2)
        update.update_list()

        self.assertTrue(hash1 in update.new_hashes, "Simple two line update failed")
        self.assertTrue(hash2 in update.new_hashes, "Simple two line update failed")

        





class MockedSafeBrowsingUpdate(SafeBrowsingUpdate):

    def __init__(self, update, *args):
        super(MockedSafeBrowsingUpdate, self).__init__(self, *args)
        self.file = update

    def retrieve_update(self):
        return self.file

    def update_list(self):
        super(MockedSafeBrowsingUpdate, self).update_list("")

class MockUpdateFile(object):

    def __init__(self, type, version=1, is_update=False):
        self.contents = None
        self.pos = 0
        self.type = type
        self.version = version
        if is_update:
            self.updatestr = " update"
        else:
            self.updatestr = ""

#    def clear_contents(self):
#        self.update = []
#        self.pos = 0
#        self.set_header()

    def set_header(self):
        header = "[goog-" + self.type + "-hash 1." + str(self.version) + self.updatestr + "]"
        if self.contents is not None:
            self.contents[0] = header
        else:
            self.contents = [header]

    def get_version(self): return self._version
    def set_version(self, version):
        self._version = version
        self.set_header()
    version = property(get_version, set_version)

    def append_add(self, url):
        hash = md5(url).hexdigest()
        self.contents.append("".join(["+",hash]))
        return hash

    def append_remove(self, url):
        hash = md5(url).hexdigest()
        self.contents.append("".join(["-",hash]))
        return hash

    def readline(self):
        self.pos += 1
        return self.contents[self.pos-1]

    def __iter__(self):
        return iter(self.contents[self.pos:])


class URLHasherTests(unittest.TestCase):

    def setUp(self):
        self.abc_url = "http://a.b.c/1/2.html?param=1"
        self.abcefg_url = "http://a.b.c.d.e.f.g/1.html"

    # For all these tests see the Safe Browsing API documentation at:
    # http://code.google.com/apis/safebrowsing/developers_guide.html#Canonicalization

    def testPathCanonicalization1(self):
        url = "http://www.google.com/dir/../page.html"
        expected_url = "http://www.google.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relativate path failed: %s" % hasher.url)

    def testPathCanonicalization2(self):
        url = "http://www.google.com/./page.html"
        expected_url = "http://www.google.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative path failed: %s" % hasher.url)

    def testPathCanonicalization3(self):
        url = "http://www.google.com/dir/.././page.html"
        expected_url = "http://www.google.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative path failed: %s" % hasher.url)

    def testPathCanonicalization4(self):
        url = "http://www.google.com/dir1/dir2/../../page.html"
        expected_url = "http://www.google.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative paths failed: %s" % hasher.url)

    def testPathCanonicalization5(self):
        url = "http://www.google.com/dir/.."
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative path failed: %s" % hasher.url)

    def testPathCanonicalization6(self):
        url = "http://www.google.com/%7Edir/page.html"
        expected_url = "http://www.google.com/~dir/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of escaped path failed: %s" % hasher.url)

    def testPathCanonicalization7(self):
        url = "http://www.google.com"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization8(self):
        url = "http://www.google.com//"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)
 
    def testPathCanonicalization9(self):
        url = "http://www.google.com/path//"
        expected_url = "http://www.google.com/path/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization10(self):
        url = "http://www.google.com/path//dir/"
        expected_url = "http://www.google.com/path/dir/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization11(self):
        url = "http://www.google.com/path//../"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization12(self):
        url = "http://www.google.com////"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization13(self):
        url = "http://www.google.com////path///..//"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)
 
    def testPathCanonicalizationFailure1(self):
        url = "http://www.google.com/../page.html"
        self.assertRaises(URLHasherError, URLHasher, url)

    def testPathCanonicalizationFailure2(self):
        url = "http://www.google.com/dir/../../page.html"
        self.assertRaises(URLHasherError, URLHasher, url)

    def testPathCanonicalizationFailure3(self):
        url = "http://www.google.com/..//page.html"
        self.assertRaises(URLHasherError, URLHasher, url)

    def testHostnameCanonicalization1(self):
        url ="http://www.google..com/"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testHostnameCanonicalization1(self):
        url ="http://www..google.com/"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testHostnameCanonicalization1(self):
        url ="http://www.google.com./"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testHostnameCanonicalization1(self):
        url ="http://.www.google.com/"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testURLCanonicalization(self):
        url = "HTTP://WWW.GOOGLE.COM/"
        expected_url = "http://www.google.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of url failed")

    # For all these tests see the Safe Browsing API documentation at:
    # http://code.google.com/apis/safebrowsing/developers_guide.html#PerformingLookups

    def testHashGeneration1(self):
        hash = md5("a.b.c/1/2.html?param=1").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration2(self):
        hash = md5("a.b.c/1/2.html").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration3(self):
        hash = md5("a.b.c/").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration4(self):
        hash = md5("a.b.c/1/").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration5(self):
        hash = md5("b.c/1/2.html?param=1").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration6(self):
        hash = md5("b.c/1/2.html").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration7(self):
        hash = md5("b.c/").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration8(self):
        hash = md5("b.c/1/").hexdigest()
        hasher = URLHasher(self.abc_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration9(self):
        hash = md5("a.b.c.d.e.f.g/1.html").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration10(self):
        hash = md5("a.b.c.d.e.f.g/").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration11(self):
        hash = md5("c.d.e.f.g/1.html").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration12(self):
        hash = md5("c.d.e.f.g/").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration13(self):
        hash = md5("d.e.f.g/1.html").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration14(self):
        hash = md5("d.e.f.g/").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration15(self):
        hash = md5("e.f.g/1.html").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration16(self):
        hash = md5("e.f.g/").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration16(self):
        hash = md5("f.g/1.html").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration17(self):
        hash = md5("f.g/").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration18(self):
        hash = md5("b.c.d.e.f.g/1.html").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash not in hasher.generate_hashes(), "Hash generation failed")

    def testHashGeneration19(self):
        hash = md5("b.c.d.e.f.g/").hexdigest()
        hasher = URLHasher(self.abcefg_url)
        self.assertTrue(hash not in hasher.generate_hashes(), "Hash generation failed")

 

def allTests():
    return unittest.TestSuite((unittest.makeSuite(BlacklistCacheTests),
                               unittest.makeSuite(SafeBrowsingManagerTests),
                               #unittest.makeSuite(SafeBrowsingUpdateTests),
                               unittest.makeSuite(URLHasherTests),
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

