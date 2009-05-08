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
#from blacklistcache import *

class SafeBrowsingManagerTests(unittest.TestCase):

    def setUp(self):
        config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        self.mgr = SafeBrowsingManager(config["safebrowsing_api_key"])

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

    def testSimpleAddUpdate(self):
        url = "www.example.com"
        update = MockSafeBrowsingUpdate(MALWARE, -1)
        hash = update.file.append_add(url)

        update.update_list()
        self.assertTrue(hash in update.new_hashes, "+%s was not parsed correctly" % hash)
        self.assertEqual(update.file.version, update.version, "Update and file should be at version 1")

    def testSimpleRemoveUpdate(self):
        url = "www.example.com"
        update = MockSafeBrowsingUpdate(MALWARE, -1)
        hash = update.file.append_remove(url)

        update.update_list()
        self.assertTrue(hash in update.old_hashes, "-%s was not parsed correctly" % hash)
        self.assertEqual(update.file.version, update.version, "Update and file should be at version 1")

    def testSimpleAddRemoveUpdate(self):
        add_url = "add.example.com"
        remove_url = "remove.example.com"
        update = MockSafeBrowsingUpdate(MALWARE, -1)
        add_hash = update.file.append_add(add_url)
        remove_hash = update.file.append_remove(remove_url)

        update.update_list()
        self.assertTrue(add_hash in update.new_hashes, "+%s was not parsed correctly" % add_hash)
        self.assertTrue(remove_hash in update.old_hashes, "-%s was not parsed correctly" % remove_hash)
        self.assertEqual(update.file.version, update.version, "Update and file should be at version 1")
 
    def testComplexUpdate1(self):
        url1 = "www1.example.com"
        url2 = "www2.example.com"
        url3 = "www3.example.com"

        update = MockSafeBrowsingUpdate(MALWARE, -1)
        hash1 = update.file.append_add(url1)
        hash2 = update.file.append_add(url2)

        update.update_list()
        self.assertTrue(hash1 in update.new_hashes, "+%s was not parsed correctly" % hash1)
        self.assertTrue(hash1 not in update.old_hashes, "+%s was not parsed correctly" % hash1)
        self.assertTrue(hash2 in update.new_hashes, "+%s was not parsed correctly" % hash2)
        self.assertTrue(hash2 not in update.old_hashes, "+%s was not parsed correctly" % hash2)
        self.assertEqual(update.file.version, update.version, "Update and file should be at version 1")

        update.file = MockUpdateFile(MALWARE, is_update=True)
        hash3 = update.file.append_remove(url3)

        update.update_list()
        self.assertTrue(hash1 not in update.new_hashes, "new_hashes was not preoperly cleared as %s still appears" % hash1)
        self.assertTrue(hash1 not in update.old_hashes, "old_hashes was not preoperly cleared as %s still appears" % hash1)
        self.assertTrue(hash2 not in update.new_hashes, "new_hashes was not preoperly cleared as %s still appears" % hash2)
        self.assertTrue(hash2 not in update.old_hashes, "old_hashes was not preoperly cleared as %s still appears" % hash2)
        self.assertTrue(hash3 not in update.new_hashes, "-%s was not parsed correctly" % hash3)
        self.assertTrue(hash3 in update.old_hashes, "-%s was not parsed correctly" % hash3)
        self.assertEqual(update.file.version, update.version, "Update and file should be at version 1")

    def testComplexUpdate2(self):
        url1 = "www1.example.com"
        url2 = "www2.example.com"
        url3 = "www3.example.com"

        update = MockSafeBrowsingUpdate(MALWARE, -1)
        hash1 = update.file.append_add(url1)
        hash2 = update.file.append_add(url2)

        update.update_list()
        self.assertTrue(hash1 in update.new_hashes, "+%s was not parsed correctly" % hash1)
        self.assertTrue(hash1 not in update.old_hashes, "+%s was not parsed correctly" % hash1)
        self.assertTrue(hash2 in update.new_hashes, "+%s was not parsed correctly" % hash2)
        self.assertTrue(hash2 not in update.old_hashes, "+%s was not parsed correctly" % hash2)
        self.assertEqual(update.file.version, update.version, "Update and file should be at version 1")

        update.file = MockUpdateFile(MALWARE, version=3)
        hash3 = update.file.append_add(url3)

        update.update_list()
        self.assertTrue(hash1 not in update.new_hashes, "new_hashes was not preoperly cleared as %s still appears" % hash1)
        self.assertTrue(hash1 not in update.old_hashes, "old_hashes was not preoperly cleared as %s still appears" % hash1)
        self.assertTrue(hash2 not in update.new_hashes, "new_hashes was not preoperly cleared as %s still appears" % hash2)
        self.assertTrue(hash2 not in update.old_hashes, "old_hashes was not preoperly cleared as %s still appears" % hash2)
        self.assertTrue(hash3 in update.new_hashes, "+%s was not parsed correctly" % hash3)
        self.assertTrue(hash3 not in update.old_hashes, "+%s was not parsed correctly" % hash3)
        self.assertEqual(update.file.version, update.version, "Update and file should be at version 3")


class MockSafeBrowsingUpdate(SafeBrowsingUpdate):

    def __init__(self, type, version):
        super(MockSafeBrowsingUpdate, self).__init__(type, version)
        self.file = MockUpdateFile(type)

    def retrieve_update(self, _):
        return self.file

    def update_list(self, apikey=None):
        super(MockSafeBrowsingUpdate, self).update_list(apikey)

class MockUpdateFile(object):

    def __init__(self, type, version=1, is_update=False):
        self.contents = None
        self.pos = 0
        if is_update:
            self.updatestr = " update"
        else:
            self.updatestr = ""
        self.type = type
        self.version = version

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
        url = "http://www.example.com/dir/../page.html"
        expected_url = "http://www.example.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relativate path failed: %s" % hasher.url)

    def testPathCanonicalization2(self):
        url = "http://www.example.com/./page.html"
        expected_url = "http://www.example.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative path failed: %s" % hasher.url)

    def testPathCanonicalization3(self):
        url = "http://www.example.com/dir/.././page.html"
        expected_url = "http://www.example.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative path failed: %s" % hasher.url)

    def testPathCanonicalization4(self):
        url = "http://www.example.com/dir1/dir2/../../page.html"
        expected_url = "http://www.example.com/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative paths failed: %s" % hasher.url)

    def testPathCanonicalization5(self):
        url = "http://www.example.com/dir/.."
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of relative path failed: %s" % hasher.url)

    def testPathCanonicalization6(self):
        url = "http://www.example.com/%7Edir/page.html"
        expected_url = "http://www.example.com/~dir/page.html"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of escaped path failed: %s" % hasher.url)

    def testPathCanonicalization7(self):
        url = "http://www.example.com"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization8(self):
        url = "http://www.example.com//"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)
 
    def testPathCanonicalization9(self):
        url = "http://www.example.com/path//"
        expected_url = "http://www.example.com/path/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization10(self):
        url = "http://www.example.com/path//dir/"
        expected_url = "http://www.example.com/path/dir/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization11(self):
        url = "http://www.example.com/path//../"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization12(self):
        url = "http://www.example.com////"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)

    def testPathCanonicalization13(self):
        url = "http://www.example.com////path///..//"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of short path failed: %s" % hasher.url)
 
    def testPathCanonicalizationFailure1(self):
        url = "http://www.example.com/../page.html"
        self.assertRaises(URLHasherError, URLHasher, url)

    def testPathCanonicalizationFailure2(self):
        url = "http://www.example.com/dir/../../page.html"
        self.assertRaises(URLHasherError, URLHasher, url)

    def testPathCanonicalizationFailure3(self):
        url = "http://www.example.com/..//page.html"
        self.assertRaises(URLHasherError, URLHasher, url)

    def testHostnameCanonicalization1(self):
        url ="http://www.example..com/"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testHostnameCanonicalization2(self):
        url ="http://www..example.com/"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testHostnameCanonicalization3(self):
        url ="http://www.example.com./"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testHostnameCanonicalization4(self):
        url ="http://.www.example.com/"
        expected_url = "http://www.example.com/"
        hasher = URLHasher(url)
        self.assertEqual(hasher.url, expected_url, "Canonicalization of hostname failed")

    def testURLCanonicalization(self):
        url = "HTTP://WWW.example.COM/"
        expected_url = "http://www.example.com/"
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
    return unittest.TestSuite((unittest.makeSuite(SafeBrowsingManagerTests),
                               unittest.makeSuite(SafeBrowsingUpdateTests),
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
    #display_warning()
   
    unittest.main(defaultTest="allTests")

