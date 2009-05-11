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
    return unittest.TestSuite((unittest.makeSuite(URLHasherTests),
                               ))

if __name__ in ('main', '__main__'):
    unittest.main(defaultTest="allTests")

