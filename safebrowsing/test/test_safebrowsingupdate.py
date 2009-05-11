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
from updatemocking import *

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

def allTests():
    return unittest.TestSuite((unittest.makeSuite(SafeBrowsingUpdateTests),
                               ))

if __name__ in ('main', '__main__'):
    unittest.main(defaultTest="allTests")

