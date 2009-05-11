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
 
