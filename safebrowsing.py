#!/usr/bin/env python

# Test in safebrowsing_tests.py

import cmemcache
import socket
import urllib2
import re

class SafeBrowsingUpdate(object):
    """Grabs the phishing or malware blacklists from
       the Google safebrowsing API"""

    MALWARE  = "malware"
    PHISHING = "black"
    URL_TEMPLATE = "http://sb.google.com/safebrowsing/update?client=api&apikey=%s&version=%s"
    HEADER_REGEX = "\[goog-(malware|black)-hash 1.([0-9]*).*\]"
    HASH_REGEX   = "(\+|-)([a-f0-9]*)"
    new_hashes = []
    old_hashes = []

    def __init__(self, type, version):
        self.type = type
        self.version = version

    def get_version_string(self):
        if self.type == self.MALWARE:
            return "goog-malware-hash:1:%s" % self.version
        elif self.type == self.PHISHING:
            return "goog-black-hash:1:%s" % self.version
        #elif self.type == ALL:
        #    return "goog-malware-hash:1:%s,goog-black-hash:1:%s" % (malware_version, phising version)

    def update_list(self, apikey):
        """Retreive and read the latest update"""

        file = self.retrieve_update(apikey)
        self.parse_update(file)

    def retrieve_update(self, apikey):
        """Grab the latest blacklist from the Google safebrowsing API"""

        # Get the full url to use
        url = self.URL_TEMPLATE % (apikey, self.get_version_string())

        # Set the timeout for the get request
        # python 2.6 adds timeout at an parameter for urllib2.urlopen()
        socket.setdefaulttimeout(10) # 10 seconds

        # Grab the blacklist
        try:
            #return urllib2.urlopen(url)
            return self.__local_fopen__(url) # for testing only
        except urllib2.URLError, e:
            if hasattr(e, "reason"):
                print "Reason", e.reason
            elif hasattr(e, "code"):
                print e
            return

    def parse_update(self, file):
        """Parses the retreived file"""

        self.new_hashes = []
        self.old_hashes = []
        (type, version) = self.parse_header(file.readline())
        pattern = re.compile(self.HASH_REGEX)
        for line in file:
            m = pattern.search(line)
            if m:
                if m.group(1) == "+":
                    self.new_hashes.append(m.group(1))
                elif m.group(1) == "-":
                    self.old_hashes.append(m.group(1))

        self.version = version

    def parse_header(self, header):
        """Pull the version number and blacklist type from the header"""

        m = re.search(self.HEADER_REGEX, header)
        if m:
            type    = m.group(1)
            version = m.group(2)
            return type, version
        else:
            return None

    def __repr__(self):
        repr = ""
        if self.type == self.MALWARE:
            repr += "Malware Blacklist\n"
        elif self.type == self.PHISHING:
            repr += "Phishing Blacklist\n"
        repr += "Version: %s\n" % self.version
        repr += "Records added: %s\n" % len(self.new_hashes)
        repr += "Records removed: %s\n" % len(self.old_hashes)

        return repr
    
    def __local_fopen__(self,url):
        """For testing purposes only"""

        m = re.search("(black|malware)", url)

        if m:
            if m.group(1) == "black":
                return open("../gsb_phishing.html")
            elif m.group(1) == "malware":
                return open("../gsb_malware.html")


def Property(func):
    return property(**func())


class BlacklistCache(object):
    """Maintains the a list of hashes from the safe browsing API in memcache"""

    def __init__(self, config):
        self.cache = cmemcache.StringClient(config["memcache_servers"].split(","))
        self.malware_version = -1
        self.phishing_version = -1

    def update(self, list):
        pass

    @Property
    def malware_version():
        doc = "The malware blacklist version"

        def fget(self):
            return int(self.cache.get("safebrowsing-malware-version"))

        def fset(self, value):
            return self.cache.set("safebrowsing-malware-version", str(value)) 

        return locals()

    @Property
    def phishing_version():
        doc = "The phishing blacklist version"

        def fget(self):
            return int(self.cache.get("safebrowsing-phishing-version"))

        def fset(self, value):
            return self.cache.set("safebrowsing-phishing-version", str(value)) 

        return locals()


class SafeBrowsingManager():
    """Manages the retreival of updates from the safe browsing API"""

    def __init__(self, apikey, malware_version, phishing_version):
        self.apikey = apikey
        self.malware  = SafeBrowsingUpdate(SafeBrowsingUpdate.MALWARE,  malware_version)
        self.phishing = SafeBrowsingUpdate(SafeBrowsingUpdate.PHISHING, phishing_version)

    def do_updates(self):
        self.malware.update_list(self.apikey)
        self.phishing.update_list(self.apikey)

    def get_lists(self):
        for h in self.malware.old_hashes:
            yield dict(type="MALWARE",
                       hash=h,
                       add=False,
                       remove=True)
        for h in self.malware.new_hashes:
            yield dict(type="MALWARE",
                       hash=h,
                       add=True,
                       remove=False)
        for h in self.phishing.old_hashes:
            yield dict(type="PHISHING",
                       hash=h,
                       add=False,
                       remove=True)
        for h in self.phishing.new_hashes:
            yield dict(type="PHISHING",
                       hash=h,
                       add=True,
                       remove=False)

def main():
    import configobj
    config = configobj.ConfigObj("whitetrash.conf")["DEFAULT"]
    if config["use_memcached"].upper()=="TRUE":
        update_safebrowsing_blacklist(config)
    else:
        print "memcached not configured"

def update_safebrowsing_blacklist(config):
    cache = BlacklistCache(config)
    d = dict(apikey = config["safebrowsing_api_key"],
             malware_version = cache.malware_version,
             phishing_version = cache.phishing_version,
             retry = cache.last_request_status)
    mgr = SafeBrowsingManager(**d)
    try:
        mgr.get_updates()
    except SafeBrowsingAvailabilityException, e:
        print e
        return

    try:
        cache.update(mgr.list)
    except BlacklistUpdateException, e:
        print e

if __name__ == '__main__':
    main()
