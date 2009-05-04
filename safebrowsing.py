#!/usr/bin/env python

# Test in safebrowsing_tests.py

import cmemcache
import socket
import urllib2
import re

# Constants for version 1 of the Safe Browsing API
MALWARE = "malware"
PHISHING = "black"
SB_URL_TEMPLATE = "http://sb.google.com/safebrowsing/update?client=api&apikey=%s&version=%s"
HEADER_REGEX = "\[goog-(malware|black)-hash 1.([0-9]*).*\]"
HASH_REGEX = "(\+|-)([a-f0-9]*)"
TIMEOUT = 30 * 60      # 30 minutes
 
class SafeBrowsingUpdate(object):
    """Grabs the phishing or malware blacklists from
       the Google safebrowsing API"""

    new_hashes = []
    old_hashes = []

    def __init__(self, type, version):
        self.type = type
        self.version = version

    def get_version_string(self):
        if self.type == MALWARE:
            return "goog-malware-hash:1:%s" % self.version
        elif self.type == PHISHING:
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
        url = SB_URL_TEMPLATE % (apikey, self.get_version_string())

        # Set the timeout for the get request
        # python 2.6 adds timeout at an parameter for urllib2.urlopen()
        socket.setdefaulttimeout(10) # 10 seconds

        # Grab the blacklist
        try:
            return urllib2.urlopen(url)
            #return self._local_fopen(url) # for testing only
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
        pattern = re.compile(HASH_REGEX)
        for line in file:
            m = pattern.search(line)
            if m:
                if m.group(1) == "+":
                    self.new_hashes.append(m.group(2))
                elif m.group(1) == "-":
                    self.old_hashes.append(m.group(2))

        self.version = version

    def parse_header(self, header):
        """Pull the version number and blacklist type from the header"""

        m = re.search(HEADER_REGEX, header)
        if m:
            type    = m.group(1)
            version = m.group(2)
            return type, version
        else:
            return None

    def __repr__(self):
        repr = ""
        if self.type == MALWARE:
            repr += "Malware Blacklist\n"
        elif self.type == PHISHING:
            repr += "Phishing Blacklist\n"
        repr += "Version: %s\n" % self.version
        repr += "Records added: %s\n" % len(self.new_hashes)
        repr += "Records removed: %s\n" % len(self.old_hashes)

        return repr

    def __len__(self):
        return len(self.new_hashes) + len(self.old_hashes)
    
    def _local_fopen(self,url):
        """For testing purposes only"""

        m = re.search("(black|malware)", url)

        if m:
            if m.group(1) == "black":
                return open("../gsb_phishing.html")
            elif m.group(1) == "malware":
                return open("../gsb_malware.html")


class BlacklistCache(object):
    """Maintains the a list of hashes from the safe browsing API in memcache"""

    def __init__(self, config):
        self.cache = cmemcache.Client(config["memcache_servers"].split(","))
        self.malware_version = -1
        self.phishing_version = -1

    def update(self, list, m_version, p_version):
        for i in list:
            if i["type"] == MALWARE:
                if i["add"]:
                    self.cache.set(i["hash"], "m".join([str(m_version)]), TIMEOUT)
                if i["remove"]:
                    self.cache.delete(i["hash"])
            if i["type"] == PHISHING:
                if i["add"]:
                    self.cache.set(i["hash"], "p".join([str(p_version)]), TIMEOUT)
                if i["remove"]:
                    self.cache.delete(i["hash"])
        self.malware_version = m_version
        self.phishing_version = p_version

    def _get_malware_version(self): return self.cache.get("safebrowsing-malware-version")
    def _set_malware_version(self, value): return self.cache.set("safebrowsing-malware-version", value) 
    malware_version = property(_get_malware_version, _set_malware_version, doc="The malware blacklist version")

    def _get_phishing_version(self): return self.cache.get("safebrowsing-black-version")
    def _set_phishing_version(self, value): return self.cache.set("safebrowsing-black-version", value) 
    phishing_version = property(_get_phishing_version, _set_phishing_version, doc="The phishing blacklist version")

#    def check_url(self, url):
#        # use urlparse here instead
#        url = url.lower()
#        url_regex = re.compile("")
#        url_match = url_regex.match(url)
#        if url_match:
#            url, prefix, suffix = url_match.groups()
#            for domain in _generate_url_prefixes(prefix):
#                for path in _generate_url_suffixes(suffix):
#                    temp_url = domain.join([path])
#
#    def _generate_url_prefixes(self, prefix):
#        return prefix
#
#    def _generate_url_suffixes(suffix):
#        return suffix

class SafeBrowsingManager():
    """Manages the retreival of updates from the safe browsing API"""

    def __init__(self, apikey):
        self._apikey = apikey
        self.malware  = SafeBrowsingUpdate(MALWARE, -1)
        self.phishing = SafeBrowsingUpdate(PHISHING, -1)

    def do_updates(self, malware_version = None, phishing_version = None):
        if malware_version:
            self.malware = SafeBrowsingUpdate(MALWARE, malware_version)
        if phishing_version:
            self.phishing = SafeBrowsingUpdate(PHISHING, phishing_version)
        self.malware.update_list(self._apikey)
        self.phishing.update_list(self._apikey)

    def get_lists(self):
        for h in self.malware.old_hashes:
            yield dict(type=MALWARE,
                       hash=h,
                       add=False,
                       remove=True)
        for h in self.malware.new_hashes:
            yield dict(type=MALWARE,
                       hash=h,
                       add=True,
                       remove=False)
        for h in self.phishing.old_hashes:
            yield dict(type=PHISHING,
                       hash=h,
                       add=False,
                       remove=True)
        for h in self.phishing.new_hashes:
            yield dict(type=PHISHING,
                       hash=h,
                       add=True,
                       remove=False)

    def __len__(self):
        return len(self.malware) + len(self.phishing)


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
