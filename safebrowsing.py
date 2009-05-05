#!/usr/bin/env python

# Tests in safebrowsing_tests.py

import socket
import urllib2
import urlparse
import re
from hashlib import md5

import cmemcache

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

    def __init__(self, type, version):
        self.type = type
        self.version = version
        self.new_hashes = []
        self.old_hashes = []

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

    def _get_phishing_version(self): return self.cache.get("safebrowsing-phishing-version")
    def _set_phishing_version(self, value): return self.cache.set("safebrowsing-phishing-version", value) 
    phishing_version = property(_get_phishing_version, _set_phishing_version, doc="The phishing blacklist version")

    def check_url(self, url):
        try:
            hasher = URLHasher(url)
        except URLHasherError, e:
            raise BlacklistCacheError(str(e))
        hashes = hasher.get_hashes()
        for hash in hashes:
            lookup = self.cache.get(hash)
            if self._validate_cache_value(lookup):
                return self._cache_value_type(lookup)

        return None

    def _validate_cache_value(self, value):
        if not value:
            return None

        type_alias = value[0]
        print "alias:", type_alias
        version = int(value[1:])
        print "version:", version
        print "m_version:", self.malware_version
        print "p_version:", self.phishing_version
        if type_alias == "m":
            return version >= self.malware_version
        if type_alias == "p":
            return version >= self.phishing_version

    def _cache_value_type(self, value):
        if value.startswith("m"):
            return MALWARE
        if value.startswith("p"):
            return PHISHING


class BlacklistCacheError(Exception):
    pass


class URLHasher(object):

    def __init__(self, url):
        self.url = self.canonicalize_url(url)

    def canonicalize_url(self, url):

        url = url.lower()
        urlparts = urlparse.urlparse(url)

        new_url = urlparse.urlunparse((urlparts.scheme,
                                       self._canonicalize_hostname(urlparts.netloc),
                                       self._canonicalize_path(urlparts.path),
                                       urlparts.params, urlparts.query, urlparts.fragment))
        return new_url

    def _canonicalize_hostname(self, hostname):
        # Canonicalizes a hostname by:
        # - removing all leading and trailing dots
        # - replace consecutive dots with a single dot

        # replace consecutive dots with a single dot
        new_hostname = re.sub("\.+", ".", hostname)

        # remove leading or trailing dots
        if new_hostname.startswith("."):
            new_hostname = new_hostname[1:]
        if new_hostname.endswith("."):
            new_hostname = new_hostname[:-1]

        return new_hostname

    def _canonicalize_path(self, path):
        # Canonicalizes a url path by:
        #  - unencoding any urlencoded values
        #  - removing "/.." and the preceding directory
        #  - removing all occurences of "/."
        #  - making sure there is a path i.e. replace "" with "/"

        # unescape the url
        new_path = urllib2.unquote(path)

        # Remove any directory traversal
        if new_path.startswith("/.."):
            raise URLHasherError("Invalid URL: path starts with relative path indicator '/..'")
        while re.search("/\.\.", new_path):
            if new_path.startswith("/.."):
                raise URLHasherError("Invalid URL: path contains too many of relative path indicator '/..'")
            new_path = re.sub("[^/]+/\.\.[/]?", "", new_path)
        new_path = new_path.replace("/./", "/")

        # making sure there is a path
        if new_path == "":
            return "/"

        return new_path

    def get_hashes(self):
        for hostname in self._generate_url_prefixes():
            for path in self._generate_url_suffixes():
                temp_url = ''.join([hostname, path])
                yield md5(temp_url).hexdigest()

    def _generate_url_prefixes(self):
        urlparts = urlparse.urlparse(self.url)
        hostname = urlparts.netloc
        yield hostname
        parts = hostname.split(".")
        if len(parts) > 5:
            parts = parts[-5:]

        for i in xrange(len(parts)*-1, -1):
            yield ".".join(parts[i:])

    def _generate_url_suffixes(self):
        urlparts = urlparse.urlparse(self.url)
        path = urlparts.path
        #params = urlparts.params
        query = urlparts.query
        fragment = urlparts.fragment

        if fragment:
            if query:
                yield ''.join([path, "?", query, "#", fragment])
            else:
                yield ''.join([path, "#", fragment])
        if query:
            yield ''.join([path, "?", query])
        yield path

        path = re.sub("[^/]*$", "", path)
        components = path.split("/")
        for i in xrange(2, len(components)):
            yield"/".join(components[0:i]) + "/"
        yield "/"


class URLHasherError(Exception):
    pass


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
    mgr = SafeBrowsingManager(config["safebrowsing_api_key"])
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
