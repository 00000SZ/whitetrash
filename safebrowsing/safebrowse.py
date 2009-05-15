#!/usr/bin/env python

# Tests in safebrowsing_tests.py

import socket
import urllib2
import urlparse
import re
import time
from hashlib import md5

import cmemcache


# Constants for version 1 of the Safe Browsing API
MALWARE = "malware"
PHISHING = "black"
SB_URL_TEMPLATE = "http://sb.google.com/safebrowsing/update?client=api&apikey=%s&version=%s"
HEADER_REGEX = "\[goog-(malware|black)-hash 1.([0-9]*).*\]"
HASH_REGEX = "(\+|\-)([a-f0-9]*)"
TIMEOUT = 30 * 60      # 30 minutes
 

class SafeBrowsingUpdate(object):
    """Grabs the phishing or malware blacklists from
       the Google safebrowsing API"""

    def __init__(self, type, version, proxy):
        self._type = type
        self._version = version
        self.proxy = proxy
        self.new_hashes = []
        self.old_hashes = []

    @property
    def version(self):
        return self._version

    @property
    def type(self):
        return self._type

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
        # python 2.6 adds timeout as a parameter for urllib2.urlopen()
        socket.setdefaulttimeout(10) # 10 seconds

        # Grab the blacklist
        try:
            if self.proxy:
                    proxy_support = urllib2.ProxyHandler({"http" : self.proxy})
                    opener = urllib2.build_opener(proxy_support)
                    urllib2.install_opener(opener)
            return urllib2.urlopen(url)
            #return self._local_fopen(url) # for testing only
        except urllib2.URLError, e:
            if hasattr(e, "reason"):
                raise SafeBrowsingUpdateError(e.reason)
            elif hasattr(e, "code"):
                raise SafeBrowsingUpdateError(str(e))

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

        self._version = int(version)

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
                return open("gsb_phishing.html")
            elif m.group(1) == "malware":
                return open("gsb_malware2.html")


class SafeBrowsingUpdateError(Exception):
    pass


class SafeBrowsingManager():
    """Manages the retreival of updates from the safe browsing API"""

    MAX_WAIT = 360

    """A dictionary with the of number of consecutive errors as keys and
       time to wait before next update (in minutes) as values. >5 consecutive
       errors have to wait 360 minutes"""
    backoff = {0 : 25,
               1 : 1,
               2 : 1,
               3 : 60,
               4 : 180,
               5 : MAX_WAIT}

    def __init__(self, apikey, proxy=None):
        self._apikey = apikey
        self.malware  = SafeBrowsingUpdate(MALWARE, -1, proxy)
        self.phishing = SafeBrowsingUpdate(PHISHING, -1, proxy)

    def do_updates(self, malware_version=None, phishing_version=None):
        if malware_version:
            self.malware = SafeBrowsingUpdate(MALWARE, malware_version)
        if phishing_version:
            self.phishing = SafeBrowsingUpdate(PHISHING, phishing_version)
        try:
            self.malware.update_list(self._apikey)
            self.phishing.update_list(self._apikey)
        except SafeBrowsingUpdateError, e:
            raise SafeBrowsingUpdateError("Update failed")

    def do_updates_blocking(self, malware_version=None, phishing_version=None):
        errors = 0
        while True:
            try:
                self.do_updates(malware_version, phishing_version)
            except SafeBrowsingUpdateError, e:
                errors += 1
                # sleep according to the number of errors we've seen
                # default is to sleep for 360 minutes (for 5 or more errors)
                time.sleep(self.backoff.get(errors, MAX_WAIT) * 60)
            finally:
                break


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
        #  - replacing runs on consecutive slashes with a single slash

        # unescape the url
        new_path = urllib2.unquote(path)

        # replace multiple slahses (e.g. "////") with "/"
        new_path = re.sub("/+", "/", new_path)

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

    def generate_hashes(self):
        for url in self.generate_url_combinations():
            yield md5(url).hexdigest()

    def generate_url_combinations(self):
         for hostname in self._generate_url_prefixes():
            for path in self._generate_url_suffixes():
                yield ''.join([hostname, path])

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
        if not path.endswith("/"):
            yield path

        path = re.sub("[^/]*$", "", path)
        components = path.split("/")
        for i in xrange(len(components)-1, 1, -1):
            yield "/".join(components[0:i]) + "/"
        yield "/"


class URLHasherError(Exception):
    pass

