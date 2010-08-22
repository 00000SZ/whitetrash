#!/usr/bin/env python

# Tests in blacklistcache_tests.py

"""
BlacklistCache provides a way of storing and looking up malicious
domains as identified by the Google Safe Browsing API.  Malicious
URLs are retrieved by a python wrapper for the Safe Browsing API
called "safebrowse".  These are then stored in the memcache as md5
hashes (as provided by the API) for quick lookup.  BlackListCache
will then check all combinations of any given URL to confirm whether
it is in the current blacklist.

Google Safe Browsing API docs:
http://code.google.com/apis/safebrowsing/developers_guide.html
"""

import logging
import logging.config
import time

try:
    import cmemcache
    from safebrowse import *
except ImportError:
    pass

log = logging.getLogger(__name__)

TIMEOUT = 30 * 60      # 30 minutes
MALWARE = "malware"
PHISHING = "black"

class BlacklistCache(object):
    """Maintains the a list of hashes from the safe browsing API in memcache"""

    def __init__(self, config):
        self.cache = cmemcache.Client(config["memcache_servers"].split(","))
        self.malware_version = -1
        self.phishing_version = -1

    def update(self, list, m_version, p_version):
        """
        Takes a list of tuples containing (hash, type, add, remove) and then
        either adds or removes that hash from the cache.  If adding to the
        cache the hash is used as the key and the value is stored as
        <type><version>. <type> is one letter (either "m" or "p") to
        indicate whether this is a malware or phishing site respectively.
        <version> is the version of the blacklist which indicated this was a
        malicious domain - this information is used in lookups
        """

        log.debug("Updating memcache")
        for i in list:
            # Update all malware hashes
            if i["type"] == MALWARE:
                if i["add"]:
                    self.cache.set(i["hash"], "".join(["m", str(m_version)]), TIMEOUT)
                if i["remove"]:
                    self.cache.delete(i["hash"])
            # Update all phishing hashes
            if i["type"] == PHISHING:
                if i["add"]:
                    self.cache.set(i["hash"], "".join(["p", str(p_version)]), TIMEOUT)
                if i["remove"]:
                    self.cache.delete(i["hash"])
        # Update the current blacklsit versions in the database
        self.malware_version = m_version
        self.phishing_version = p_version

    # 
    def _get_malware_version(self): return self.cache.get("safebrowsing-malware-version")
    def _set_malware_version(self, value): return self.cache.set("safebrowsing-malware-version", value) 
    malware_version = property(_get_malware_version, _set_malware_version, doc="The malware blacklist version")

    def _get_phishing_version(self): return self.cache.get("safebrowsing-phishing-version")
    def _set_phishing_version(self, value): return self.cache.set("safebrowsing-phishing-version", value) 
    phishing_version = property(_get_phishing_version, _set_phishing_version, doc="The phishing blacklist version")

    def check_url(self, url):
        log.debug("Checking URL: %s" % url)
        try:
            hasher = URLHasher(url)
        except URLHasherError, e:
            raise BlacklistCacheError(str(e))
        hashes = hasher.generate_hashes()
        for hash in hashes:
            lookup = self.cache.get(hash)
            if lookup:
                if self._validate_cache_value(lookup):
                    return self._cache_value_type(lookup)
                else:
                    # delete entries from old blacklist versions
                    self.cache.delete(key)

        return None

    def _validate_cache_value(self, value):
        version = int(value[1:])
        if value.startswith("m"):
            return version >= self.malware_version
        if value.startswith("p"):
            return version >= self.phishing_version

    def _cache_value_type(self, value):
        if value.startswith("m"):
            return MALWARE
        if value.startswith("p"):
            return PHISHING


class BlacklistCacheError(Exception): pass


def main():
    import configobj
    config = configobj.ConfigObj("../whitetrash.conf")["DEFAULT"]
    if config["use_memcached"].upper()=="TRUE":
        update_safebrowsing_blacklist(config)
    else:
        print "memcached not configured"

def update_safebrowsing_blacklist(config):
    cache = BlacklistCache(config)
    apikey = config["safebrowsing_api_key"]
    try:
        proxy = config["safebrowsing_proxy"]
        cache.log.debug("Using proxy: %s for updates" % proxy)
    except KeyError, e:
        proxy = None

    mgr = SafeBrowsingManager(apikey, proxy)
    try:
        mgr.do_updates_blocking()
    except SafeBrowsingUpdateError, e:
        cache.log.error(e)
        print e
        return

    try:
        cache.update(mgr.get_lists(),mgr.malware.version,mgr.phishing.version)
    except BlacklistCacheError, e:
        cache.log.error(e)
        print e

if __name__ == '__main__':
    main()
