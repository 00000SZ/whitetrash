#!/usr/bin/env python

# Tests in safebrowsing_tests.py

import cmemcache
from safebrowsing import *


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
        for i in list:
            if i["type"] == MALWARE:
                if i["add"]:
                    self.cache.set(i["hash"], "".join(["m", str(m_version)]), TIMEOUT)
                if i["remove"]:
                    self.cache.delete(i["hash"])
            if i["type"] == PHISHING:
                if i["add"]:
                    self.cache.set(i["hash"], "".join(["p", str(p_version)]), TIMEOUT)
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


class BlacklistCacheError(Exception):
    pass


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
