#! /usr/bin/env

import logging
import logging.config
import MySQLdb
from configobj import ConfigObj

try:

    config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
    logging.config.fileConfig("/etc/whitetrash.conf")
    log = logging.getLogger("whitetrashCleanup")
    log.info("Running whitetrash_cleanup")

    dbh = MySQLdb.Connect(user = config['DATABASE_CLEANUP_USER'],
                                passwd = config['DATABASE_CLEANUP_PASSWORD'],
                                db = config['DATABASE_NAME'],
                                unix_socket = config['DATABASE_UNIX_SOCKET'],
                                use_unicode = False
                                )

    cursor=dbh.cursor()

    if config["use_memcached"].upper() =="TRUE":
        import cmemcache
        servers=config["memcache_servers"].split(",")
        cache=cmemcache.Client(servers)
        result=cursor.execute("select whitelist_id,protocol,domain from whitelist_whitelist where (DATEDIFF(NOW(),last_accessed) > %s)",config["timeout_in_days"])
        for (id,proto,dom) in cursor.fetchall():
            key = "|".join((dom,str(proto)))
            if config["delete_old_domains"].upper() =="TRUE":
                cache.delete(key)
            else:
                cache.set(key,(id,False))

        log.info("Deleted/disabled %s entries in memcache" % result)

    if config["delete_old_domains"].upper() =="TRUE":
        result=cursor.execute("delete from whitelist_whitelist where (DATEDIFF(NOW(),last_accessed) > %s)",config["timeout_in_days"])
        log.info("Whitetrash cleanup successful. Deleted %s domains(s)" % result)
    else:
        result=cursor.execute("update whitelist_whitelist set enabled=0 where (DATEDIFF(NOW(),last_accessed) > %s)",config["timeout_in_days"])
        log.info("Whitetrash cleanup successful. Disabled %s domain(s)" % result)

except Exception,e:
    log.error("whitetrash_cleanup.py error:%s" % e)

