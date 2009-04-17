#! /usr/bin/env

import syslog

import MySQLdb
from configobj import ConfigObj

syslog.openlog('whitetrash.py',0,syslog.LOG_USER)
syslog.syslog("Running whitetrash_cleanup")

try:

    config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
    dbh = MySQLdb.Connect(user = config['DATABASE_CLEANUP_USER'],
                                passwd = config['DATABASE_CLEANUP_PASSWORD'],
                                db = config['DATABASE_NAME'],
                                unix_socket = config['DATABASE_UNIX_SOCKET'],
                                use_unicode = False
                                )
    cursor=dbh.cursor()
    result=cursor.execute("delete whitelist, hitcount from whitelist left join hitcount on whitelist.whitelist_id=hitcount.whitelist_id where ((DATEDIFF(NOW(),hitcount.timestamp) > %s) or (hitcount.whitelist_id is NULL))",config["timeout_in_days"])

    syslog.syslog("whitetrash_cleanup.py successful. Deleted %s row(s)" % result)

except Exception,e:
    syslog.syslog("whitetrash_cleanup.py error:%s" % e)

