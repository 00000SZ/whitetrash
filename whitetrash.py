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

import sys,os
import syslog
import urllib
import re
import MySQLdb
import MySQLdb.cursors
import whitetrash_db.DB as DB

#I use os.write(1,"string") to write to standard out to avoid the python buffering on print statements.

http_fail_url="http://whitelistproxy/whitetrash_genform.py?"
ssl_fail_url="whitelistproxy:443/whitetrash_genform.py?"
www=re.compile("^www[0-9]?\.")
syslog.openlog('whitetrash.py',0,syslog.LOG_USER)

def db_connect():

    dbh = MySQLdb.Connect(user = DB.DBUSER,
                                passwd = DB.DBPASSWD,
                                db = DB.DATABASE,
                                unix_socket = DB.DBUNIXSOCKET, 
                                use_unicode = False
                                )

    return dbh.cursor()

def check_whitelist_db(url_domain_only,protocol):

    url_domain_only_wild=re.sub("^[a-z0-9-]+\.","",url_domain_only,1)
    if www.match(url_domain_only):
        #Do this query whereever possible, more efficient than with the or.
        #This is a www or www2 query
        cursor.execute("select whitelist_id from whitelist where domain=%s and protocol=%s", (url_domain_only_wild,protocol))
    else:
        #If we are checking images.slashdot.org and www.slashdot.org is listed, we let it through.  If we don't do this pretty much every big site is trashed because images are served from a subdomain.  Believe it is more efficient to do an OR than two separate queries.  Only want this behaviour for www - we don't want to throw away the start of every domain because users won't expect this.
        #syslog.syslog("logger wild:"+url_domain_only_wild)
        cursor.execute("select whitelist_id from whitelist where (domain=%s and protocol=%s) or (domain=%s and protocol=%s)", (url_domain_only,protocol,url_domain_only_wild,protocol))

    if cursor.fetchone():
        os.write(1,"\n")
        #syslog.syslog("domain in whitelist: %s" % url_domain_only)
    else:
        os.write(1,fail_url+"\n")
        #syslog.syslog("domain not in whitelist: %s.  Writing fail url:%s" % (url_domain_only,fail_url))


cursor=db_connect()

#Strip out everything except the domain
#Valid domain suffixes are 2-6 chars
domain_regex=re.compile("([a-z0-9-]+\.)+[a-z]{2,6}")
#Valid domains are from iana.org
#Too many country designators, so we will accept any two letters

domain_sanitise=re.compile("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$")

while 1:

    try:
 
        #The squidurl is of the form: 
        #http://www.microsoft.com/ 10.10.9.60/- greg GET
        #Or for SSL
        #www.microsoft.com:443 10.10.9.60/- greg CONNECT
        squidurl=sys.stdin.readline()
        #syslog.syslog("String received from squid: %s" % squidurl)

        spliturl=squidurl.strip().split(" ")
        if spliturl[3]=="GET":
            #syslog.syslog("Protocol=HTTP")
            protocol="HTTP"
            newurl=spliturl[0]
            fail_url=http_fail_url
        elif spliturl[3]=="CONNECT":
            #syslog.syslog("Protocol=SSL")
            protocol="SSL"
            newurl="http://"+spliturl[0].split(":")[0]
            fail_url=ssl_fail_url
        else:
            syslog.syslog("Only understand CONNECT and GET statements, got:%s" % squidurl)
            raise TypeError("Only understand CONNECT and GET statements, got:%s" % spliturl[3])

        #The full url as passed by squid
        #urlencode it to make it safe to hand around in forms
        newurl_safe=urllib.quote(spliturl[0])

        #Get just the client IP
        clientaddr=spliturl[1].split("/")[0]
        #syslog.syslog("client address: %s" % clientaddr)

        #Get the client username
        clientident=spliturl[2]
        #syslog.syslog("client username:%s " % clientident)

        fail_url+="url=%s&clientaddr=%s&clientident=%s&" % (newurl_safe,clientaddr,clientident)
        #strip out the domain.
        url_domain_only_unsafe=domain_regex.match(newurl.lower().replace("http://","",1)).group()[:70]
        #sanitise it
        url_domain_only=domain_sanitise.match(url_domain_only_unsafe).group()
        fail_url+="domain=%s" % url_domain_only
        #syslog.syslog("domainonly: %s" % url_domain_only)
    except Exception,e:
        #syslog.syslog("Exception:%s" % e)
        os.write(1,fail_url+"domain=invalid_try_again\n")
        continue

    try:

        check_whitelist_db(url_domain_only,protocol)

    except Exception,e:
        #Our database handle has probably timed out.
        try:
            cursor=db_connect()
            check_whitelist_db(url_domain_only)
        except:
            #Something weird/bad has happened, tell the user.
            syslog.syslog("Error when checking domain in whitelist. Exception: %s" %e)
            os.write(1,"http://database_error"+"\n")




