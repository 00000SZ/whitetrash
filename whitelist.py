#!/usr/env/python

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
import urllib
import re
import MySQLdb
import MySQLdb.cursors

#I use os.write(1,"string") to write to standard out to avoid the python buffering on print statements.

new_fail_url="http://whitelistproxy/generate_form.cgi?"
www=re.compile("^www[0-9]?\.")

def db_connect():

    dbh = MySQLdb.Connect(user = "unpriv",
                                      passwd = "passwd",
                                      db = "proxy",
                                      unix_socket = "/var/run/mysqld/mysqld.sock", 
                                      use_unicode = False
                                      )

    return dbh.cursor()

cursor=db_connect()

#Strip out everything except the domain
#Valid domain suffixes are 2-6 chars
domain_regex=re.compile("([a-z0-9-]+\.)+[a-z]{2,6}")
#Valid domains are from iana.org
#Too many country designators, so we will accept any two letters

domain_sanitise=re.compile("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$")

while 1:

    try:
 
        fail_url=new_fail_url
        #The squidurl is of the form: 
        #http://www.microsoft.com/ 10.10.9.60/- greg GET
        #Or for SSL
        #www.microsoft.com:443 10.10.9.60/- greg CONNECT
        squidurl=sys.stdin.readline()
        #os.system("logger squidurl:"+squidurl)

        #The full url as passed by squid
        newurl=squidurl.split(" ")[0]
        #urlencode it to make it safe to hand around in forms
        newurl_safe=urllib.quote(newurl)

        #Get just the client IP
        clientaddr=squidurl.split(" ")[1].split("/")[0]
        #os.system("logger clientadd"+clientaddr)

        #Get the client username
        clientident=squidurl.split(" ")[2]
        #os.system("logger clientident"+clientident)

        fail_url+="url=%s&clientaddr=%s&clientident=%s&" % (newurl_safe,clientaddr,clientident)
        #strip out the domain.
        url_domain_only_unsafe=domain_regex.match(newurl.lower().replace("http://","",1)).group()[:70]
        #sanitise it
        url_domain_only=domain_sanitise.match(url_domain_only_unsafe).group()
        fail_url+="domain=%s" % url_domain_only
        #os.system("logger failurl2"+fail_url)
        #os.system("logger domainonly"+url_domain_only)
    except Exception,e:
        os.write(1,fail_url+"domain=invalid_try_again\n")
        continue

    try:
        url_domain_only_wild=re.sub("^[a-z0-9-]+\.","",url_domain_only,1)
        if www.match(url_domain_only):
            #Do this query whereever possible, more efficient than with the or.
            #This is a www or www2 query
            cursor.execute("select id from whitelist where domain=%s", url_domain_only_wild)
        else:
            #If we are checking images.slashdot.org and www.slashdot.org is listed, we let it through.  If we don't do this pretty much every big site is trashed because images are served from a subdomain.  Believe it is more efficient to do an OR than two separate queries.  Only want this behaviour for www - we don't want to throw away the start of every domain because users won't expect this.
            #os.system("logger wild:"+url_domain_only_wild)
            cursor.execute("select id from whitelist where domain=%s or domain=%s", (url_domain_only,url_domain_only_wild))

        if cursor.fetchone():
            os.write(1,"\n")
            #os.system("logger passed"+url_domain_only)
        else:
            os.write(1,fail_url+"\n")
            #os.system("logger failed"+url_domain_only+fail_url)

    except Exception,e:
        os.system("logger whitelist.py db connection failed attempting to reconnect")
        os.write(1,"http://database_error"+"\n")
        try:
            cursor=db_connect()
        except:
            pass




