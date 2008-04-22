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
from whitetrash_db.configobj import ConfigObj
try:
    import cmemcache
except ImportError:
    pass

class WTSquidRedirector:
    """Whitetrash squid redirector.
    
    I use os.write(1,"string") to write to standard out to avoid the python buffering on print statements."""

    def __init__(self,config):
        self.http_fail_url="http://%s/addentry?" % config["whitetrash_add_domain"]
        self.ssl_fail_url="%s:8000" % config["whitetrash_add_domain"]
        self.fail_string=config["domain_fail_string"]
        self.www=re.compile("^www[0-9]?\.")
        syslog.openlog('whitetrash.py',0,syslog.LOG_USER)
#Strip out everything except the domain
        self.domain_regex=re.compile("([a-z0-9-]+\.)+[a-z]+")
        self.domain_sanitise=re.compile(config["domain_regex"])
        self.auto_add_all=config["auto_add_all_domains"].upper()=="TRUE"

        self.cursor=self.db_connect()

    def db_connect(self):

        dbh = MySQLdb.Connect(user = DB.DBUSER,
                                    passwd = DB.DBPASSWD,
                                    db = DB.DATABASE,
                                    unix_socket = DB.DBUNIXSOCKET, 
                                    use_unicode = False
                                    )

        return dbh.cursor()

    def get_whitelist_id(self):
        """Get whitelist_id for non www domain.

        If we are checking images.slashdot.org and www.slashdot.org is listed, we let it through.  
        If we don't do this pretty much every big site is trashed because images are served from a subdomain.
        Believe it is more efficient to do an OR than two separate queries.  
        Only want this behaviour for www - we don't want to throw away the start of every domain 
        because users won't expect this."""

        self.cursor.execute("select whitelist_id from whitelist where (domain=%s and protocol=%s) or (domain=%s and protocol=%s)", (self.url_domain_only,self.protocol,self.url_domain_only_wild,self.protocol))
        return self.cursor.fetchone()

    def get_whitelist_id_wild(self):
        """Get whitelist ID for the wildcarded domain (i.e. www or www2).

        Do this query whereever possible, more efficient than with the or."""

        self.cursor.execute("select whitelist_id from whitelist where domain=%s and protocol=%s", (self.url_domain_only_wild,self.protocol))
        return self.cursor.fetchone()
            
    def add_to_whitelist(self):
        self.cursor.execute("insert into whitelist set domain=%s,timestamp=NOW(),username=%s,protocol=%s,originalrequest=%s,comment='Automatically added by whitetrash'", (self.insert_domain,self.clientident,self.protocol,self.newurl_safe))

    def update_hitcount(self,whitelist_id):
        self.cursor.execute("insert into hitcount set whitelist_id=%s, hitcount=1, timestamp=NOW() on duplicate key update hitcount=hitcount+1, timestamp=NOW()", whitelist_id)

    def check_whitelist_db(self):
        """Check the db for domain self.url_domain_only with protocol self.protocol
        
        If domain is present (ie. in whitelist), write \n as redirector output (no change)
        If domain is not present, write self.fail_url as redirector output
        """

        self.url_domain_only_wild=re.sub("^[a-z0-9-]+\.","",self.url_domain_only,1)
        if self.www.match(self.url_domain_only):
            self.insert_domain=self.url_domain_only_wild
            whitelist_id=self.get_whitelist_id_wild()
        else:
            self.insert_domain=self.url_domain_only
            whitelist_id=self.get_whitelist_id()
      
        if whitelist_id:

            result=True
            os.write(1,"\n")
            try:
                self.update_hitcount(whitelist_id)
            except Exception,e:
                syslog.syslog("Error updating hitcount for whitelistid %s: %s" % (whitelist_id,e))
        else:

            if self.auto_add_all:
                self.add_to_whitelist()
                result=True
                os.write(1,"\n")
            else:
                result=False
                os.write(1,self.fail_url+"\n")

        return result

    def parseSquidInput(self,squidurl):
        """Parse squid input line. Return true if parsing is successful.

        Store result in self.fail_url.  On error, write redirector output and return false.

        The squidurl is of the form: 
        http://www.microsoft.com/ 10.10.9.60/- greg GET
        Or for SSL
        www.microsoft.com:443 10.10.9.60/- greg CONNECT
        """

        try:
            spliturl=squidurl.strip().split(" ")
            if spliturl[3]=="CONNECT":
                #syslog.syslog("Protocol=SSL")
                self.protocol="SSL"
                self.url_domain_only=self.domain_sanitise.match(spliturl[0].split(":")[0]).group()
                self.fail_url=self.ssl_fail_url
                return True

            else:
                #syslog.syslog("Protocol=HTTP")
                self.protocol="HTTP"
                self.fail_url=self.http_fail_url

                #The full url as passed by squid
                #urlencode it to make it safe to hand around in forms
                self.newurl_safe=urllib.quote(spliturl[0])
                #syslog.syslog("sanitised_url: %s" % self.newurl_safe)

                #Get just the client IP
                clientaddr=spliturl[1].split("/")[0]
                #syslog.syslog("client address: %s" % clientaddr)

                #Get the client username
                self.clientident=spliturl[2]
                #syslog.syslog("client username:%s " % self.clientident)

                self.fail_url+="url=%s&clientaddr=%s&clientident=%s&" % (self.newurl_safe,clientaddr,self.clientident)
                #strip out the domain.
                url_domain_only_unsafe=self.domain_regex.match(spliturl[0].lower().replace("http://","",1)).group()
                #syslog.syslog("unsafe: %s" % url_domain_only_unsafe)
        
                #sanitise it
                self.url_domain_only=self.domain_sanitise.match(url_domain_only_unsafe).group()
                #syslog.syslog("domainonly: %s" % self.url_domain_only)
                self.fail_url+="domain=%s" % self.url_domain_only
                return True

        except AttributeError:
            #Probably a bad domain
            if self.protocol=="SSL":
                self.fail_url+="\n"
            else:
                self.fail_url="%sdomain=%s\n" % (self.http_fail_url,self.fail_string)
            os.write(1,self.fail_url)
            return False
        except Exception,e:
            syslog.syslog("Unexpected whitetrash redirector exception:%s. Using fail url:%s" % (e,self.fail_url))
            os.write(1,self.fail_url+"\n")
            return False

    def readForever(self):
        """Read squid URL from stdin, and write response to stdout."""

        while 1:

            squidurl=sys.stdin.readline()
            #syslog.syslog("String received from squid: %s" % squidurl)
            if self.parseSquidInput(squidurl):

                try:
                    self.check_whitelist_db()
                except Exception,e:
                    #Our database handle has probably timed out.
                    try:
                        self.cursor=db_connect()
                        self.check_whitelist_db()
                    except:
                        #Something weird/bad has happened, tell the user.
                        syslog.syslog("Error when checking domain in whitelist. Exception: %s" %e)
                        os.write(1,"http://database_error"+"\n")


class WTSquidRedirectorCached(WTSquidRedirector):
    """Squid redirector with memcache support.
    
    Currently only caching the whitelist table.  Not as much value in caching the hitcount table, since I
    still need to update the database each time to keep it consistent.
    """

    def __init__(self,config):
        WTSquidRedirector.__init__(self,config)
        self.servers=config["memcache_servers"].split(",")
        self.cache=cmemcache.StringClient(self.servers)

    def find_id(self,domain,dbmethod):
        """Get whitelist id from memcache cache or, failing that, the database"""

        key="|".join((domain,self.protocol))
        cache_value=self.cache.get(key)
        if cache_value:
            #syslog.syslog("Using cache value %s: %s" % (key,cache_value))
            return cache_value
        else:
            result=dbmethod(self)
            if result:
                #syslog.syslog("Got result from db %s: %s" % (key,str(result[0])))
                self.cache.set(key,str(result[0]))
            return result

    def get_whitelist_id(self):
        return self.find_id(self.url_domain_only,WTSquidRedirector.get_whitelist_id)

    def get_whitelist_id_wild(self):
        return self.find_id(self.url_domain_only_wild,WTSquidRedirector.get_whitelist_id_wild)

    def add_to_whitelist(self):
        self.cursor.execute("insert into whitelist set domain=%s,timestamp=NOW(),username=%s,protocol=%s,originalrequest=%s,comment='Automatically added by whitetrash'", (self.insert_domain,self.clientident,self.protocol,self.newurl_safe))

if __name__ == "__main__":
    config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
    if config["use_memcached"].upper()=="TRUE":
        redir=WTSquidRedirectorCached(config)
    else:
        redir=WTSquidRedirector(config)
    redir.readForever()

