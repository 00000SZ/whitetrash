#!/usr/bin/env python -u
# The -u ensures we have unbuffered output

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
    """Whitetrash squid redirector."""

    def __init__(self,config):
        self.PROTOCOL_CHOICES={'HTTP':1,'SSL':2}
        self.clientident="auto"
        self.http_fail_url="http://%s/whitelist/getform?" % config["whitetrash_add_domain"]
        self.whitetrash_admin_path="http://%s" % config["whitetrash_admin_domain"]
        self.dummy_content_url="%s/empty" % self.whitetrash_admin_path
        self.nonhtml_suffix_re=re.compile(config["nonhtml_suffix_re"])
        self.ssl_fail_url="sslwhitetrash:80"
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
       
    def get_whitelist_id(self,proto,domain,domain_wild):
        """Get whitelist_id for non www domain.

        If we are checking images.slashdot.org and www.slashdot.org is listed, we let it through.  
        If we don't do this pretty much every big site is trashed because images are served from a subdomain.
        Believe it is more efficient to do an OR than two separate queries.  
        Only want this behaviour for www - we don't want to throw away the start of every domain 
        because users won't expect this."""

        self.cursor.execute("select whitelist_id,enabled from whitelist_whitelist where protocol=%s and ((domain=%s) or (domain=%s))", (proto,domain,domain_wild))

        return self.cursor.fetchone()

    def get_whitelist_id_wild(self,proto,domain_wild):
        """Get whitelist ID for the wildcarded domain (i.e. www or www2).
        Do this query whereever possible, more efficient than with the or."""

        self.cursor.execute("select whitelist_id,enabled from whitelist_whitelist where domain=%s and protocol=%s", (domain_wild,proto))

        return self.cursor.fetchone()
            
    def add_to_whitelist(self,domain,protocol,username,url):
        self.cursor.execute("insert into whitelist_whitelist set domain=%s,date_added=NOW(),username=%s,protocol=%s,original_request=%s,comment='Auto add, learning mode',enabled=1,hitcount=1,last_accessed=NOW()", (domain,username,protocol,url))

    def enable_domain(self,whitelist_id):
        self.cursor.execute("update whitelist_whitelist set username=%s,date_added=NOW(),last_accessed=NOW(),comment='Auto add, learning mode',enabled=1,hitcount=hitcount+1 where whitelist_id=%s", whitelist_id)

    def update_hitcount(self,whitelist_id):
        self.cursor.execute("update whitelist_whitelist set last_accessed=NOW(),hitcount=hitcount+1 where whitelist_id=%s", whitelist_id)

    def check_whitelist_db(self):
        """Check the db for domain self.url_domain_only with protocol self.protocol
        
        If domain is present (ie. in whitelist), write \n as redirector output (no change)
        If domain is not present, write self.fail_url as redirector output
        """
        #TODO: move params into arg list to make testing easier. 
        self.url_domain_only_wild=re.sub("^[a-z0-9-]+\.","",self.url_domain_only,1)

        if self.www.match(self.url_domain_only):
            result=self.get_whitelist_id_wild(self.protocol,
                                                            self.url_domain_only_wild)

        else:
            result=self.get_whitelist_id(self.protocol,
                                                self.url_domain_only,
                                                self.url_domain_only_wild)
        if result:
        	(whitelist_id,enabled)=result
        else:
            whitelist_id=False

        if whitelist_id and enabled==1:

            result=True
            sys.stdout.write("\n")
            try:
                self.update_hitcount(whitelist_id)
            except Exception,e:
                syslog.syslog("Error updating hitcount for whitelistid %s: %s" % (whitelist_id,e))
        else:

            if self.auto_add_all:
            	if whitelist_id:
            		self.enable_domain(whitelist_id)
                else:
                    self.add_to_whitelist(self.url_domain_only,self.protocol,'auto',self.newurl_safe)
                result=True
                sys.stdout.write("\n")
            else:
                #TODO: add disabled to whitelist, increment hitcount.
                result=False
                if self.nonhtml_suffix_re.match(self.original_url):
                    #only makes sense to return the form if the browser is expecting html
                    #This is something other than html so just give it some really small dummy content.
                    sys.stdout.write(self.dummy_content_url+"\n")
                else:
                    sys.stdout.write(self.fail_url+"\n")

        return result

    def parseSquidInput(self,squidurl):
        """Parse squid input line. Return true if parsing is successful.

        Store result in self.fail_url.  On error, write redirector output and return false.

        The squidurl is of the form: 
        http://www.microsoft.com/ 10.10.9.60/fqdn greg GET
        Or for SSL
        www.microsoft.com:443 10.10.9.60/fqdn greg CONNECT
        """

#        try:
        spliturl=squidurl.strip().split(" ")
        self.original_url=spliturl[0]
        syslog.syslog(str(squidurl))

        if spliturl[3]=="CONNECT":
            #syslog.syslog("Protocol=SSL")
            self.protocol=self.PROTOCOL_CHOICES["SSL"]
            self.url_domain_only=self.domain_sanitise.match(spliturl[0].split(":")[0]).group()
            self.fail_url=self.ssl_fail_url
            return True

        else:
            #syslog.syslog("Protocol=HTTP")
            self.protocol=self.PROTOCOL_CHOICES["HTTP"]
            self.fail_url=self.http_fail_url

            #The full url as passed by squid
            #urlencode it to make it safe to hand around in forms
            self.newurl_safe=urllib.quote(spliturl[0])
            #syslog.syslog("sanitised_url: %s" % self.newurl_safe)

            #Get just the client IP
            clientaddr=spliturl[1].split("/")[0]
            #syslog.syslog("client address: %s" % clientaddr)

            #strip out the domain.
            url_domain_only_unsafe=self.domain_regex.match(spliturl[0].lower().replace("http://","",1)).group()
            #syslog.syslog("unsafe: %s" % url_domain_only_unsafe)
    
            #sanitise it
            self.url_domain_only=self.domain_sanitise.match(url_domain_only_unsafe).group()
            #syslog.syslog("domainonly: %s" % self.url_domain_only)
            self.fail_url+="url=%s&clientaddr=%s&domain=%s" % (self.newurl_safe,clientaddr,self.url_domain_only)
            return True

#TODO: return errors to squid: http://wiki.squid-cache.org/SquidFaq/SquidRedirectors

#        except AttributeError:
#            #Probably a bad domain
#            if self.protocol==self.PROTOCOL_CHOICES["SSL"]:
#                self.fail_url+="\n"
#            else:
#                self.fail_url="%sdomain=%s\n" % (self.http_fail_url,self.fail_string)
#            sys.stdout.write(self.fail_url)
#            return False
#        except Exception,e:
#            try:
#                syslog.syslog("Unexpected whitetrash redirector exception:%s. Using fail url:%s" % (e,self.fail_url))
#                sys.stdout.write(self.fail_url+"\n")
#            except:
#                syslog.syslog("Unexpected whitetrash redirector exception:%s." % e)
#                sys.stdout.write("http://split_error\n")
                
#            return False

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
                        sys.stdout.write("http://database_error"+"\n")


class WTSquidRedirectorCached(WTSquidRedirector):
    """Squid redirector with memcache support.
    
    Currently only caching the whitelist table.  Not as much value in caching the hitcount table, since I
    still need to update the database each time to keep it consistent.
    """

    def __init__(self,config):
        WTSquidRedirector.__init__(self,config)
        self.servers=config["memcache_servers"].split(",")
        self.cache=cmemcache.StringClient(self.servers)

    def find_id(self,domain,dbmethod,*args):
        """Get whitelist id from memcache cache or, failing that, the database"""

        key="|".join((domain,self.protocol))
        cache_value=self.cache.get(key)
        if cache_value:
            #syslog.syslog("Using cache value %s: %s" % (key,cache_value))
            return cache_value
        else:
            result=dbmethod(self,*args)
            if result:
                #syslog.syslog("Got result from db %s: %s" % (key,str(result[0])))
                self.cache.set(key,str(result[0]))
            return result

    def get_whitelist_id(self):
        return self.find_id(self.url_domain_only,WTSquidRedirector.get_whitelist_id)

    def get_whitelist_id_wild(self):
        return self.find_id(self.url_domain_only_wild,WTSquidRedirector.get_whitelist_id_wild)

if __name__ == "__main__":
    config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
    if config["use_memcached"].upper()=="TRUE":
        redir=WTSquidRedirectorCached(config)
    else:
        redir=WTSquidRedirector(config)
    redir.readForever()

