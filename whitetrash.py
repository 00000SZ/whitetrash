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
import logging
import logging.config
import urllib
import re
import MySQLdb
import MySQLdb.cursors
from configobj import ConfigObj
from socket import inet_aton
try:
    import cmemcache
except ImportError:
    pass

class WTSquidRedirector:
    """Whitetrash squid redirector."""

    def __init__(self,config):
        self.config=config
        logging.config.fileConfig("/etc/whitetrash.conf")
        self.log = logging.getLogger("whitetrashRedir")

        self.PROTOCOL_CHOICES={'HTTP':1,'SSL':2}
        self.http_fail_url="http://%s/whitelist/addentry?" % config["whitetrash_domain"]
        self.error_url="http://%s/whitelist/error" % config["whitetrash_domain"]
        self.dummy_content_url="http://blocked%s/empty" % config["whitetrash_domain"]

        self.whitetrash_admin_path="http://%s" % config["whitetrash_domain"]
        self.nonhtml_suffix_re=re.compile(config["nonhtml_suffix_re"])
        self.ssl_fail_url="sslwhitetrash:80"
        self.fail_string=config["domain_fail_string"]
        self.www=re.compile("^www[0-9]?\.")
        #Strip out everything except the domain
        self.domain_regex=re.compile("([a-z0-9-]+\.)+[a-z]+")
        self.domain_sanitise=re.compile(config["domain_regex"])
        self.auto_add_all=config["auto_add_all_domains"].upper()=="TRUE"
        
        self.cursor=self.db_connect()

    def db_connect(self):
        """Connect to the database and return a DB cursor"""

        dbh = MySQLdb.Connect(user = self.config['DATABASE_WHITETRASH_USER'],
                                    passwd = self.config['DATABASE_WHITETRASH_PASSWORD'],
                                    db = self.config['DATABASE_NAME'],
                                    unix_socket = self.config['DATABASE_UNIX_SOCKET'],
                                    use_unicode = False
                                    )

        return dbh.cursor()
       
    def get_whitelist_id(self,proto,domain,domain_wild,wild=False):
        """Get whitelist_id.

        If wild=false:
            This is a non www domain.
            If we are checking images.slashdot.org and www.slashdot.org is listed, we let it through.  
            If we don't do this pretty much every big site is trashed because images are served from a subdomain.
            Only want this behaviour for www - we don't want to throw away the start of every domain 
            because users won't expect this.

        If wild=true:
            Get whitelist ID for the wildcarded domain (i.e. www or www2).
        """

        if wild:
            self.cursor.execute("select whitelist_id,enabled from whitelist_whitelist where domain=%s and protocol=%s", (domain_wild,proto))
        else:
            self.cursor.execute("select whitelist_id,enabled from whitelist_whitelist where protocol=%s and ((domain=%s) or (domain=%s))", (proto,domain,domain_wild))

        return self.cursor.fetchone()

    def get_proto_domain(self,whitelist_id):
        self.cursor.execute("select protocol,domain from whitelist_whitelist where whitelist_id=%s", (whitelist_id))
        return self.cursor.fetchone()
    
    def add_to_whitelist(self,domain,protocol,username,url,clientaddr):
        self.cursor.execute("insert into whitelist_whitelist set domain=%s,date_added=NOW(),username=%s,protocol=%s,url=%s,comment='Auto add, learning mode',enabled=1,hitcount=1,last_accessed=NOW(),client_ip=%s", (domain,username,protocol,url,clientaddr))

    def add_disabled_domain(self,domain,protocol,username,url,clientaddr):
        """Add a domain to the table with enabled = 0.
        
        This allows us to keep track of domains that have been requested but not added 
        since they are proabably spyware/trackers/malware."""

        self.cursor.execute("insert into whitelist_whitelist set domain=%s,date_added=NOW(),username=%s,protocol=%s,url=%s, comment='', enabled=0,hitcount=1,last_accessed=NOW(), client_ip=%s", (domain,username,protocol,url,clientaddr))

    def enable_domain(self,whitelist_id):
        """Update db entry to set enabled=1."""

        ret=self.cursor.execute("update whitelist_whitelist set username='auto',date_added=NOW(),last_accessed=NOW(),comment='Auto add, learning mode',enabled=1,hitcount=hitcount+1 where whitelist_id=%s", whitelist_id)
        if ret!=1:
        	raise ValueError("Error enabling domain, it must be present in the table")

    def update_hitcount(self,whitelist_id):
        self.cursor.execute("update whitelist_whitelist set last_accessed=NOW(),hitcount=hitcount+1 where whitelist_id=%s", whitelist_id)

    def get_error_url(self,errortext):
        return "%s?error=%s\n" % (self.error_url,urllib.quote(errortext))

    def check_whitelist_db(self,domain,protocol,url,orig_url,clientaddr):
        """Check the db for domain with protocol.

        @param domain:      Domain to be checked
        @param protocol:    Protocol to pair with the domain, HTTP|SSL enum
        @param url:         Sanitised url 
        @param orig_url:    The original un-sanitised url
        @return:            Tuple (True if domain is whitelisted,url to write back to squid)

        If domain is present (ie. in whitelist), write \n as url redirector output (no change)
        If domain is not present, write self.fail_url as redirector output
        """
        try:
            domain_wild=re.sub("^[a-z0-9-]+\.","",domain,1)

            if self.www.match(domain):
                white_id=self.get_whitelist_id(protocol,domain,domain_wild,wild=True)
                domain=domain_wild

            else:
                white_id=self.get_whitelist_id(protocol,domain,domain_wild,wild=False)

            if white_id:
        	    (whitelist_id,enabled)=white_id
            else:
                whitelist_id=False

            if whitelist_id and enabled==1:

                self.update_hitcount(whitelist_id)
                result = (True,"\n")

            else:

                if self.auto_add_all:
            	    if whitelist_id:
            		    self.enable_domain(whitelist_id)
                    else:
                        self.add_to_whitelist(domain,protocol,'auto',url,clientaddr)

                    result = (True,"\n")
                else:
                    
                    if whitelist_id:
                        self.update_hitcount(whitelist_id)
                    else:
                        self.add_disabled_domain(domain,protocol,'notwhitelisted',url,clientaddr)

                    if protocol == self.PROTOCOL_CHOICES["HTTP"] and	\
                        self.nonhtml_suffix_re.match(orig_url):
                        #only makes sense to return the form if the browser is expecting html
                        #This is something other than html so just give some really small dummy content.
                        result = (False,self.dummy_content_url+"\n")
                    else:
                        result = (False,self.fail_url+"\n")

            return result

        except Exception,e:
            self.log.error("Error checking whitelist with %s,%s,%s.  Error:%s" % (domain,protocol,url,e)) 
            return (False,self.get_error_url("Error checking domain in whitelist"))


    def parseSquidInput(self,squidurl):
        """Parse squid input line. Return true if parsing is successful.

        Store result in self.fail_url.  On error, return false and self.error_url.

        Example HTTP:
        http://www.slkdfjlksjd.com/ 127.0.1.2/sslwhitetrash - GET - myip=127.0.1.2 myport=3128

        Example SSL:
        sdfsdfsdf.com:443 127.0.1.2/sslwhitetrash - CONNECT - myip=127.0.1.2 myport=3128
        """

        try:
            spliturl=squidurl.strip().split(" ")
            self.original_url=spliturl[0]

            if spliturl[3]=="CONNECT":
                self.log.debug("Protocol=SSL")
                self.protocol=self.PROTOCOL_CHOICES["SSL"]
                domain = self.domain_sanitise.match(spliturl[0].split(":")[0]).group()

                #Get just the client IP
                self.clientaddr=spliturl[1].split("/")[0]
                #use inet_aton to validate the IP
                inet_aton(self.clientaddr)

                self.url_domain_only = domain
                self.newurl_safe = "https://%s" % domain
                self.fail_url = self.ssl_fail_url
                return True

            else:
                if not spliturl[3].isalpha():
                    raise ValueError("Bad HTTP request method is not alphabetic")

                self.log.debug("Protocol=HTTP")
                self.protocol=self.PROTOCOL_CHOICES["HTTP"]
                self.fail_url=self.http_fail_url

                #The full url as passed by squid
                #urlencode it to make it safe to hand around in forms
                self.newurl_safe=urllib.quote(spliturl[0])
                self.log.debug("sanitised_url: %s" % self.newurl_safe)

                #Get just the client IP
                self.clientaddr=spliturl[1].split("/")[0]
                #use inet_aton to validate the IP
                inet_aton(self.clientaddr)
                self.log.debug("client address: %s" % self.clientaddr)

                #strip out the domain.
                if spliturl[0].lower().startswith("http://"):
                    url_domain_only_unsafe=self.domain_regex.match(spliturl[0].lower().replace("http://","",1)).group()
                    self.log.debug("unsafe: %s" % url_domain_only_unsafe)
                else:
                    raise ValueError("Bad domain doesn't start with http")
        
                #sanitise it
                self.url_domain_only=self.domain_sanitise.match(url_domain_only_unsafe).group()
                self.log.debug("domainonly: %s" % self.url_domain_only)
                self.fail_url+="url=%s&domain=%s" % (self.newurl_safe,self.url_domain_only)
                return True

        except Exception,e:
            self.log.error("Error parsing string '%s' from squid.  Error:%s" % (squidurl,e)) 
            self.fail_url=self.get_error_url("Bad request logged.  See your sysadmin for assistance.")
            return False

    def readForever(self):
        """Read squid URL from stdin, and write response to stdout."""

        while 1:

            squidurl=sys.stdin.readline()
            self.log.debug("String received from squid: %s" % squidurl)
            if self.parseSquidInput(squidurl):

                try:
                    (res,url)=self.check_whitelist_db(self.url_domain_only,self.protocol,self.newurl_safe,
                                            self.original_url,self.clientaddr)
                    self.log.debug("Dom: %s, proto:%s, Result: %s, Output url: %s" % 
                            (self.url_domain_only,self.protocol,res,url))
                    sys.stdout.write(url)

                except Exception,e:
                    #Our database handle has probably timed out.
                    try:
                        self.cursor=db_connect()
                        (res,url)=self.check_whitelist_db(self.url_domain_only,
                                                        self.protocol,self.newurl_safe,
                                                        self.original_url,self.clientaddr)
                        sys.stdout.write(url)

                    except:
                        #Something weird/bad has happened, tell the user.
                        self.log.error("Error when checking domain in whitelist. Exception: %s" %e)
                        sys.stdout.write(self.get_error_url())
            else:
                sys.stdout.write(self.fail_url)


class WTSquidRedirectorCached(WTSquidRedirector):
    """Squid redirector with memcache support."""

    def __init__(self,config):
        WTSquidRedirector.__init__(self,config)
        self.servers=config["memcache_servers"].split(",")
        self.cache=cmemcache.Client(self.servers)

    def enable_domain(self,whitelist_id):
        """Update db and memcache entry to set enabled=1."""
        
        WTSquidRedirector.enable_domain(self,whitelist_id)
        (proto,domain)=WTSquidRedirector.get_proto_domain(self,whitelist_id)

        key="|".join((domain,str(proto)))
        self.cache.set(key,(whitelist_id,True))


    def get_whitelist_id(self,proto,domain,domain_wild,wild):
        """Get whitelist id from memcache cache or, failing that, the database
        
        The behaviour is to get either cache_value or cache_value_wild when wild is false
        and only cach_value_wild when wild is true...probably need to rename some variables.

        """

        key="|".join((domain,str(proto)))
        cache_value=self.cache.get(key)

        key_wild="|".join((domain_wild,str(proto)))
        cache_value_wild=self.cache.get(key_wild)

        if cache_value and not wild:
            self.log.debug("Using cache value %s: %s" % (key,cache_value))
            return cache_value
        elif cache_value_wild:
            return cache_value_wild
        else:
            result=WTSquidRedirector.get_whitelist_id(self,proto,domain,domain_wild,wild)
            if result:
                self.log.debug("Got result from db %s: %s" % (key,str(result[0])))
                if wild:
                    self.cache.set(key_wild,result)
                else:
                    self.cache.set(key,result)
            return result

if __name__ == "__main__":
    config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
    if config["use_memcached"].upper()=="TRUE":
        redir=WTSquidRedirectorCached(config)
    else:
        redir=WTSquidRedirector(config)
    redir.readForever()

