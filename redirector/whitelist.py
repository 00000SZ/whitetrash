#!/usr/bin/env python -u
# The -u ensures we have unbuffered output

# Author: gregsfdev@users.sourceforge.net
#         cford@users.sourceforge.net
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

import logging

from urlparse import urlparse

import MySQLdb
import MySQLdb.cursors

log = logging.getLogger(__name__)

class Whitelist:
    """
    A Whitelist for the Whitetrash proxy server, persisted to a MySQL database.
    """

    # This behaviour may be specified in whitetrash.conf
    db_user = "whitetrash"
    db_passwd = ""
    # Name of the database
    db_name = "whitetrash"
    # Network port for database connection
    db_port = "3306"
    # Unix socket for database connection
    db_socket = "/var/run/mysqld/mysqld.sock"
    # Indicates if whitetrash is in learning mode and should
    # automatically add any requested domain
    auto_add_all = False

    def __init(self): 
        self.cursor = self.db_connect()

    def db_connect(self):
        """
        Connect to the database and return a databse cursor
        """
        dbh = MySQLdb.Connect(user=self.db_user,
                              passwd=self.db_passwd,
                              db=self.db_name,
                              unix_socket=self.db_socket,
                              use_unicode=False)
        return dbh.cursor()

    def _parse_domain(self, url):
        return urlparse(url).netloc.lower()

    def _parse_protocol(self, url):
        return urlparse(url).scheme.lower()

    def is_whitelisted(self, url, client_ip, http_method):
        """
        Indicates whether an item is enabled/whitelisted in the whitetrash database.
        Returns true or false
        """
        domain = self._parse_domain(request.url)
        protocol = self._parse_protocol(request.url)
        

    #########################################################
    #########################################################
    ###### Everything below is used in the Django code ######
    #########################################################
    #########################################################

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
            self.cursor.execute("select whitelist_id, enabled \
                                 from whitelist_whitelist \
                                 where domain=%s and protocol=%s", (domain_wild,proto))
        else:
            res = self.cursor.execute("select whitelist_id, enabled \
                                       from whitelist_whitelist \
                                       where protocol=%s and ((domain=%s) or (domain=%s))", (proto,domain,domain_wild))
            if res > 1:
                #If there is more than one result from the or, take the non-wildcarded one.
                self.cursor.execute("select whitelist_id, enabled \
                                     from whitelist_whitelist \
                                     where protocol=%s and domain=%s", (proto,domain))

        return self.cursor.fetchone()

    def get_proto_domain(self, whitelist_id):
        self.cursor.execute("select protocol, domain \
                             from whitelist_whitelist \
                             where whitelist_id=%s", (whitelist_id))
        return self.cursor.fetchone()
    
    def add_to_whitelist(self, domain, protocol, username, url, clientaddr):
        self.cursor.execute("insert into whitelist_whitelist \
                             set domain=%s, \
                             date_added=NOW(), \
                             username=%s, \
                             protocol=%s, \
                             url=%s, \
                             comment='Auto add, learning mode', \
                             enabled=1, \
                             hitcount=1, \
                             last_accessed=NOW(), \
                             client_ip=%s", 
                             (domain,
                             username,
                             protocol,
                             self._convert_http(url),
                             clientaddr))

    def _convert_http(self, url):
        return re.sub(r"^(https?)%3A",r"\1:",url)

    def add_disabled_domain(self, domain, protocol, username, url, clientaddr):
        """Add a domain to the table with enabled = 0.
        
        This allows us to keep track of domains that have been requested but not added 
        since they are proabably spyware/trackers/malware."""
        self.cursor.execute("insert into whitelist_whitelist \
                             set domain=%s, \
                             date_added=NOW(), \
                             username=%s, \
                             protocol=%s, \
                             url=%s, \
                             comment='', \
                             enabled=0, \
                             hitcount=1, \
                             last_accessed=NOW(), \
                             client_ip=%s", 
                             (domain,
                             username,
                             protocol,
                             self._convert_http(url),
                             clientaddr))

    def enable_domain(self, whitelist_id):
        """Update db entry to set enabled=1."""

        ret=self.cursor.execute("update whitelist_whitelist \
                                 set username='auto', \
                                 date_added=NOW(), \
                                 last_accessed=NOW(), \
                                 comment='Auto add, learning mode', \
                                 enabled=1, \
                                 hitcount=hitcount+1 \
                                 where whitelist_id=%s", whitelist_id)
        if ret!=1:
            raise ValueError("Error enabling domain, it must be present in the table")

    def update_hitcount(self,whitelist_id):
        self.cursor.execute("update whitelist_whitelist \
                             set last_accessed=NOW(), hitcount=hitcount+1 \
                             where whitelist_id=%s", whitelist_id)

    def add_domain(self, domain, protocol, url, clientaddr):
        """
        Adds a new domain to the list.  This domain is disabled by default.
        If whitetrash is in learning mode the domain will be enabled (whitelisted)
        """
        # Learning mode
        if self.auto_add_all:
            self.add_to_whitelist(domain, protocol, 'auto', url, clientaddr)

        # Normal mode
        else:
            self.add_disabled_domain(domain, protocol, 'notwhitelisted', url, clientaddr)
            return seilf.fail_url

    def update_domain(self):
        """
        Update a domain that is already in the list.

        This just updates the hitcount by default however if whitetrash is in
        learning mode the domain will be enabled (whitelisted)
        """

        # Learning mode
        if self.auto_add_all:
            self.enable_domain(whitelist_id)

        # Normal mode
        else:
            self.update_hitcount(whitelist_id)
            return self.fail_url

    def check_whitelist_db(self, domain, protocol, method, url, orig_url, clientaddr):
        """Check the db for domain with protocol.

        @param domain:      Domain to be checked
        @param protocol:    Protocol to pair with the domain, HTTP|SSL enum
        @param url:         Sanitised url 
        @param orig_url:    The original un-sanitised url
        @return:            Url to redirect squid to

        If domain is present (ie. in whitelist), write \n as url redirector output (no change)
        If domain is not present, write self.fail_url as redirector output
        """

        redirect = WhitetrashRedirect(orig_url)

        try:

            # drop the first component from the URL
            if "." in domain:
                (_, domain_wild) = redirect.requested_domain.split(".", 1)

            # if the domain starts with www[0-9]
            if self.www.match(redirect.requested_domain):
                # whitelist all subdomains
                white_id = self.get_whitelist_id(redirect.requested_protocol, 
                                                 redirect.requested_domain, 
                                                 domain_wild, wild=True)
                domain = domain_wild
            else:
                # whitelist only that specific domain
                white_id = self.get_whitelist_id(redirect.requested_protocol, 
                                                 redirect.requested_domain,
                                                 domain_wild, wild=False)

            if white_id:
                (whitelist_id, enabled) = white_id
            else:
                whitelist_id = False

            if whitelist_id and enabled:
                # The domain is already whitelisted
                self.update_hitcount(whitelist_id)
            elif whitelist_id:
                redirect = self.update_domain(domain, protocol, url, clientaddr)
            else:
                redirect = self.add_domain(domain, protocol, url, clientaddr)

            if not redirect:
                # The only conditions under which we should continue onto the requested url.
                assert self.auto_add_all or (whitelist_id and enabled), "Whitelist bypassed"

            return redirect

        except Exception,e:
            self.log.error("Error checking whitelist with %s,%s,%s,%s.  Error:%s" % (domain,protocol,method,url,e)) 
            raise

    def parseSquidInput(self, squidurl):
        """Parse squid input line. Return true if parsing is successful.

        Store result in self.fail_url.  On error, return false and self.error_url.

        Spec is as follows:
        URL <SP> client_ip "/" fqdn <SP> user <SP> method <SP> urlgroup [<SP> kvpairs] <NL>

        Example HTTP:
        http://www.slkdfjlksjd.com/ 127.0.1.2/sslwhitetrash - GET - myip=127.0.1.2 myport=3128

        Example SSL:
        sdfsdfsdf.com:443 127.0.1.2/sslwhitetrash - CONNECT - myip=127.0.1.2 myport=3128
        """

        try:
            spliturl = squidurl.strip().split(" ")
            self.original_url = spliturl[0]
            redirect = WhitetrashRedirector(spliturl[0])
            self.method = spliturl[3]

            if self.method is "CONNECT":
                self.log.debug("Protocol=SSL")
                self.protocol = self.PROTOCOL_CHOICES["SSL"]
                domain = self.domain_sanitise.match(spliturl[0].split(":")[0]).group()

                #Get just the client IP
                self.clientaddr = spliturl[1].split("/")[0]
                #use inet_aton to validate the IP
                inet_aton(self.clientaddr)

                self.url_domain_only = domain
                self.newurl_safe = "https://%s" % domain
                self.fail_url = "%s.%s" % (domain, self.ssl_fail_url)
                return True

            else:
                if not self.method.isalpha():
                    raise ValueError("Bad HTTP request method is not alphabetic")

                self.log.debug("Protocol=HTTP")
                self.protocol = self.PROTOCOL_CHOICES["HTTP"]
                self.fail_url = self.http_fail_url

                #The full url as passed by squid
                #urlencode it to make it safe to hand around in forms
                self.newurl_safe = urllib.quote(self.original_url)
                self.log.debug("sanitised_url: %s" % self.newurl_safe)

                #Get just the client IP
                self.clientaddr = spliturl[1].split("/")[0]
                #use inet_aton to validate the IP
                inet_aton(self.clientaddr)
                self.log.debug("client address: %s" % self.clientaddr)

                #strip out the domain.
                if spliturl[0].lower().startswith("http://"):
                    url_domain_only_unsafe = self.domain_regex.match(spliturl[0].lower().replace("http://","",1)).group()
                    self.log.debug("unsafe: %s" % url_domain_only_unsafe)
                else:
                    raise ValueError("Bad domain doesn't start with http")
        
                #sanitise it
                self.url_domain_only=self.domain_sanitise.match(url_domain_only_unsafe).group()
                self.log.debug("domainonly: %s" % self.url_domain_only)
                self.fail_url+="url=%s&domain=%s" % (self.newurl_safe, self.url_domain_only)
                return True

        except Exception,e:
            self.log.error("Error parsing string '%s' from squid.  Error:%s" % (squidurl, e)) 
            self.fail_url = self.get_error_url("Bad request logged.  See your sysadmin for assistance.")
            return False

    def get_redirect_url(self, url):
        """
        Handles the corner cases of a HTTP request and makes sure the response
        will be suitably handled by the user's browser.
        """

        if not url:
            return None

        # It only makes sense to return the form if the browser is expecting html.
        # This is something other than html so just give some really small dummy content.
        if self.protocol is self.PROTOCOL_CHOICES["HTTP"] and self.nonhtml_suffix_re.match(self.original_url):
            return self.dummy_content_url + "\n"

        # If this isn't a GET ie. usually a POST
        # POSTing or anything else to the whitetrash server doesn't make sense.
        # Send a "302 moved temporarily" back to the client so they request the web form.
        if self.method is not "GET" and self.protocol is self.PROTOCOL_CHOICES["HTTP"]:
            self.fail_url = "302:%s" % url
            print "returning: ", self.fail_url + "\n"
            return self.fail_url + "\n"

        return url

 
    def _do_check(self):
        redirect = self.check_whitelist_db(self.url_domain_only,
                                self.protocol, self.method, self.newurl_safe,
                                self.original_url, self.clientaddr)

        redirect = WhitetrashRedirect(self.orginal_url)
        if is_site_whitelisted(redirect):
            return self.CONTINUE
        else:
            return redirect.add_site_url()
            
            

        redirect = self.get_redirect_url(redirect)

        self.log.debug("Dom: %s, proto:%s, Result: %s, Output url: %s" % 
                (self.url_domain_only, self.protocol, not bool(redirect), redirect))

        if redirect:
            sys.stdout.write(redirect)
        else:
            sys.stdout.write(self.CONTINUE)

    def parse_squid_input(self, input):
        """
        Takes a raw line from Squid's redirector interface and returns
        the requested url, client's ip address and http method used as tuple
        """
        input_array = input.strip().split(" ")
        url = input_array[0]
        client_ip = input_array[1]
        http_method = input_array[3]

        return Request._make(url, client_ip, http_method)

    def validate_squid_input(self, request):
        try:
            socket.inet_aton(request.client_ip)
        except socket.error:
            self.log.error("Invalid client IP Address %s" % request.client_ip)
            return False

        allowed_methods = ["GET", "POST", "CONNECT"]
        if http_method.upper() not in allowed_methods
            self.log.error("Invalid HTTP method %s" % request.http_method)
            return False

        return True

    def send_url_to_squid(self, url):
        self.log.debug("String to squid: %s" % url)
        sys.stdout.write(url)


    def is_requested_whitelisted(self, request):
        try:
            pass
            # check the database
        except Exception as e:
            # perhaps try again or return false
            return False

        return True

    def handle_request(self, request):
        if self.is_request_whitelisted(request):
            self.send_url_to_squid(WhitetrashRedirector.no_redirect)
        else:
            self.redirect(request)

    def readForever(self):
        """
        Read squid URL from stdin, and write response to stdout.
        """
        while True:
            # get input
            squid_input = sys.stdin.readline()
            self.log.debug("String received from squid: %s" % squid_input)

            # parse and validate input
            request = self.parse_squid_input(input)
            if not is_squid_input_valid(request):

            

            try:
                self._do_check()                    
            except Exception,e:
                #Our database handle has probably timed out.
                try:
                    self.cursor = self.db_connect()
                    self._do_check()                    
                except Exception,e:
                    #Something weird/bad has happened, tell the user.
                    self.log.error("Error when checking domain in whitelist. Exception: %s" % e)
                    sys.stdout.write(self.get_error_url("Error checking domain"))




class WTSquidRedirectorCached(WTSquidRedirector):
    """Squid redirector with memcache support."""

    def __init__(self, config):
        WTSquidRedirector.__init__(self,config)
        self.servers = config["memcache_servers"].split(",")
        self.cache = cmemcache.Client(self.servers)
        self.blacklistcache = blacklistcache.BlacklistCache(config)

    def enable_domain(self, whitelist_id):
        """Update db and memcache entry to set enabled=1."""
        
        WTSquidRedirector.enable_domain(self, whitelist_id)
        (proto, domain) = WTSquidRedirector.get_proto_domain(self, whitelist_id)

        key = "|".join((domain, str(proto)))
        self.cache.set(key, (whitelist_id, True))


    def get_whitelist_id(self, proto, domain, domain_wild, wild):
        """Get whitelist id from memcache cache or, failing that, the database
        
        The behaviour is to get either cache_value or cache_value_wild when wild is false
        and only cach_value_wild when wild is true...probably need to rename some variables.

        """

        key = "|".join((domain, str(proto)))
        cache_value = self.cache.get(key)

        key_wild = "|".join((domain_wild, str(proto)))
        cache_value_wild = self.cache.get(key_wild)

        if cache_value and not wild:
            self.log.debug("Using cache value %s: %s" % (key,cache_value))
            return cache_value
        elif cache_value_wild:
            return cache_value_wild
        else:
            result = WTSquidRedirector.get_whitelist_id(self, proto, domain, domain_wild, wild)
            if result:
                self.log.debug("Got result from db %s: %s" % (key, str(result[0])))
                if wild:
                    self.cache.set(key_wild, result)
                else:
                    self.cache.set(key, result)
            return result

    @if_enabled("safebrowsing")
    def check_safebrowsing_blacklist(self, url):
        # check safebrowsing here so whitelist is applied first - allow admins to bypass 
        # safebrowsing blacklist
        sbresult = self.blacklistcache.check_url(orig_url)
        if sbresult:
            self.log.critical("****SAFEBROWSING BLACKLIST HIT**** on %s blacklist from %s for url: %s using protocol:%s" 
                                    % (sbresult, clientaddr, orig_url, protocol))
            self.fail_url = self.get_sb_fail_url(sbresult, domain)
            return self.fail_url + "\n"

    def _do_check(self):
        redirect = self.check_whitelist_db(self.url_domain_only,
                                self.protocol, self.method, self.newurl_safe,
                                self.original_url, self.clientaddr)

        sbredirect = self.check_safebrowsing_blacklist(url)
        redirect = self.get_redirect_url(sbredirect)

        self.log.debug("Dom: %s, proto:%s, Result: %s, Output url: %s" % 
                (self.url_domain_only, self.protocol, not bool(url), redirect))

        if redirect:
            sys.stdout.write(redirect)
        else:
            sys.stdout.write(self.CONTINUE)


class WhitetrashRedirectMap(object):
    """
    Encapsulates all information regarding a URL Request e.g. protocol,
    request type, forwarding url etc.
    """

    # This behaviour may be specified in whitetrash.conf
    domain_regex = re.compile("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$")
    redirect_to_ssl = False
    ssl_port = 443
    hostname = "whitetrash"

    def __init__(self, url):#, method, originator):
        """
        Creates a mapping of a URL to all it's possible
        redirections e.g. redirection to add the url to the whitelist
        """
        self._url = urlparse(url)
        #self.method = method.upper()
        #self.originator = originator
        self.validate()
        
        self.hostname = self.__class__.hostname
        self.ssl_port = self.__class__.ssl_port

    def validate(self):
        """
        Validates all parts of the redirection.  Raises AssertionErrors for
        bad protocols/schemes, bad domain names, bad HTTP methods and bad IP
        addresses.
        """
        assert self.requested_protocol in ["http", "https"], "Invalid protocol: %s" % self.requested_protocol
        assert self.domain_regex.match(self.requested_domain), "Invalid domain: %s" % self.requested_domain
        #assert self.method in ["GET", "POST", "CONNECT"], "Invalid method: %s" % self.method
        #assert len(self.originator.split(".")) is 4, "Invalid IP Address: %s" % self.originator
        #try:
        #    socket.inet_aton(self.originator)
        #except socket.error:
        #    raise AssertionError("Invalid IP Address :%s" % self.originator)

    @property
    def requested_domain(self):
        """
        The domain component of a url.
        """
        return self._url.netloc

    @property
    def requested_protocol(self):
        """
        The protocol being used.
        This will either "http" or "https".
        """
        return self._url.scheme.lower()

    @property
    def requested_url(self):
        """
        The requested url in full.
        """
        return self._url.geturl()

    def _formatdict(self):
        # Because format and properties don't play nice
        # More info: http://mail.python.org/pipermail/python-list/2003-February/190248.html
        if self.redirect_to_ssl:
            protocol = "https"
        else:
            protocol = "http"
        return {"protocol": protocol,
                "hostname": self.hostname,
                "domain": self.requested_domain,
                "url": self.requested_url,
                "ssl_port": self.ssl_port}

    def add_site_url(self):
        """
        The redirect to use when a domain does not appear on the whitelist
        """
        if self.redirect_to_ssl:
            return self._frame_response("{protocol}://{domain}.ssl{hostname}:{ssl_port}/addentry?".format(**self._formatdict()))
        else:
            return self._frame_response("{protocol}://{hostname}/addentry?url={url}&domain={domain}".format(**self._formatdict()))

    def blocked_phishing_url(self):
        """
        The redirect to use when urls appear on Google's phishing site blacklist
        """
        return self._frame_response("{protocol}://{hostname}/whitelist/forgerydomain={url}".format(**self._formatdict()))

    def blocked_malicious_url(self):
        """
        The redirect to use when urls appear on Google's malicious site blacklist
        """
        return self._frame_response("{protocol}://{hostname}/whitelist/attackdomain={url}".format(**self._formatdict()))

    def empty_content_url(self):
        """
        The redirect to use when the browser is not expecting html back
        """
        return self._frame_response("{protocol}://blocked{hostname}/empty".format(**self._formatdict()))

    def _frame_response(self, url):
        # Cleans up a url so it will be treated nicely by Squid and
        # the user's browser

        # Add a newline for Squid
        url = ''.join([url, "\n"])

        # Add a status code when using ssl to keep the browser happy
        if self.redirect_to_ssl:
            return ''.join(["302:", url])
        else:
            return url

def run():


if __name__ == "__main__":
    config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
    if config["use_memcached"].upper() is "TRUE":
        redir = WTSquidRedirectorCached(config)
    else:
        redir = WTSquidRedirector(config)
    redir.readForever()

