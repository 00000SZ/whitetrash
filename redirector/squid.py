#!/usr/bin/env python -u
# The -u ensures we have unbuffered output

# Authors: gregsfdev@users.sourceforge.net
#          cford@users.sourceforge.net
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

import sys
import re
import socket
import logging
import logging.config

from collections import namedtuple
from urlparse import urlparse

from django.core.management import setup_environ
import django_site.whitetrash.settings as settings
setup_environ(settings)

from django_site.whitetrash.whitelist.models import Whitelist

from redirector.common import RedirectMap
from django_site.whitetrash.wtdomains import WTDomainUtils
from django.contrib.auth.models import User
try:
    import blacklistcache
except ImportError:
    if settings.SAFEBROWSING:
        settings.LOG.error("Couldn't import blacklistcache, not using safebrowsing")
        raise


Request = namedtuple("Request", "url, client_ip, http_method")

log = logging.getLogger(__name__)

class RedirectHandler(object):
    """
    A class for performing Redirects in Squid.

    Redirects are performed by:
       - reading in requests from Squid's redirector interface (through stdin)
       - evaluating the request against a whitelist or blacklist for example
       - sending either the requested url or a new url to squid and in this way
         redirecting the request
    """
    # RedirectHandler is a ContextManager (http://docs.python.org/library/stdtypes.html#typecontextmanager)
    # in order to simply the various stages of processing a redirect
    # Some general benefits/rules for using RedirectHandler:
    # - Debug level log can go anywhere in the class
    # - Error level log should only happen in the __exit__ function (see next point)
    # - Any error should raise a RedirectError which will be handled in __exit__

    # This behaviour may be overridden by whitetrash.conf
    non_html_regex = re.compile(".*(jpg|gif|png|css|js|ico|swf)$")
    domain_regex = re.compile("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$")
    safebrowsing = False

    def __init__(self, input=sys.stdin, output=sys.stdout):
        self.input_stream = input
        self.output_stream = output
        self.redirect = None
        self.dom_util = WTDomainUtils() 
        if self.safebrowsing:
            self.blc = blacklistcache.BlacklistCache(settings.CONFIG)

    def __enter__(self):
        """
        Returns self as the context manager to be bound to the "as" clause
        of a "with" statement.
        """
        return self

    def read_request(self):
        """
        Reads a request from Squid through stdin
        """
        self._get_request()
        self._validate_request()
        self.redirect_map = RedirectMap(self.request.url)

    def _get_request(self):
        """
        Get's the request by spliting a line from stdin
        """
        squid_input = self.input_stream.readline()
        log.debug("Squid input: %s", squid_input[:-1])
        input_array = squid_input.strip().split(" ")
        if len(input_array) < 4:
            raise RedirectError("Invalid Request.  Not enough information")
        url = input_array[0].lower()
        client_ip = input_array[1].split("/")[0]
        http_method = input_array[3].upper()

        self.request = Request(url, client_ip, http_method)
        log.debug("Request parsed: (%s, %s, %s)" % (url, client_ip, http_method))

    def _validate_request(self):
        """
        Validates a request's ip address and HTTP method
        """
        # The use of urlparse here is quite expensive for simply extracting the domain.
        # It would be much nicer if domain_regex validated the *whole* url.
        url_parts = urlparse(self.request.url)
        self.domain = url_parts.hostname
        if not self.domain_regex.match(self.domain):
            raise RedirectError("Invalid URL in request. Hostname %s does not " \
                                "match domain_regex in whitetrash.conf" % self.domain)
        proto_str = url_parts.scheme.upper()

        # TODO: Decide if FTP should work and will be included
        # Does FTP from the browser go via HTTP and via the Redirector even?
        self.protocol = Whitelist.get_protocol_choice(proto_str)

        # Check the client IP
        try:
            socket.inet_aton(self.request.client_ip)
        except socket.error as err:
            raise RedirectError("Invalid client IP in request")
        # Check the HTTP Method
        try:
            allowed_methods = ["GET", "POST", "CONNECT"]
            assert self.request.http_method in allowed_methods
        except AssertionError as err:
            raise RedirectError("Invalid HTTP method in request")

        log.debug("Request validated: (%s, %s)" % (self.domain, self.protocol))

    def evaluate_request(self):
        """
        Applies redirection rules to a squid request

        domain is evaluated in this order:

        1. Blacklisted  -   Means safebrowsing is checked for every url
        2. Whitelisted
        2. Auto-add
        4. Non-html
        5. Whitetrash form for adding
        """
        log.debug("Evaluating request for %s" % (self.domain))

        if self.is_blacklisted():
            self.redirect = self.redirect_map.blocked_malicious_url()
            log.debug("%s is blacklisted.  Preparing to send user to %s" % (self.domain,self.redirect))
            return

        if self.dom_util.is_whitelisted(self.domain,self.protocol):
            self.dom_util.update_hitcount(domain = self.domain, protocol = self.protocol)
            log.debug("%s is whitelisted." % self.domain)
            return

        if self.auto_add:
            self.dom_util.add_domain(self.domain,
                                    self.protocol,
                                    self.request.url,"",
                                    self.request.client_ip,
                                    User.objects.filter(username="auto"))
            log.debug("Auto adding %s." % self.domain)
            return

        w = self.dom_util.get_or_create_disabled(self.domain,
                                            self.protocol,
                                            self.request.url,
                                            self.request.client_ip)

        self.dom_util.update_hitcount(whitelistobj=w)

        if self.non_html_regex.match(self.request.url):
            self.redirect = self.redirect_map.empty_content_url()
            log.debug("Not HTML.  Preparing to send user to %s" % self.redirect)
            return

        self.redirect = self.redirect_map.add_site_url()
        log.debug("Not whitelisted.  Preparing to send user to %s" % self.redirect)
        return

    def is_blacklisted(self):
        """
        Is this request on the Google safebrowsing blacklists?
        """
        if not self.safebrowsing:
           return False

        return self.blc.check_url(self.request.url)
        

    def forward_request(self):
        """
        Sends a response to squid.  This is either a new url to fetch instead of
        the requested url or is may be an acknowledgement that the orignal
        request should continue without redirection (in which case a newline is
        sent to squid).
        """
        self._send_url_to_squid(self.redirect)

    def _send_url_to_squid(self, url=""):
        if url is None:
            log.debug("Sending newline to squid (no redirect)")
            self.output_stream.write("\n")
        else:
            log.debug("Sending redirected url to squid: %s" % url)
            self.output_stream.write(url + "\n")

    def __exit__(self, exception_type, exception, traceback):
        """
        Handles the various exceptions that may be thrown and sends the
        appropriate response to squid
        """
        if exception_type is RedirectError:
            log.error(str(exception))
            log.debug(traceback)
            if exception.url:
                self._send_url_to_squid(exception.url)
            else:
                self._send_url_to_squid(RedirectMap.http_error_url)
            return True # Do not re-raise this exception

        # Returning false indicates we want exceptions to be passed up the chain
        # (in the code above we catch antcipated exceptions and therefore
        # suppress the re-raising of exceptions)
        return False


class RedirectError(Exception):
    """
    An exception indicating either the squid request is not valid
    or the lookup failed.  The error may or may not indicate a
    forwarding url
    """

    def __init__(self, msg, url=None):
        Exception.__init__(self, msg)
        self.url = url
