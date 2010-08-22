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

import re
import socket
import logging

from urlparse import urlparse

log = logging.getLogger(__name__)

class RedirectMap(object):
    """
    Encapsulates all information regarding a URL Request e.g. protocol,
    request type, forwarding url etc.
    """

    # This behaviour may be specified in whitetrash.conf
    redirect_to_ssl = True
    ssl_port = 443
    hostname = "whitetrash"

    http_error_url = "http://{0}/error".format(hostname)

    def __init__(self, url):
        """
        Creates a mapping of a URL to all it's possible redirections
        e.g. redirection to add the url to the whitelist.

        """
        self._url = urlparse(url)
        #self.validate()

    #def validate(self):
    #    """
    #    Validates all parts of the redirection.  Raises AssertionErrors for
    #    bad protocols/schemes, bad domain names, bad HTTP methods and bad IP
    #    addresses.
    #    """
    #    protocol = self._url.scheme.upper()
    #    assert protocol in ["HTTP", "HTTPS"], "Invalid protocol: %s" % protocol
    #
    #    domain = self._url.hostname
    #    assert self.domain_regex.match(domain), "Invalid domain: %s" % domain

    def _formatdict(self):
        # Because format and properties don't play nice
        # More info: http://mail.python.org/pipermail/python-list/2003-February/190248.html
        if self.redirect_to_ssl:
            protocol = "https"
        else:
            protocol = "http"
        return {"protocol": protocol,
                "hostname": self.__class__.hostname,
                "domain": self._url.netloc,
                "url": self._url.geturl(),
                "ssl_port": self.__class__.ssl_port}

    def add_site_url(self):
        """
        The redirect to use when a domain does not appear on the whitelist
        """
        #This is wrong.  Want to send to .sslwhitetrash when the *request* is SSL.
#        if self.redirect_to_ssl:
#            return self._frame_response("{protocol}://{domain}.ssl{hostname}:{ssl_port}" \
#                                        "/addentry?".format(**self._formatdict()))
#        else:
        return self._frame_response("{protocol}://{hostname}/whitelist/addentry?url={url}&" \
                                        "domain={domain}".format(**self._formatdict()))

    def blocked_phishing_url(self):
        """
        The redirect to use when urls appear on Google's phishing site blacklist
        """
        return self._frame_response("{protocol}://{hostname}/whitelist/" \
                                    "forgerydomain={url}".format(**self._formatdict()))

    def blocked_malicious_url(self):
        """
        The redirect to use when urls appear on Google's malicious site blacklist
        """
        return self._frame_response("{protocol}://{hostname}/whitelist/" \
                                    "attackdomain={url}".format(**self._formatdict()))

    def empty_content_url(self):
        """
        The redirect to use when the browser is not expecting html back
        """
        return self._frame_response("{protocol}://blocked{hostname}/" \
                                    "empty".format(**self._formatdict()))

    def error_url(self, msg):
        """
        The redirect to use when you need to send an error to the user
        """
        formatdict = self._formatdict().update({"msg": msg})
        return self._frame_response("{protocol}://{hostname}/whitelist/error?" \
                                    "msg={msg}" % formatdict)

    # TODO: rewrite frame_response as a decorator
    def _frame_response(self, url):
        # Cleans up a url so it will be treated nicely by Squid and
        # the user's browser

        # Add a status code when using ssl to keep the browser happy
        if self.redirect_to_ssl:
            return ''.join(["302:", url])
        else:
            return url

