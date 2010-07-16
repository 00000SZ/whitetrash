#!/usr/bin/env python -u

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

#import os
#print 'ENVIRON START'
#os.environ['DJANGO_SETTINGS_MODULE'] = "django_site.whitetrash.settings"
#print os.environ['DJANGO_SETTINGS_MODULE']
#print 'ENVIRON END'

import sys
import re

from configobj import ConfigObj

from redirector.common import RedirectMap
from redirector.squid import RedirectHandler

config_file = "/etc/whitetrash.conf"


def main():
    start_logging()
    open_config()
    configure()
    run()

def start_logging():
    logging.fileConfig(config_file)

def open_config():
    """
    Tries opening the config file for whitetrash
    """
    global config
    try:
        config = ConfigObj(config_file, file_error=True)["DEFAULT"]
    except IOError:
        print "Can't find config file %s" % config_file
        sys.exit(1)
    except KeyError:
        print "Config has no 'DEFAULT' section.  Does %s start with the line '[DEFAULT]'?" % config_file
        sys.exit(1)

def configure():
    """
    Configures all of whitetrash's components from whitetrash.conf
    """
    # Whether Whitetrash is being hosted over SSL
    # Default to True unless explicity told no SSL
    RedirectMap.redirect_to_ssl = get_option("ssl_sever_enabled", default=True)

    # Which SSL port Whitetrash is listening on
    # Default is 443
    #RedirectMap.redirect_to_ssl = get_option("ssl_sever_port", default=443)

    # The hostname that the Whitetrash server is using
    # Default is whitetrash
    RedirectMap.redirect_to_ssl = get_option("whitetrash_domain", default="whitetrash")

    # Used for validating requests
    regex = get_option("domain_regex", default="^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$")
    RedirectHandler.domain_regex = re.compile(regex)

    # Used for validating requests
    regex = get_option("nonhtml_siffix_re", default=".*(jpg|gif|png|css|js|ico|swf)$")
    RedirectHandler.non_html_regex = re.compile(regex)

    # So we know whether to check the blacklist 
    RedirectHandler.safebrowsing = get_option("safebrowsing", default=False)

    # Should we automatically add all domains we see 
    RedirectHandler.auto_add = get_option("auto_add_all_domains", default=False)


def get_option(option, default):
    """
    Returns a value from the config, interpolating the value's type from the default supplied
    """
    try:
        try:
            if type(default) is bool:
                return config.as_bool(option)
            elif type(default) is int:
                return config.as_int(option)
            else:
                return config[option]
        except ValueError:
            # Happens if as_bool(option) is not actually a bool or
            # as_int(option) is not a valid int
            print "Invalid value for %s in %s" % (option, config_file)
            sys.exit(1)
    except KeyError:
        return default

def run():
    while True:
        with RedirectHandler() as redirect:
            redirect.read_request()
            redirect.evaluate_request()
            redirect.forward_request()


if __name__=="__main__":
    main()
