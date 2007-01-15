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

import cgi
#This MUST be turned off for production.
#import cgitb; cgitb.enable()
import os
import datetime

#cgi.test()
form = cgi.FieldStorage()

#Squid does all the url validity checking for us, which is nice
#HOWEVER we need to handle the case where users directly submit their
#own urls and also check to make sure people are not submitting IPs.

print "Content-Type: text/html\r\n\n"
print """
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    <title>Internet Access Request Form</title>
  </head>

  <body>
    <h1>Internet Access Request</h1>    
    <form action="http://whitelistproxy/cgi-bin/whitelist_add.py" method="post">

      <p><b>Host Requested (edit if necessary): </b><input type="text" name="domain" value="%s" maxlength=70 size=70></p>
      <p><b>Full Request: </b>%s</p>
      <p><b>Client IP: </b>%s</p>
      <p><b>Client Username: </b>%s</p>
      <p><b>Enter business requirement or comment for this domain: </b><input type="text" name="comment" maxlength=100 size=100></p>
      
      <p>By clicking "I Agree" below you are agreeing to have the information above stored on a list of whitelisted websites with YOUR UNIQUE USERNAME at <a href="http://viewwhitelist/whitelist.html">this address</a></p>
      <input type="hidden" name="url" value="%s">
      <input type="submit" name="consent" value="I Agree" class="LgnBtn">
    </form>


    <hr>
    <address><a href="mailto:cnvt@ubuntu">cnvt</a></address>
<!-- Created: Mon Jul  3 20:28:18 EST 2006 -->
<!-- hhmts start -->
Last modified: Fri Jul  7 00:17:53 EST 2006
<!-- hhmts end -->
  </body>
</html>
<HTML>
""" % (form.getfirst("domain"),form.getfirst("url"),form.getfirst("clientaddr"),form.getfirst("clientident"),form.getfirst("url"))

