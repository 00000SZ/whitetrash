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
import urllib
import datetime
import MySQLdb
import MySQLdb.cursors

dbh = MySQLdb.Connect(user = "unpriv",
                                      passwd = "passwd",
                                      db = "proxy",
                                      unix_socket = "/var/run/mysqld/mysqld.sock", 
                                      use_unicode = False
                                      )

table=""

try:
    cursor=dbh.cursor()
    cursor.execute("select * from whitelist order by username,id")
    dateobj=datetime
    #Table is id,domain,time,username,orig request,comment
    #I don't unquote the original domain urllib.unquote(row[4]) due to the potential for code injection.
    for row in cursor:
        table+="<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" %(row[0],row[1],row[2],row[3],row[5],row[4])
    htmlpage="""

    <HTML>
    <HEAD>
    <TITLE>HTTP Whitelist Report</TITLE>
    </HEAD>

    <BODY>

    <h1>Whitelist</h1>
    <p>
    Report generated at %s.
    <p>
    
    <table border=1 frame=box>
    <tr><td><b>ID</b></td><td><b>Whitelisted Domain</b></td><td><b>Timestamp (local)</b></td><td><b>Username</b></td><td><b>Comment</b></td><td><b>Original Request</b></td></tr>
    %s
    </table>

    </BODY>
    </HTML>""" % (str(dateobj.datetime.now()),table)

    handle=open("/var/www/whitelist.html","w")
    os.system("chmod 744 /var/www/whitelist.html")
    handle.write(htmlpage)
    handle.close()

except Exception,e:
    print "Error running whitelist html page generation: %s" %e

