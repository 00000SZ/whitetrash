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

import CGIHTTPServer
import BaseHTTPServer
import os,re
from base64 import decodestring


class WhitelistCGIRequestHandler(CGIHTTPServer.CGIHTTPRequestHandler):

    def invalid_auth(self):
        self.wfile.write("""

        <HTML>
        
        <HEAD>
        <TITLE>Authentication Error</TITLE>
        </HEAD>
        
        <BODY>
        
        <h1>Authentication Error</h1>
        
        The Proxy-Authorization header did not contain the expected authorisation value.  Either you haven't authenticated to the proxy or you are trying something dodgy.  Contact your friendly sysadmin.
        
        </BODY>
        
        </HTML>
        
        """)
        
    def invalid_request(self,params):
        self.wfile.write("""

        <HTML>
        
        <HEAD>
        <TITLE>CGI Error</TITLE>
        </HEAD>
        
        <BODY>
        
        <h1>CGI Error</h1>
        
        <P>I didn't get the parameters I was expecting from your request.  Here are the parameters I got:<P>
        <pre>
        %s
        <pre>
        
        <p>Contact your friendly sysadmin.</p>
        
        </BODY>
        
        </HTML>
        
        """ % params)


    def do_POST(self):
        try:
            #Use this for digest: breaks basic.
            #split_header=re.split(r"[=,]",self.headers['Proxy-Authorization'])
            
            #Basic header:
            #Header looks like: "Basic sldkfjlssjd\r\n"
            uname=decodestring(self.headers['Proxy-Authorization'].split(" ")[1]).split(":")[0]
            
            #Digest header
            #uname_pos=split_header.index("Digest username")
            #uname=split_header[uname_pos+1].strip("\"")
            if uname.isalnum():
                #This is a simple check
                #Username is alpha-numeric
                os.environ['REMOTE_USER']=uname
                self.cgi_info = "./", "whitetrash_add.py"
                self.run_cgi()
            else:
                #User name invalid
                self.invalid_auth()
        except:
            self.invalid_auth()
        
        
    def do_GET(self):

        try:
            param_start=self.path.index("?")

            if param_start>0:
                self.cgi_info = "./", "whitetrash_genform.py?" + self.path[param_start+1:].replace("?","%3F")
                #print self.cgi_info
                self.run_cgi()

        except:
            self.invalid_request(self.path)

def run(server_class=BaseHTTPServer.HTTPServer,
        handler_class=WhitelistCGIRequestHandler):
    server_address = ('127.0.0.1', 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

run()
