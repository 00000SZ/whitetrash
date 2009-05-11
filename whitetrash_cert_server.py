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

import BaseHTTPServer, SimpleHTTPServer, SocketServer
import os,sys,time,cgi
import os.path
import socket
import re,urllib
import threading
from OpenSSL import SSL
from string import join
from configobj import ConfigObj
from random import randint
import logging
import logging.config
from OpenSSL import crypto
import random

config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
logging.config.fileConfig("/etc/whitetrash.conf")
wtlog = logging.getLogger("whitetrashCertServer")
domainre = re.compile(config["domain_regex"])
stripre = re.compile("(.*).ssl%s$" % config["whitetrash_domain"])
upper_rand = pow(2,(8*int(config["serial_number_bytes"])))
cert_years = int(config["certificate_years"])

cacertfile = os.path.join(config["cacert_dir"],"cacert.pem")
cakeyfile = os.path.join(config["cacert_dir"],"private/cakey.pem")
certkey = ""


def clean_domain(domain):
    try:
        return domainre.match(domain).group()
    except AttributeError:
        wtlog.info("Bad domain: %s" % domain)
        return ""

def cert_exists(certfile):
    return os.path.exists(certfile)


def createKeyPair(type, bits):
    """
    Create a public/private key pair.

    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def createCertRequest(pkey, digest="sha1", **name):
    """
    Create a certificate request.

    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key,value) in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req

def createCertificate(req, (issuerCert, issuerKey), serial, (notBefore, notAfter), digest="md5"):
    """
    Generate a certificate given a certificate request.

    Arguments: req        - Certificate reqeust to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert

def create_cert(certfile,prefix,domain):
    """Create a certificate file, just shell out for now."""
    req = createCertRequest(certkey,C=config["country"],
                            ST=config["state"],L=config["city"],
                            O=config["org_unit"],CN="%s%s" % (prefix,domain))
    issue_time = int(config["certificate_time_offset_s"])
    cert = createCertificate(req, (cacert,cakey), random.randint(0,upper_rand), (-issue_time, 60*60*24*365*cert_years) ) 
    open(certfile,'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


def get_domain(domain):
    """If this domain is second level or deeper, strip the first label so we can wildcard it.
    
    If we are wildcarding, return *. as the prefix, otherwise return empty string.
    """
    splits = domain.split(".")
    if len(splits) > 2:
        dom_temp=domain
        return ("*.",re.sub("^[a-z0-9-]+\.","",dom_temp,1))
    else:
        return ("",domain)
    
        
def get_cert(domain):
    (pref,dom) = get_domain(domain)
    certfile=os.path.join(config["dynamic_certs_dir"],"%s.pem" % dom)
    if not cert_exists(certfile):
        create_cert(certfile,pref,dom)
    return certfile 

class HTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    def setup(self):
        SimpleHTTPServer.SimpleHTTPRequestHandler.setup(self)
        self.domain = ""

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location","https://%s/whitelist/addentry?url=https%%253A//%s&domain=%s&protocol=2" 
                            % (config["whitetrash_domain"],self.domain,self.domain))
        self.end_headers()

    def do_CONNECT(self):
        wtlog.debug("Got connect request: %s" % self.request)
        wtlog.debug("Path: %s" % self.path)
        #strip off the sslwhitetrash bit from the end of the domain
        self.domain = clean_domain(stripre.sub(r"\1",self.path.split(":")[0]))
        self.send_response(200, 'OK')
        self.end_headers()

        #Switch our socket to SSL
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        #server.pem's location (containing the server private key and
        #the server certificate).
        ctx.use_privatekey_file( config["dynamic_certs_keyfile"] )
        ctx.use_certificate_file( get_cert(self.domain) )
        ssl_socket = SSL.Connection(ctx, self.wfile)
        self.rfile = socket._fileobject(ssl_socket, "rb", self.rbufsize)
        self.wfile = socket._fileobject(ssl_socket, "wb", self.wbufsize)
        ssl_socket.set_accept_state()
        self.handle()

class WhitetrashServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

def run_http(server_class=WhitetrashServer,
        handler_class=HTTPRequestHandler):
    server_address = (config["cert_server_listen_addr"], int(config["cert_server_listen_port"]))
    httpd = server_class(server_address, handler_class)
    PIDFILE = config["pidfile"]
    DAEMON = False 

    if (DAEMON):
        # Unix double-fork magic
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror)
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")   # don't prevent unmounting
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent, print eventual PID before
                open(PIDFILE,'w').write("%d"%pid)
                sys.exit(0)
        except OSError, e:
            print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror)
            sys.exit(1)
    
    
        # redirect outputs to a log file
        #sys.stdout = sys.stderr = Log(open(LOGFILE, 'a+'))
    wtlog.info("***** Whitetrash Server Started - %s *****" % (str(time.asctime())))

    httpd.serve_forever()

if __name__ in ('main', '__main__'):

    cacert = crypto.load_certificate(crypto.FILETYPE_PEM,open(cacertfile,'r').read())
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                    open(cakeyfile,'r').read(),
                                    open(config["ca_pass"],'r').readline().strip())

    certkey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                            open(config["dynamic_certs_keyfile"],'r').read())
    
    run_http()



