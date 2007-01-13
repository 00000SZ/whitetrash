#!/usr/env/python

import cgi
#This MUST be turned off for production.
#import cgitb; cgitb.enable()
import os
import re,urllib
import datetime
import MySQLdb
import MySQLdb.cursors


def failed(e):
    print "Content-Type: text/html\r\n\n"
    print """

    <HTML>

    <HEAD>
    <TITLE>Error - Cannot add domain to whitelist</TITLE>
    </HEAD>

    <BODY>

    <h1>Could not add domain to whitelist</h1>
    <p>
    Please contact your friendly sysadmin.  Error details as follows
    <p>
    <hr>
    <p>%s</p>

    </BODY>

    </HTML>

    """ % (e)

def success():
    dateobj=datetime
    print "Content-Type: text/html\r\n\n"
    print """

    <HTML>

    <HEAD>
    <TITLE>Access Granted</TITLE>
    <META HTTP-EQUIV=\"refresh\" CONTENT=\"1;URL=%s\">
    </HEAD>

    <BODY>

    <h1>Thank you %s</h1>
    <p>
    Your access request has been granted.  Your browser should automatically take you to the website. If it doesn't you can use this link: <a href=\"%s\">%s</a>
    <p>

    <p>The following information was recorded:</p>

    <table border=1 frame=box>

    <tr><td><b>TimeStamp</b></td><td><b>Username</b></td><td><b>Whitelist site added</b></td><td><b>Original Request</b></td></tr>

    <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>

    </table>


    </BODY>

    </HTML>

    """ % (orig_url,user,orig_url,orig_url,str(dateobj.datetime.now()),user,domain,orig_url)



#cgi.test()
try:
    #All of these fields need to be sanitised.
    form = cgi.FieldStorage()
    orig_comment=str(form.getfirst("comment"))[:99]
    orig_url=str(form.getfirst("url"))[:254]
    user=os.environ['REMOTE_USER']
    domain=str(form.getfirst("domain"))[:70]
    
    if orig_url and user and domain:
        if not orig_comment:
            orig_comment="None"

        #Quote the url to get rid of any dangerous stuff for the DB, but still display the proper text when viewed in a browser.
        url=urllib.quote(orig_url.lower())
        #Only allow sane text in the comment.
        comment=re.sub("[^a-zA-Z0-9- .,!]+","",orig_comment)

        #sanitise domain
        domain=form.getfirst("domain").lower()
        #Make sure it is of something.com format
        #domain_sanitise=re.compile("([a-z0-9-]+\.)+(?=(?P<suffix>(aero|biz|cat|com|co|coop|info|jobs|mobi|museum|name|net|org|pro|travel|gov|edu|mil|int)(\.[a-z]{2})?$))(?P=suffix)")
        domain_sanitise=re.compile("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$")
        domain_res=domain_sanitise.match(domain)
        if domain_res:
            #Domain is valid.
            domain=domain_res.group()
            domain=re.sub("^www[0-9]?\.","",domain,1)
            dbh = MySQLdb.Connect(user = "unpriv",
                                        passwd = "passwd",
                                        db = "proxy",
                                        unix_socket = "/var/run/mysqld/mysqld.sock", 
                                        use_unicode = False
                                        )

            try:
                cursor=dbh.cursor()
                #Normalise www2 to www
                cursor.execute("insert into whitelist set domain=%s,timestamp=NOW(),username=%s,originalrequest=%s,comment=%s", (domain,user,url,comment))
                success()
            except Exception,e:
                failed(e)
        else:
            #Decided to fail rather than change to a valid domain name.
            failed("Bad domain name")
    else:
        failed("Incomplete fields")
except Exception,e:
    failed("Invalid input:%s" % e)



