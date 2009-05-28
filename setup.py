#!/usr/bin/env python

import sys
import os
import glob
import datetime
import string
import random 
from OpenSSL import crypto


try:
    from distutils.core import setup
    from distutils.file_util import copy_file,move_file,write_file
    from distutils.dir_util import copy_tree,mkpath
    from distutils.util import execute
    from distutils.command.install import install 

except ImportError:
    print """Error: The "distutils" standard module, which is required for the
    print installation of Whitetrash, could not be found.  You may need to
    print install a package called "python-dev" (or similar) on your
    print system using your package manager."""
    sys.exit(1)

def check_modules(*modules):
    for module in modules:
        import imp
        try:
            imp.find_module(module)
        except ImportError, e:
            raise DistutilsError, 'Could not find module %s. Make sure all dependencies are installed.' % e


class WhitetrashInstallData(install):
    user_options = install.user_options
    user_options.append(('mysql-root-passwd=', "p", 'MySQL root password for local server [default: None]'))
    user_options.append(('web-root=', "w", 'Web root for apache [default: /var/www/]. Change requires modification to site config'))
    user_options.append(('apache-configdir=', "a", 'Apache2 config dir [default: /etc/apache2/]'))

    def initialize_options(self):
        install.initialize_options(self)
        self.mysql_root_passwd=""
        self.web_root="/var/www/"
        self.apache_configdir="/etc/apache2/"

    def run(self):
        install.run(self)
        check_modules('MySQLdb')
        execute(self.installPathFile,())
        execute(self.copyApacheConfigs,())
        execute(self.copyWebStaticFiles,())
        execute(self.copySquidConfigs,())
        execute(self.createWTUser,())
        execute(self.createCertAuthority,())
        execute(self.createWTApacheCert,())
        execute(self.createDBandUsers,())
        execute(self.createCleanupCron,())

    def installPathFile(self):
        """Put safebrowse on the python path so you don't have to import safebrowsing.safebrowse"""
        self.extra_dirs = "safebrowsing"
        self.path_file = "safebrowsing"
        self.create_path_file()

    def createWTUser(self):
        ret=os.system("""adduser --shell /bin/false --no-create-home --disabled-password --disabled-login --gecos "" whitetrash""")
        if ret !=0:
            print "Could not add whitetrash user - already exists?"

    def installDjango(self):
        #Need to change our 'working dir' to make sure the django install works properly
        sys.path[0]=os.path.abspath("django_site/whitetrash")
        from django.core.management import execute_manager
        import settings # Assumed to be in the same directory.
        execute_manager(settings,argv=['manage.py','syncdb'])

    def createDBUser(self,dbcur,user,passwd):
        try:
            dbcur.execute("CREATE USER %s@'localhost' IDENTIFIED BY %s",(user,passwd))
        except Exception,e:
            print """Error creating user, it may already exist? (%s)""" % e


    def createDBandUsers(self):

        try:
            import MySQLdb
        except ImportError:
            print """Python MySQL bindings not installed.  Look for a
            python-mysqldb package."""
            sys.exit(1)

        try:
            from configobj import ConfigObj
            config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        except Exception,e:
            print """Error parsing /etc/whitetrash.conf (%s)""" % e

        try:
            if self.mysql_root_passwd:
                con=MySQLdb.Connect(user="root",passwd=self.mysql_root_passwd)
            else:
                con=MySQLdb.Connect(user="root")
            cur=con.cursor()
            cur.execute("create database if not exists whitetrash")

            #This user is for django 
            self.createDBUser(cur,config["DATABASE_DJANGO_USER"],config["DATABASE_DJANGO_PASSWORD"])
            cur.execute("GRANT ALL on whitetrash.* TO %s",(config["DATABASE_DJANGO_USER"]))

            #This user is for the whitetrash squid redirector (url rewriter)
            self.createDBUser(cur,config["DATABASE_WHITETRASH_USER"],config["DATABASE_WHITETRASH_PASSWORD"])

            #This user is used by the whitetrash_cleanup.py script
            self.createDBUser(cur,config["DATABASE_CLEANUP_USER"],config["DATABASE_CLEANUP_PASSWORD"])

            #We need to install django here to get the right tables for the next grants
            self.installDjango()

            cur.execute("GRANT INSERT,SELECT,UPDATE on whitetrash.whitelist_whitelist TO %s",(config["DATABASE_WHITETRASH_USER"]))
            cur.execute("GRANT SELECT,DELETE,UPDATE on whitetrash.whitelist_whitelist TO %s",(config["DATABASE_CLEANUP_USER"]))

        except Exception,e:
            print """Installing database failed (%s). You may need to create database and users manually.""" % e

    def copyApacheConfigs(self):
        if os.path.exists(os.path.join(self.apache_configdir,"sites-available")):
    
            #Replace the placeholder with our actual code location
            apache_wt_conf=open("example_configs/apache2/whitetrash","r").read()
            open("example_configs/apache2/whitetrash","w").write(apache_wt_conf.replace("/home/greg/whitetrash/django_site",os.path.abspath("django_site")))

            copy_file("example_configs/apache2/whitetrash", os.path.join(self.apache_configdir,"sites-available/whitetrash"))
            httpconf=os.path.join(self.apache_configdir,"httpd.conf")

            if os.path.exists(httpconf):
                print "Backing up existing %s" % httpconf
                move_file(os.path.join(self.apache_configdir,"httpd.conf"),
                                    "/etc/apache2/httpd.conf.wt.bak.%s" % datetime.datetime.now().isoformat())

            copy_file("example_configs/apache2/httpd.conf", httpconf)
            copy_file(os.path.join(self.apache_configdir,"sites-available/whitetrash"), os.path.join(self.apache_configdir,"sites-enabled/whitetrash"),link="sym")

            mkpath(os.path.join(self.apache_configdir,"ssl")) 
            
        else:

            print """Apache2 not installed, couldn't find %s""" % os.path.join(self.apache_configdir,"sites-available")
            sys.exit(1)

    def copyWebStaticFiles(self):
        mkpath(os.path.join(self.web_root,"whitetrash/"))
        #Couldn't use copy tree because it grabs the .svn directory too
        for thisfile in glob.glob("example_configs/apache2/www/whitetrash/*.*"):
            copy_file(thisfile,os.path.join(self.web_root,"whitetrash/"))

        if not os.path.exists(os.path.join(self.web_root,"whitetrash/media")):
            os.symlink("/usr/share/python-support/python-django/django/contrib/admin/media/", os.path.join(self.web_root,"whitetrash/media"))

    def copySquidConfigs(self):
        if os.path.exists("/etc/squid/squid.conf"):

            move_file("/etc/squid/squid.conf","/etc/squid/squid.conf.wt.bak.%s" % datetime.datetime.now().isoformat())
            copy_file("example_configs/squid/squid.conf","/etc/squid/squid.conf")

        else:
            print "Squid not installed, no /etc/squid/squid.conf."
            sys.exit(1)


    def genPasswd(self,length=8, chars=string.letters + string.digits):
        return ''.join([random.choice(chars) for i in range(length)])
   
    def createCertAuthority(self):
        """Create a certificate authority for dynamic creation of SSL certs"""

        import whitetrash_cert_server as wtcs
        try:
            from configobj import ConfigObj
            config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        except Exception,e:
            print """Error parsing /etc/whitetrash.conf (%s)""" % e

        #Create dir where dynamic certs will be installed
        mkpath(os.path.join(config["cacert_dir"],"private")) 
        if not os.path.exists(config["dynamic_certs_dir"]):
            print("Creating dynamic certs dir: %s" % config["dynamic_certs_dir"])
            mkpath(config["dynamic_certs_dir"]) 
            os.system("chown whitetrash:whitetrash %s" % config["dynamic_certs_dir"])

        #Create the keyfile that all dynamic certs will use
        if not os.path.exists(config["dynamic_certs_keyfile"]): 
            print("Creating dynamic certs keyfile: %s" % config["dynamic_certs_keyfile"])
            certkey = wtcs.createKeyPair(crypto.TYPE_RSA,4096)
            outkey = crypto.dump_privatekey(crypto.FILETYPE_PEM,certkey)
            open(config["dynamic_certs_keyfile"],'w').write(outkey)
            os.system("chown whitetrash:whitetrash %s" % config["dynamic_certs_keyfile"])
            os.system("chmod 400 %s" % config["dynamic_certs_keyfile"])

        #Create the cakey and store encrypted with random password
        if not os.path.exists(wtcs.cakeyfile):
            print("Creating CA keyfile: %s" % wtcs.cakeyfile)
            capass = self.genPasswd(length=64)
            self.cakey = wtcs.createKeyPair(crypto.TYPE_RSA,4096)
            privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM,self.cakey,"DES3",capass)
            open(wtcs.cakeyfile,'w').write(privkey)
            print("Writing CA keyfile passwd to: %s" % config["ca_pass"])
            open(config["ca_pass"],'w').write(capass)

            os.system("chown whitetrash:whitetrash %s %s" % (wtcs.cakeyfile,config["ca_pass"]))
            os.system("chmod 400 %s %s" % (wtcs.cakeyfile,config["ca_pass"]))
        else:
            print("Loading CA keyfile: %s" % wtcs.cakeyfile)
            self.cakey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                    open(wtcs.cakeyfile,'r').read(),
                                    open(config["ca_pass"],'r').readline().strip())

        #Create the cacert
        if not os.path.exists(wtcs.cacertfile):  
            print("Creating CA cert: %s" % wtcs.cacertfile)
            # The CA *cannot* have the same subject string as a cert, because
            # SSL will think it is self signed.  I use Whitetrash CA here.
            req = wtcs.createCertRequest(self.cakey,C=config["country"],
                                    ST=config["state"],L=config["city"],
                                    O=config["org_unit"],CN="Whitetrash CA")
            issue_time = int(config["certificate_time_offset_s"])
            self.cacert = wtcs.createCertificate(req, (req,self.cakey), 
                            random.randint(0,wtcs.upper_rand), 
                            (-issue_time, 60*60*24*365*wtcs.cert_years),CA=True) 
            open(wtcs.cacertfile,'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.cacert))

        else:
            print("Loading CA cert: %s" % wtcs.cacertfile)
            self.cacert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                    open(wtcs.cacertfile,'r').read())


        #Create apache link to cacert to make it easy to download
        if not os.path.exists(os.path.join(self.web_root,"whitetrash/cacert.pem")):
            print("Creating CA download link for apache")
            os.symlink(wtcs.cacertfile, os.path.join(self.web_root,"whitetrash/cacert.pem"))


    def createWTApacheCert(self):
        import whitetrash_cert_server as wtcs
        apachekeyfile = "/etc/apache2/ssl/server.key"
        apachecertfile = "/etc/apache2/ssl/server.crt"

        try:
            from configobj import ConfigObj
            config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        except Exception,e:
            print """Error parsing /etc/whitetrash.conf (%s)""" % e


        if not os.path.exists(apachekeyfile):
            print("Creating apache ssl key file: %s" % apachekeyfile)
            apachekey = wtcs.createKeyPair(crypto.TYPE_RSA,4096)
            privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM,apachekey)
            open(apachekeyfile,'w').write(privkey)
            os.system("chmod 400 %s" % apachekeyfile)
        else:
            print("Loading apache ssl key file: %s" % apachekeyfile)
            apachekey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                    open(apachekeyfile,'r').read())

        if not os.path.exists(apachecertfile):
            print("Creating apache ssl cert: %s" % apachecertfile)
            req = wtcs.createCertRequest(apachekey,C=config["country"],
                                    ST=config["state"],L=config["city"],
                                    O=config["org_unit"],CN=config["whitetrash_domain"])
            issue_time = int(config["certificate_time_offset_s"])
            cert = wtcs.createCertificate(req, (self.cacert,self.cakey), 
                            random.randint(0,wtcs.upper_rand), 
                            (-issue_time, 60*60*24*365*wtcs.cert_years)) 
            open(apachecertfile,'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    def createCleanupCron(self):
        """
        Reads the cron string from whitetrash.conf and creates
        a daily cron job using this string to run at 3:00am daily.
        The default cron string in whitetrash.conf is
        "python whitetrash_cleanup.py" which removes old entries
        from the whitelist (both in the whitelist and memcache)
        """

        try:
            from configobj import ConfigObj
            config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]
        except Exception,e:
            print """Error parsing /etc/whitetrash.conf (%s)""" % e

        cron_file = "/etc/cron.d/whitetrash-cleanup"
        cron_str = config["cleanup_cron"]
        write_file(cron_file, [cron_str])


def setup_args():
    setup_args={
        'name': 'whitetrash',
        'description': 'Whitetrash -- Dynamic web whitelisting for squid',
        'long_description': """\
    The goal of Whitetrash is to provide a user-friendly and
    sysadmin-friendly proxy that makes it significantly harder
    for malware to use HTTP and SSL for initial compromise, 
    data exfiltration, and command and control. Whitetrash 
    implements a whitelisted web proxy as a Squid redirector.""", # wrap at col 60
        'url': 'http://whitetrash.sourceforge.net/',
        'version': '0.2',
        'author': 'gregsfdev',
        'author_email': 'gregsfdev@users.sourceforge.net',
        'license': 'GPL',
        'platforms': 'Linux',
        'packages': ['safebrowsing'],
        'py_modules': ['configobj','blacklistcache'],
        'scripts' : ['whitetrash_cert_server.py',
                     'whitetrash_cleanup.py',
                     'whitetrash.py'],
        'classifiers' : [
            'License :: OSI-Approved Open Source :: GNU General Public License (GPL)',
            'Intended Audience :: by End-User Class :: System Administrators',
            'Development Status :: 4 - Beta'
            'Topic :: Security',
            'Programming Language :: Python',
            'Operating System :: Modern (Vendor-Supported) Desktop Operating Systems :: Linux',
            'User Interface :: Web-based',
            'Database Environment :: Database API :: SQL-based',
            'Environment :: Console',
            'Natural Language :: English',],
        'data_files' : [('/etc', ['whitetrash.conf']),
                        ('/etc/init.d', ['whitetrash_cert'])],
        'requires': ["django (>=1.0)","MySQLdb"],
        'cmdclass': {'install': WhitetrashInstallData}
    }

    return setup_args

def main():
    setup(**setup_args())

if __name__ == "__main__":
    main()

