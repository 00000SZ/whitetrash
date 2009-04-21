#!/usr/bin/env python

import sys
import os
import glob
import datetime

try:
    from distutils.core import setup
    from distutils.file_util import copy_file,move_file
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
        execute(self.copyApacheConfigs,())
        execute(self.copyWebStaticFiles,())
        execute(self.copySquidConfigs,())
        execute(self.createDBandUsers,())

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

            #This user is for the whitetrash squid redirector (url rewriter)
            self.createDBUser(cur,config["DATABASE_WHITETRASH_USER"],config["DATABASE_WHITETRASH_PASSWORD"])

            #This user is used by the whitetrash_cleanup.py script
            self.createDBUser(cur,config["DATABASE_CLEANUP_USER"],config["DATABASE_CLEANUP_PASSWORD"])

            #We need to install django here to get the right tables for the next grants
            self.installDjango()

            cur.execute("GRANT ALL on whitetrash.* TO %s",(config["DATABASE_DJANGO_USER"]))
            cur.execute("GRANT INSERT,SELECT,UPDATE on whitetrash.whitelist_whitelist TO %s",(config["DATABASE_WHITETRASH_USER"]))
            cur.execute("GRANT SELECT,DELETE on whitetrash.whitelist_whitelist TO %s",(config["DATABASE_CLEANUP_USER"]))

        except Exception,e:
            print """Installing database failed (%s). You may need to create database and users manually.""" % e

    def copyApacheConfigs(self):
        if os.path.exists(os.path.join(self.apache_configdir,"sites-available")):
    
            #Replace the placeholder with our actual code location
            apache_wt_conf=open("example_configs/apache2/whitetrash","r").read()
            open("example_configs/apache2/whitetrash","w").write(apache_wt_conf.replace("/home/greg/whitetrash/django_site/",os.path.abspath("django_site")))

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
        'py_modules': ['configobj'],
        'scripts' : ['whitetrash_cleanup.py',
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
        'data_files' : [('/etc', ['whitetrash.conf'])],
        'requires': ["django (>=1.0)","MySQLdb"],
        'cmdclass': {'install': WhitetrashInstallData}
    }

    return setup_args

def main():
    setup(**setup_args())

if __name__ == "__main__":
    main()

