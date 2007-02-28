#!/usr/bin/env python

import sys
import os
import glob
try:
    from distutils.core import setup
    from distutils.command.build_py import build_py
except ImportError:
    print 'Error: The "distutils" standard module, which is required for the '
    print 'installation of Whitetrash, could not be found.  You may need to '
    print 'install a package called "python-dev" (or similar) on your '
    print 'system using your package manager.'
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
        'version': '0.1',
        'author': 'gregsfdev',
        'author_email': 'gregsfdev@users.sourceforge.net',
        'license': 'GPL',
        'platforms': 'Linux',
        'packages': ['whitetrash_db'],
        'scripts' : ['whitetrash_serv',
                    'whitetrash.py',
                    'whitetrash_report.py'],
        'classifiers' : [
            'License :: OSI-Approved Open Source :: GNU General Public License (GPL)',
            'Intended Audience :: by End-User Class :: System Administrators',
            'Development Status :: 2 - Pre-Alpha'
            'Topic :: Security',
            'Programming Language :: Python',
            'Operating System :: Modern (Vendor-Supported) Desktop Operating Systems :: Linux',
            'User Interface :: Web-based',
            'Database Environment :: Database API :: SQL-based',
            'Environment :: Console',
            'Natural Language :: English',],
        'data_files' : [('/etc/init.d', ['whitetrash'])],
    }

    return setup_args

def main():
    setup(**setup_args())

if __name__ == "__main__":
    main()

