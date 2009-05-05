# Django settings for whitetrash project.
from configobj import ConfigObj
import logging
import logging.config

config = ConfigObj("/etc/whitetrash.conf")["DEFAULT"]

def conf(config_item):
    return config[config_item].upper() == "TRUE"

logging.config.fileConfig("/etc/whitetrash.conf")
LOG = logging.getLogger("whitetrashDjango")

CAPTCHA_HTTP = conf("CAPTCHA_HTTP") 
CAPTCHA_SSL = conf("CAPTCHA_SSL")
CAPTCHA_WINDOW_SEC = int(conf("CAPTCHA_WINDOW_SEC"))

#Fix weird need to specify absolute paths
import os.path
ROOT = os.path.dirname(os.path.realpath(__file__))
def absp(path):
    return os.path.join(ROOT,path)

#session expiry time in seconds.
SESSION_COOKIE_AGE = 28800
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_SECURE = conf("ssl_server_enabled")

LOGIN_REDIRECT_URL = "/whitelist/addentry/?url=&domain="

DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS

DATABASE_ENGINE = 'mysql'           # 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'ado_mssql'.
DATABASE_NAME = config['DATABASE_NAME']             # Or path to database file if using sqlite3.
DATABASE_USER = config['DATABASE_DJANGO_USER']             # Not used with sqlite3.
DATABASE_PASSWORD = config['DATABASE_DJANGO_PASSWORD']         # Not used with sqlite3.
DATABASE_HOST = config['DATABASE_HOST']      # Set to empty string for localhost. Not used with sqlite3.
DATABASE_PORT = config['DATABASE_PORT']      # Set to empty string for default. Not used with sqlite3.

# Local time zone for this installation. Choices can be found here:
# http://www.postgresql.org/docs/8.1/static/datetime-keywords.html#DATETIME-TIMEZONE-SET-TABLE
# although not all variations may be possible on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/New_York EST5EDT SystemV/EST5EDT US/Eastern'

# Language code for this installation. All choices can be found here:
# http://www.w3.org/TR/REC-html40/struct/dirlang.html#langcodes
# http://blogs.law.harvard.edu/tech/stories/storyReader$15
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT.
# Example: "http://media.lawrence.com"
MEDIA_URL = ''

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'ua1a2l8%r7$8u)yec73u)bpd8a^=72=dx2gyp8figty_hn9j#t'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.doc.XViewMiddleware',
    'whitetrash.SSLMiddleware.SSLRedirect',
)

ROOT_URLCONF = 'whitetrash.urls'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    absp("../templates")
)


TEMPLATE_CONTEXT_PROCESSORS = ('django.core.context_processors.request',
'django.core.context_processors.auth',
'django.core.context_processors.i18n',
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.admin',
    'whitetrash.whitelist',
)

if conf("use_memcached"):
    import cmemcache
    MEMCACHE_SERVERS=config["memcache_servers"].split(",")
    MEMCACHE=cmemcache.Client(MEMCACHE_SERVERS)
else:
    MEMCACHE=""

if conf("LDAP_AUTH"):

    import ldap
    AUTHENTICATION_BACKENDS = (
    'whitetrash.ldapauth.LDAPBackend',
    # 'django.contrib.auth.backends.ModelBackend',
    )
    #LDAP_DEBUG=True
    LDAP_SERVER_URI='ldaps://fqdn.com:636'
    LDAP_SEARCHDN='dc=myorg,dc=lan'
    LDAP_FULL_NAME='uid'
    LDAP_BINDDN = 'ou=people,dc=myorg,dc=lan'
    LDAP_BIND_ATTRIBUTE = 'uid'
    LDAP_OPTIONS = {ldap.OPT_X_TLS_CACERTFILE: "/etc/ssl/ldapcacert.pem"}

