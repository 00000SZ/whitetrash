from django.conf.urls.defaults import *

urlpatterns = patterns('',
    # Example:
    # (r'^whitetrash/', include('whitetrash.foo.urls')),
    (r'^$', include('whitetrash.whitelist.urls')),

    # Uncomment this for admin:
     (r'^admin/', include('django.contrib.admin.urls')),
)
