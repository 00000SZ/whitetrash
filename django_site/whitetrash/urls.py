from django.conf.urls.defaults import *

urlpatterns = patterns('',
    # Example:
    # (r'^whitetrash/', include('whitetrash.foo.urls')),
    (r'^whitelist/', include('whitetrash.whitelist.urls')),

    # Uncomment this for admin:
    (r'^admin/', include('django.contrib.admin.urls')),
    (r'^accounts/login/$', 'django.contrib.auth.views.login',{'template_name': 'whitelist/login_form.html'}),
)
