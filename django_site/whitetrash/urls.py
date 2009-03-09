from django.conf.urls.defaults import *
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    (r'^whitelist/', include('whitetrash.whitelist.urls')),
    (r'^$', 'whitetrash.whitelist.views.index'),
    (r'^admin/(.*)', admin.site.root,{'SSL':True}),
    (r'^accounts/login/$', 'django.contrib.auth.views.login',
                {'template_name': 'whitelist/login_form.html','SSL':True}),
)


