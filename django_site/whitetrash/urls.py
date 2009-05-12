from django.conf.urls.defaults import *
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    (r'^whitelist/', include('whitetrash.whitelist.urls')),
    (r'^$', 'whitetrash.whitelist.views.index'),
    (r'^admin/(.*)', admin.site.root,{'SSL':True}),
    (r'^accounts/login/$', 'django.contrib.auth.views.login',
                {'template_name': 'whitelist/login_form.html','SSL':True}),
    (r'^accounts/logout/$', 'django.contrib.auth.views.logout',
                {'template_name': 'whitelist/logout.html','SSL':True}),

)


