from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^whitelist/', include('whitetrash.whitelist.urls')),
    (r'^$', 'whitetrash.whitelist.views.index'),
    (r'^admin/', include('django.contrib.admin.urls')),
    (r'^accounts/login/$', 'django.contrib.auth.views.login',{'template_name': 'whitelist/login_form.html'}),
)
