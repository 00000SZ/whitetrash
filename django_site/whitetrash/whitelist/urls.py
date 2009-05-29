from django.conf.urls.defaults import *
from whitetrash.whitelist.models import Whitelist

enabled_whitelist = {
    'queryset': Whitelist.objects.filter(enabled=True).order_by("-date_added"),
    'paginate_by': 10,
    'allow_empty': True,
    'template_name': 'whitelist/whitelist_list.html',
    'extra_context': dict(isenabled=True)
}

not_enabled_whitelist = {
    'queryset': Whitelist.objects.filter(enabled=False).order_by("-hitcount"),
    'paginate_by': 10,
    'allow_empty': True,
    'template_name': 'whitelist/whitelist_list.html',
    'extra_context': dict(isenabled=False)
}

delete_domains = {
    #Futher filtering of list in view to display only domains owned by user.
    'queryset': Whitelist.objects.all(),
    'paginate_by': 10,
    'allow_empty': True,
    'template_name': 'whitelist/whitelist_list.html',
    'extra_context': dict(delete_domains=True)
}

urlpatterns = patterns('django.views.generic.list_detail',
    (r'^view/list/$', 'object_list', enabled_whitelist),
    (r'^view/disabledlist/$', 'object_list', not_enabled_whitelist),
)

urlpatterns += patterns('django.views.generic.simple',
    (r'^attackdomain/$',                'direct_to_template', {'template': 'whitelist/sb_web_attack.html',
                            'extra_context': dict(hasdom=False)}),
    (r'^attackdomain\=(?P<domain>.+)$', 'direct_to_template', {'template': 'whitelist/sb_web_attack.html',
                            'extra_context': dict(hasdom=True)}),

    (r'^forgerydomain/$',                'direct_to_template', {'template': 'whitelist/sb_web_forgery.html',
                            'extra_context': dict(hasdom=False)}),
    (r'^forgerydomain\=(?P<domain>.+)$', 'direct_to_template', {'template': 'whitelist/sb_web_forgery.html', 
                            'extra_context': dict(hasdom=True)}),

    (r'^error/$',                'direct_to_template', {'template': 'whitelist/whitelist_error.html',
                            'extra_context': dict(hastext=False)}),
    (r'^error\=(?P<errortext>.+)$', 'direct_to_template', {'template': 'whitelist/whitelist_error.html', 
                            'extra_context': dict(hastext=True)}),

)

urlpatterns += patterns('whitetrash.whitelist.views',
    (r'^$', 'index'),
    (r'^addentry/','addentry'),
    (r'^checkdomain/','check_domain'),
    (r'^captcha/','show_captcha'),
    (r'^deletelist/$', 'limited_object_list', delete_domains),
    (r'^delete/', 'delete_entries'),
)
    
