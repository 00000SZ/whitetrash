from django.conf.urls.defaults import *
from whitetrash.whitelist.models import Whitelist

enabled_whitelist = {
	'queryset': Whitelist.objects.filter(enabled=True).order_by("-date_added"),
	'paginate_by': 10,
	'allow_empty': True,
    'template_name': 'whitelist/whitelist_list.html'
}

not_enabled_whitelist = {
	'queryset': Whitelist.objects.filter(enabled=False).order_by("-hitcount"),
	'paginate_by': 10,
	'allow_empty': True,
    'template_name': 'whitelist/whitelist_list.html'
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

#http://whitetrash/whitelist/getform/?url=http%3A%2F%2Fwww.lkjsdljsld.com%2F&clientaddr=192.168.1.2&domain=www.lkjsdljsld.com&clientident=-
urlpatterns += patterns('whitetrash.whitelist.views',
    (r'^$', 'index'),
    (r'^addentry/','addentry'),
    (r'^getform/','getform'),
    (r'^delete/$', 'limited_object_list', delete_domains),
)
    
