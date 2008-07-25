from django.conf.urls.defaults import *
from whitetrash.whitelist.models import Whitelist

enabled_whitelist = {
	'queryset': Whitelist.objects.filter(enabled=True).order_by("-date_added"),
	'paginate_by': 10,
	'allow_empty': True,
    'template_name': 'whitelist/whitelist_list.html'
}


urlpatterns = patterns('django.views.generic.list_detail',
    #TODO: pagination, I like the Digg style here: http://www.djangosnippets.org/snippets/773/
    (r'viewlist', 'object_list', enabled_whitelist),
)

#http://whitetrash/whitelist/getform/?url=http%3A%2F%2Fwww.lkjsdljsld.com%2F&clientaddr=192.168.1.2&domain=www.lkjsdljsld.com&clientident=-
urlpatterns += patterns('whitetrash.whitelist.views',
    (r'^$', 'index'),
    (r'^addentry/','addentry'),
    (r'^getform/','getform'),
)
    
