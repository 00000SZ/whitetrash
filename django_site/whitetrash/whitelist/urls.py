from django.conf.urls.defaults import *
from whitetrash.whitelist.models import Whitelist

enabled_whitelist = {
	'queryset': Whitelist.objects.filter(enabled=True).order_by("-timestamp"),
	'paginate_by': 10,
	'allow_empty': True
}


urlpatterns = patterns('django.views.generic.list_detail',
    (r'^$', 'object_list', enabled_whitelist),

)
