from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from whitetrash.whitelist.models import Whitelist,get_protocol_choice
from django.http import HttpResponseForbidden
from django.template import loader, Context, RequestContext
from django.views.generic.list_detail import object_list
from django.http import HttpResponsePermanentRedirect
import re

def index(request):
    if request.method == 'CONNECT':
        t = loader.get_template('whitelist/whitelist_getform.html')
        c = RequestContext(request,{ 'protocol':'SSL',
                     'form_target':'https://whitetrash/whitelist/addentry/' })
        resp=HttpResponseForbidden(t.render(c))
        resp["Proxy-Connection"]="close"
        return resp
    else:
        return HttpResponsePermanentRedirect("http://whitetrash/whitelist/view/list/")


@login_required
def addentry(request):
    #TODO: sanitise
    url=request.POST["url"]
    protocol=request.POST["protocol"]
    domain=request.POST["domain"]
    comment=request.POST["comment"]
    #TODO: initial insert in redirector, then get_or_create here
    #Still might insert a brand-new entry without hitting it first, so handle that.

    if re.match("^www[0-9]?\.",domain):
    	# If this is a www domain, strip off the www.
    	dom_temp=domain
        domain=re.sub("^[a-z0-9-]+\.","",dom_temp,1)

    w=Whitelist(domain=domain,protocol=get_protocol_choice(protocol),username=request.user,
                            original_request=url,comment=comment,enabled=True)
    w.save()
    if not url:
        #Handle SSL by refreshing to the domain added
        if protocol=="SSL" and domain:
            url="https://%s" % domain
        elif protocol=="HTTP" and domain:
            url="http://%s" % domain
    return render_to_response('whitelist/whitelist_added.html', 
                                { 'url':url,'protocol':protocol,'domain':domain,'comment':comment },
                                context_instance=RequestContext(request)) 

@login_required
def getform(request):
    #TODO: santise each
    url=request.GET["url"]
    src_ip=request.GET["clientaddr"]
    domain=request.GET["domain"]
    #return render_to_response('whitelist/whitelist_getform.html', { 'url':url,'src_ip':src_ip,'domain':domain })
    return render_to_response('whitelist/whitelist_getform.html', 
                            { 'url':url,'src_ip':src_ip,'domain':domain,
                            'protocol':'HTTP',
                            'form_target':'http://whitetrash/whitelist/addentry/' },
                            context_instance=RequestContext(request))


@login_required
def limited_object_list(*args, **kwargs):
    """Require login for generic views, display only results owned by the user.
    This view is used to present our delete interface. args[0] is the request object."""

    kwargs['queryset']=Whitelist.objects.filter(enabled=True).filter(username=args[0].user).order_by("-date_added")

    return object_list(*args, **kwargs)

