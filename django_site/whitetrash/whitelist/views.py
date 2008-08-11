from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from whitetrash.whitelist.models import Whitelist
from django.http import HttpResponseForbidden
from django.template import loader, Context, RequestContext

def index(request):
    if request.method == 'CONNECT':
        t = loader.get_template('whitelist/whitelist_getform.html')
        #TODO: make this SSL form_target an ssl address so you don't get insecure popup.
        c = Context({ 'protocol':'SSL',
                     'form_target':'http://whitetrash/whitelist/addentry/' })
        resp=HttpResponseForbidden(t.render(c))
        resp["Proxy-Connection"]="close"
        return resp
    else:
        #TODO: Return a whitetrash menu of options, view, add, login, logout
        #This is just a placeholder
        return render_to_response('whitelist/whitelist_added.html')


@login_required
def addentry(request):
    #TODO: sanitise
    url=request.POST["url"]
    protocol=request.POST["protocol"]
    domain=request.POST["domain"]
    comment=request.POST["comment"]
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
    """Lets us require login for generic views"""
    return object_list(*args, **kwargs)

