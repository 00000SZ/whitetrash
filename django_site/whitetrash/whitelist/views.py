#!/usr/bin/env python

from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from whitetrash.whitelist.models import Whitelist,get_protocol_choice
from django.http import HttpResponseForbidden
from django.template import loader, Context, RequestContext
from django.views.generic.list_detail import object_list
from django.http import HttpResponsePermanentRedirect
import whitetrash.whitelist.templatetags.whitetrash_filters as whitetrash_filters
from django.template.defaultfilters import force_escape
import re

def index(request):
    """Handle a request for the domain with a blank path.

    We need to handle CONNECT (SSL) in a special manner as below:

    Browser --CONNECT-->        Squid -------check---------->   url_rewriter
                                Squid <---sslwhitetrash:80--   url_rewriter 

                                Squid ------CONNECT--------->   sslwhitetrash
    Browser <-HTTP forbidden--  Squid <---HTTP forbidden----   sslwhitetrash
    
    We can't just start doing SSL since the certificate domain won't match that
    requested by the user.  Can't just return HTTP either since the client asked for
    SSL, *except* if there is an error, which is why I send back a forbidden.  To get
    squid to go out with a connect instead of just client hello we require sslwhitetrash
    to be a cache peer.
    """
    if request.method == 'CONNECT':
        t = loader.get_template('whitelist/whitelist_getform.html')
        c = RequestContext(request,{ 'protocol':'SSL',
                     'form_target':'https://whitetrash/whitelist/addentry/', })
        resp=HttpResponseForbidden(t.render(c))
        resp["Proxy-Connection"]="close"
        return resp
    else:
        return HttpResponsePermanentRedirect("http://whitetrash/whitelist/view/list/")


@login_required
def addentry(request):
    """Add an entry to the whitelist.

    The domain will usually exist since it is created with enabled=False by the redirector the first
    time it is requested.
    """
    try:
        url=request.POST["url"]
        protocol=whitetrash_filters.protocol(request.POST["protocol"])
        domain=whitetrash_filters.domain(request.POST["domain"])
        comment=request.POST["comment"]
        src_ip=whitetrash_filters.ip(request.META.get('REMOTE_ADDR'))
    except KeyError:
        return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':"Bad request: url, protocol, domain, and comment required"},
                            context_instance=RequestContext(request))


    if protocol and domain:

        if re.match("^www[0-9]?\.",domain):
    	    # If this is a www domain, strip off the www.
    	    dom_temp=domain
            domain=re.sub("^[a-z0-9-]+\.","",dom_temp,1)

        w,created = Whitelist.objects.get_or_create(domain=domain,protocol=get_protocol_choice(protocol), defaults={'username':request.user,
                                    'original_request':url,'comment':comment,'enabled':True})

        if not url:
            #Handle SSL by refreshing to the domain added
            if protocol=="SSL" and domain:
                url="https://%s" % domain
            elif protocol=="HTTP" and domain:
                url="http://%s" % domain

        if not created:
    	    w.username = request.user
    	    w.url = url
    	    w.comment = comment
    	    w.enabled = True
            w.save()

        return render_to_response('whitelist/whitelist_added.html', 
                                    { 'url':url,'protocol':protocol,'domain':domain,'comment':comment, 'ssl':protocol=="SSL" },
                                    context_instance=RequestContext(request)) 
    else:
        return render_to_response('whitelist/whitelist_error.html', 
                    { 'error_text':"Bad parameters for domain or protocol"},
                    context_instance=RequestContext(request))


@login_required
def getform(request):
    """Return a form for a HTTP request.

    SSL is handled in the index view since the squid redirector just sends CONNECTs to the domain
    without any path information.

    We use the raw url here because it is HTML-sanitised at display time by django.
    """
    try:
        url=request.GET["url"]
        domain=whitetrash_filters.domain(request.GET["domain"])

        if not domain:
            return render_to_response('whitelist/whitelist_error.html', 
                    { 'error_text':"Bad domain"},
                    context_instance=RequestContext(request))
            
    except KeyError:
        return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':"Bad request: url, domain required"},
                            context_instance=RequestContext(request))
        
    return render_to_response('whitelist/whitelist_getform.html', 
                            { 'url':url,'domain':domain,
                            'protocol':'HTTP',
                            'form_target':'http://whitetrash/whitelist/addentry/', 'ssl':domain=="" },
                            context_instance=RequestContext(request))


@login_required
def limited_object_list(*args, **kwargs):
    """Require login for generic views, display only results owned by the user.
    This view is used to present our delete interface. args[0] is the request object.
    """

    kwargs['queryset']=Whitelist.objects.filter(enabled=True).filter(username=args[0].user).order_by("-date_added")

    return object_list(*args, **kwargs)

def error(request):
    error=request.GET["error"]
    return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':error},
                            context_instance=RequestContext(request))


