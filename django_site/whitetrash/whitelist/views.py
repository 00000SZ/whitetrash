#!/usr/bin/env python

from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from whitetrash.whitelist.models import Whitelist,WhiteListForm
from django.http import HttpResponseForbidden
from django.template import loader, Context, RequestContext
from django.views.generic.list_detail import object_list
from django.http import HttpResponsePermanentRedirect
import whitetrash.whitelist.templatetags.whitetrash_filters as whitetrash_filters
from django.template.defaultfilters import force_escape
from django.forms import ValidationError
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
        form = WhiteListForm(initial={'protocol':Whitelist.get_protocol_choice('SSL')})

        c = RequestContext(request,{ 'form':form, 'form_target':'https://whitetrash/whitelist/addentry/' ,'ssl':True})
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

    if request.method == 'POST':
        form = WhiteListForm(request.POST)

        if form.is_valid(): 
            domain = form.cleaned_data['domain']
            protocol = form.cleaned_data['protocol']
            url = form.cleaned_data['url']
            comment = form.cleaned_data['comment']
            src_ip=whitetrash_filters.ip(request.META.get('REMOTE_ADDR'))

            if re.match("^www[0-9]?\.",domain):
    	        # If this is a www domain, strip off the www.
    	        dom_temp=domain
                domain=re.sub("^[a-z0-9-]+\.","",dom_temp,1)

            w,created = Whitelist.objects.get_or_create(domain=domain,protocol=protocol, 
                                defaults={'username':request.user,'url':url,
                                'comment':comment,'enabled':True,'client_ip':src_ip})

            if not url:
                #Handle SSL by refreshing to the domain added
                if protocol=="SSL":
                    url="https://%s" % domain
                else:
                    url="http://%s" % domain

            if not created and w.enabled:
                return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':"Domain already whitelisted."})

            elif not created and not w.enabled:
    	        w.username = request.user
    	        w.url = url
    	        w.comment = comment
    	        w.enabled = True
    	        w.client_ip = src_ip
                w.save()


            return render_to_response('whitelist/whitelist_added.html', 
                                    { 'url':url,'protocol':protocol,'domain':domain,'client_ip':src_ip,'comment':comment, 'ssl':protocol=="SSL" },
                                    context_instance=RequestContext(request)) 

    else:
        #Pre-populate the form
        #Do some quick checks on the pre-population data, if anything fails
        #just present an empty form.
        try:
            url=request.GET["url"]
            domain=whitetrash_filters.domain(request.GET["domain"])
                
        except KeyError:
            url=""
            domain=""
                    
        form = WhiteListForm(initial={'url': url,
                            'protocol':Whitelist.get_protocol_choice('HTTP'),
                            'domain':domain})

    return render_to_response('whitelist/whitelist_getform.html', {
        'form': form, 'form_target':'http://whitetrash/whitelist/addentry/'},
        context_instance=RequestContext(request)) 


@login_required
def limited_object_list(*args, **kwargs):
    """Require login for generic views, display only results owned by the user.
    This view is used to present our delete interface. args[0] is the request object.
    """

    kwargs['queryset']=Whitelist.objects.filter(enabled=True).filter(username=args[0].user).order_by("-date_added")

    return object_list(*args, **kwargs)

@login_required
def delete_entries(request):

    if request.method == 'POST':
    	try:
            idlist = request.POST.getlist("DeleteId")
            #sanitise
            for id in idlist:
        	    int(id)
        	    if id < 0:
        		    raise ValidationError("Bad ID passed")

            Whitelist.objects.filter(pk__in=idlist).filter(username=request.user).delete()
            return render_to_response('whitelist/whitelist_deleted.html', 
                            { 'num_deleted':len(idlist)})
        except:
            return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':"Bad domain IDs submitted for delete"})

    return HttpResponsePermanentRedirect("http://whitetrash/whitelist/delete/")



def error(request):
    error=request.GET["error"]
    return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':error})


