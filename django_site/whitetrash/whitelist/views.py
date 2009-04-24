#!/usr/bin/env python

from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from whitetrash.whitelist.models import Whitelist,WhiteListForm,WhiteListCheckDomainForm
from django.http import HttpResponseForbidden,HttpResponsePermanentRedirect,HttpResponse,HttpResponseRedirect
from django.template import loader, Context, RequestContext
from django.views.generic.list_detail import object_list
import whitetrash.whitelist.templatetags.whitetrash_filters as whitetrash_filters
from django.template.defaultfilters import force_escape
from django.forms import ValidationError
from django.conf import settings
from django.forms.util import ErrorList
import sha
import datetime
import re

try:
    from Captcha.Visual.Tests import PseudoGimpy
except ImportError:
    print "PyCAPTCHA not installed.  Use: easy_install http://pypi.python.org/packages/2.4/P/PyCAPTCHA/PyCAPTCHA-0.4-py2.4.egg"


def index(request):
    """Handle a request for the domain with a blank path.

    We need to handle CONNECT (SSL) in a special manner as below:

    Browser --CONNECT-->        Squid -------check---------->   url_rewriter
                                Squid <---sslwhitetrash:80--   url_rewriter 

                                Squid ------CONNECT--------->   sslwhitetrash
    Browser <-HTTP redirect---  Squid <---HTTP redirect------   sslwhitetrash
    
    We can't just start doing SSL directly without the proxy in the loop
    since the certificate domain won't match that
    requested by the user.  Can't just return HTTP either since the client asked for
    SSL, unless I send a redirect.  To get
    squid to go out with a connect instead of just client hello we require sslwhitetrash
    to be a cache peer.

    """
    if request.method == 'CONNECT':
        t = loader.get_template('whitelist/whitelist_getform.html')
        resp=HttpResponseRedirect("https://whitetrash/whitelist/addentry/?url=&domain=&protocol=%s" % Whitelist.get_protocol_choice('SSL'))
        resp["Proxy-Connection"]="close"
        return resp
    else:
        return HttpResponsePermanentRedirect("http://whitetrash/whitelist/view/list/")

@login_required
def show_captcha(request):
    """Return a captcha image.
    Can't think of a good way to tie IDs of generated images to the form input field
    Instead timestamp each and have a timeout checked on submission.  
    User could potentially have a large array of captcha solutions per session.
    So will also cull the list here when it gets big.
    """

    response = HttpResponse()
    response['Content-type'] = "image/png"
    g = PseudoGimpy()
    i = g.render()
    i.save(response, "png")
    safe_solutions = [sha.sha(s).hexdigest() for s in g.solutions]
    try:
        if len(request.session['captcha_solns']) > 100:
            for (sol,createtime) in request.session['captcha_solns']:
                if ((datetime.datetime.now()-createtime) > 
                    datetime.timedelta(seconds=settings.CAPTCHA_WINDOW_SEC)):
                    request.session['captcha_solns'].remove((sol,createtime))

        request.session['captcha_solns'].append((safe_solutions,datetime.datetime.now()))
        #Need explicit save here because we don't add a new element and
        #SESSION_SAVE_EVERY_REQUEST is false
        request.session.save()
    except KeyError:
        request.session['captcha_solns'] = [(safe_solutions,datetime.datetime.now())]
    return response

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
            captcha_required = False

            if ((settings.CAPTCHA_HTTP and protocol == Whitelist.get_protocol_choice('HTTP')) or
                (settings.CAPTCHA_SSL and protocol == Whitelist.get_protocol_choice('SSL'))):

                captcha_required = True
                captcha_passed = False 

                for (sol,createtime) in request.session['captcha_solns']:
                    for thissol in sol:
                        if sha.sha(form.cleaned_data['captcha_response']).hexdigest() == thissol:

                            if ((datetime.datetime.now()-createtime) < 
                                datetime.timedelta(seconds=settings.CAPTCHA_WINDOW_SEC)):
                                request.session['captcha_solns'].remove((sol,createtime))
                                request.session.save()
                                captcha_passed = True
                            else:
                                form._errors["captcha_response"] = ErrorList(["Captcha time window expired."])
                                return render_to_response('whitelist/whitelist_getform.html', {
                                    'form': form, 'captcha':True},
                                    context_instance=RequestContext(request)) 
                
                if not captcha_passed:
                    form._errors["captcha_response"] = ErrorList(["Captcha test failed.  Please try again."])
                    return render_to_response('whitelist/whitelist_getform.html', {
                        'form': form, 'captcha':True},
                        context_instance=RequestContext(request)) 

            if re.match("^www[0-9]?\.",domain):
                # If this is a www domain, strip off the www.
                dom_temp=domain
                domain=re.sub("^[a-z0-9-]+\.","",dom_temp,1)

            w,created = Whitelist.objects.get_or_create(domain=domain,protocol=protocol, 
                                defaults={'username':request.user,'url':url,
                                'comment':comment,'enabled':True,'client_ip':src_ip})

            if not url:
                #Handle SSL by refreshing to the domain added
                if protocol == Whitelist.get_protocol_choice('SSL'):
                    url="https://%s" % domain
                else:
                    url="http://%s" % domain

            if not created and w.enabled:
                form._errors["domain"] = ErrorList(["Domain already whitelisted."])
                return render_to_response('whitelist/whitelist_getform.html', {
                    'form': form, 'captcha':captcha_required},
                    context_instance=RequestContext(request)) 

            elif not created and not w.enabled:
                w.username = request.user
                w.url = url
                w.comment = comment
                w.enabled = True
                w.client_ip = src_ip
                w.save()


            return render_to_response('whitelist/whitelist_added.html', 
                                    { 'url':url,'protocol':protocol,'domain':domain,'client_ip':src_ip,'comment':comment},
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

        #If this is SSL, it will come with proto set.  Otherwise assume HTTP.
        try:
            proto=int(request.GET["protocol"])
            if not (proto == Whitelist.get_protocol_choice('HTTP') or proto == Whitelist.get_protocol_choice('SSL')):
                proto=Whitelist.get_protocol_choice('HTTP')
        except KeyError:
            proto = Whitelist.get_protocol_choice('HTTP')

        form = WhiteListForm(initial={'url': url,
                            'protocol':proto,
                            'domain':domain})


    return render_to_response('whitelist/whitelist_getform.html', {
        'form': form, 'captcha':settings.CAPTCHA_HTTP},
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

            if settings.MEMCACHE:
                list=Whitelist.objects.filter(pk__in=idlist).filter(username=request.user)
                for obj in list:
                    key = "|".join((obj.domain,str(obj.protocol)))
                    if settings.MEMCACHE.get(key):
                        settings.MEMCACHE.delete(key)
                    obj.delete()
            else:
                Whitelist.objects.filter(pk__in=idlist).filter(username=request.user).delete()


            return render_to_response('whitelist/whitelist_deleted.html', 
                            { 'num_deleted':len(idlist)})
        except:
            return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':"Bad domain IDs submitted for delete"})

    return HttpResponsePermanentRedirect("http://whitetrash/whitelist/delete/")

def check_domain(request):
    """Ajax request to check if a domain is in the whitelist.

    Returns 1 if the value is in the whitelist, 0 if not, Error and the get request on error.
    Wildcarding of the first label is performed for consistency with www.  wildcarding in redirector.
    """
    if request.method == 'GET':
        form = WhiteListCheckDomainForm(request.GET)

        if form.is_valid(): 
            domain = form.cleaned_data['domain']
            protocol = form.cleaned_data['protocol']
            domain_wild=re.sub("^[a-z0-9-]+\.","",domain,1)
            if (Whitelist.objects.filter(enabled=True,domain=domain,protocol=protocol) or 
                Whitelist.objects.filter(enabled=True,domain=domain_wild,protocol=protocol)):
                return HttpResponse("1")
                #return HttpResponse("{'in_whitelist': 'True'}", mimetype="application/json")
            else:
                return HttpResponse("0")

    return HttpResponse("Error %s" % request.GET)
 
def error(request):
    error=request.GET["error"]
    return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':error})


