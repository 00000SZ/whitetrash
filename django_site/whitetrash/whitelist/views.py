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
from hashlib import sha1
import datetime
import re
from urllib import unquote
from django_site.whitetrash.wtdomains import WTDomainUtils
from django_site.whitetrash.wtcaptcha import get_captcha_image,check_captcha 
    
try:
    import blacklistcache
except ImportError:
    if settings.SAFEBROWSING:
        settings.LOG.error("Couldn't import blacklistcache, not using safebrowsing")
        raise

def check_login_required(func):
    if settings.LOGIN_REQUIRED:
        return login_required(func)
    else:
        return func

def index(request):
    """Handle a request for the domain with a blank path."""
    return HttpResponsePermanentRedirect("http://%s/whitelist/view/list/" % settings.DOMAIN)


@check_login_required
def show_captcha(request):
    """Return a captcha image."""

    return get_captcha_image(request)

def check_safebrowse(domain,url):
    """Check the url and domain in the google safebrowsing blacklist.
    Not strictly neccessary to check the domain, since it is checked as a component of the url.
    However, whitetrash does not check that the url matches the domain, so we need to check the domain
    too since that is what matters for the whitelist.  The domain and url will never be different if the
    form parameters haven't been tampered with.

    Only check safebrowsing on POST.  Checking on GET will introduce unnecessary load on the server for do benefit,
    especially if there is malware doing a lot of beaconing, generating lots of forms.  Hits against the blacklist will
    still be logged by the redirector.
    
    @return: If it is bad, return redirect to appropriate warning page, if not bad return none"""


    #TODO: why does this need to be a redirect, why not just render to a template?
    blc = blacklistcache.BlacklistCache(settings.CONFIG)
    settings.LOG.debug("Got %s,%s" % (domain,url))
    for check_string in [url,domain]:
        if check_string:
            settings.LOG.debug("Checking %s for badness" % check_string)
            sbresult = blc.check_url(check_string)
            if sbresult:
                if sbresult == blacklistcache.PHISHING:
                    return HttpResponseRedirect("%s%s/whitelist/forgerydomain=%s" % (settings.SERV_PREFIX,settings.DOMAIN,whitetrash_filters.domain(domain)))

                return HttpResponseRedirect("%s%s/whitelist/attackdomain=%s" % (settings.SERV_PREFIX,settings.DOMAIN,whitetrash_filters.domain(domain)))
    return None


@check_login_required
def addentry(request):
    """Add an entry to the whitelist.

    The domain will usually exist since it is created with enabled=False by the redirector the first
    time it is requested.
    """

    if request.method == 'POST':
        #settings.LOG.debug("POST request: %s" % request)
        form = WhiteListForm(request.POST)

        if form.is_valid(): 
            domain = form.cleaned_data['domain']
            protocol = form.cleaned_data['protocol']
            url = form.cleaned_data['url']
            comment = form.cleaned_data['comment']
            src_ip=whitetrash_filters.ip(request.META.get('REMOTE_ADDR'))

            if settings.SAFEBROWSING:
                sbcheck=check_safebrowse(domain,url)
                if sbcheck:
                    settings.LOG.critical("****SAFEBROWSING BLACKLIST WHITELISTING ATTEMPT**** \
                                        from IP:%s for url: %s, domain:%s using protocol:%s"
                                        % (src_ip,url,domain,protocol))
                    return sbcheck

            res = check_captcha(form,request)
            if res:
            	return res

            du = WTDomainUtils()
            (template,dict) = du.add_domain(domain,protocol,url,comment,src_ip,request.user)
            return render_to_response(template,dict,context_instance=RequestContext(request))

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
            if not (proto == Whitelist.get_protocol_choice('HTTP') or proto == Whitelist.get_protocol_choice('HTTPS')):
                proto=Whitelist.get_protocol_choice('HTTP')
        except KeyError:
            proto = Whitelist.get_protocol_choice('HTTP')

        form = WhiteListForm(initial={'url': url,
                            'protocol':proto,
                            'domain':domain})
        
        if (proto==Whitelist.get_protocol_choice('HTTP') and settings.CAPTCHA_HTTP) or \
            (proto==Whitelist.get_protocol_choice('HTTPS') and settings.CAPTCHA_SSL):
            show_captcha=True
        else:
            show_captcha=False

        return render_to_response('whitelist/whitelist_getform.html', {
        'form': form, 'captcha': show_captcha},
        context_instance=RequestContext(request)) 

    #This is the last resort case if form is not valid.
    #Make a best-guess at CAPTCHA requirement (if it is on for HTTP should probably display it)
    return render_to_response('whitelist/whitelist_getform.html', {
        'form': form, 'captcha': settings.CAPTCHA_HTTP},
        context_instance=RequestContext(request)) 

@check_login_required
def limited_object_list(*args, **kwargs):
    """Require login for generic views, display only results owned by the user.
    This view is used to present our delete interface. args[0] is the request object.
    """

    kwargs['queryset']=Whitelist.objects.filter(enabled=True).filter(user=args[0].user).order_by("-date_added")

    return object_list(*args, **kwargs)

@check_login_required
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
                list=Whitelist.objects.filter(pk__in=idlist).filter(user=request.user)
                for obj in list:
                    key = "|".join((obj.domain,str(obj.protocol)))
                    if settings.MEMCACHE.get(key):
                        settings.MEMCACHE.delete(key)
                    obj.delete()
            else:
                Whitelist.objects.filter(pk__in=idlist).filter(user=request.user).delete()


            return render_to_response('whitelist/whitelist_deleted.html', 
                            { 'num_deleted':len(idlist)})
        except:
            return render_to_response('whitelist/whitelist_error.html', 
                            { 'error_text':"Bad domain IDs submitted for delete"})

    return HttpResponsePermanentRedirect("http://%s/whitelist/delete/" % settings.DOMAIN)

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

