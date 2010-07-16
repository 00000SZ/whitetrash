from django.conf import settings
from whitetrash.whitelist.models import Whitelist
from django.http import HttpResponse

try:
    from Captcha.Visual.Tests import PseudoGimpy
except ImportError:
    if (settings.CAPTCHA_HTTP) or (settings.CAPTCHA_SSL):
        settings.LOG.error("PyCAPTCHA not installed.  Use: easy_install http://pypi.python.org/packages/2.4/P/PyCAPTCHA/PyCAPTCHA-0.4-py2.4.egg")
        raise


def get_captcha_image(request):
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
    safe_solutions = [sha1(s).hexdigest() for s in g.solutions]
    try:
        if len(request.session['captcha_solns']) > 100:
            for (sol,createtime) in request.session['captcha_solns']:
                if ((datetime.datetime.now()-createtime) > 
                    datetime.timedelta(seconds=settings.CAPTCHA_WINDOW_SEC)):
                    request.session['captcha_solns'].remove((sol,createtime))

        settings.LOG.debug("Adding solution:%s to session, number of solutions stored: %s" % 
                                (safe_solutions,len(request.session['captcha_solns'])))
        request.session['captcha_solns'].append((safe_solutions,datetime.datetime.now()))
        #Need explicit save here because we don't add a new element and
        #SESSION_SAVE_EVERY_REQUEST is false
        request.session.save()
    except KeyError:
        request.session['captcha_solns'] = [(safe_solutions,datetime.datetime.now())]
    return response


def check_captcha(form,request):
    """Check the CAPTCHA solution.  If the solution is bad, return a render_to_response (True)
    if the solution is correct, return False"""

    if ((settings.CAPTCHA_HTTP and protocol == Whitelist.get_protocol_choice('HTTP')) or
        (settings.CAPTCHA_SSL and protocol == Whitelist.get_protocol_choice('SSL'))):

        captcha_passed = False 

        settings.LOG.debug("CAPTCHA response: %s" % form.cleaned_data['captcha_response'])
        for (sol,createtime) in request.session['captcha_solns']:
            for thissol in sol:
                if sha1(form.cleaned_data['captcha_response']).hexdigest() == thissol:

                    if ((datetime.datetime.now()-createtime) < 
                        datetime.timedelta(seconds=settings.CAPTCHA_WINDOW_SEC)):
                        request.session['captcha_solns'].remove((sol,createtime))
                        request.session.save()
                        captcha_passed = True
                    else:
                        settings.LOG.debug("CAPTCHA timediff: %s, window: %s " % 
                                    (datetime.datetime.now()-createtime,settings.CAPTCHA_WINDOW_SEC))
                        form._errors["captcha_response"] = ErrorList(["Captcha time window expired."])
                        return render_to_response('whitelist/whitelist_getform.html', {
                            'form': form, 'captcha':True},
                            context_instance=RequestContext(request))
        
        if not captcha_passed:
            settings.LOG.debug("CAPTCHA response '%s' incorrect" % form.cleaned_data['captcha_response'])
            form._errors["captcha_response"] = ErrorList(["Captcha test failed.  Please try again."])
            return render_to_response('whitelist/whitelist_getform.html', {
                'form': form, 'captcha':True},
                context_instance=RequestContext(request))

    return False

