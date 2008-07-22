# Create your views here.
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from whitetrash.whitelist.models import Whitelist
from django.http import HttpResponseForbidden
from django.template import loader, Context

def index(request):
    if request.method == 'CONNECT':
        t = loader.get_template('whitelist/whitelist_addentry.html')
        c = Context()
        resp=HttpResponseForbidden(t.render(c))
        resp["Proxy-Connection"]="close"
        return resp

@login_required
def addentry(request):
    return render_to_response('whitelist/whitelist_addentry.html')


