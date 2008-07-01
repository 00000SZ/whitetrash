# Create your views here.
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from whitetrash.whitelist.models import Whitelist

@login_required
def addentry(request):
    return render_to_response('whitelist/whitelist_addentry.html')


