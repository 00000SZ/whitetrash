#!/usr/bin/env python

from django import template
from django.template.defaultfilters import stringfilter
from whitetrash.whitelist.models import Whitelist
from socket import inet_aton
import re
from urllib import quote

register = template.Library()

@stringfilter
@register.filter
def domain(value):
    try:
        re.match("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$",value).group()
        return value
    except:
        return ""

@stringfilter
@register.filter
def ip(value):
    try:
        inet_aton(value)
        return value
    except:
        return ""

@stringfilter
@register.filter
def quoteall(value):
    """Quote everything between url= and the next parameter, 
    including slashes, but leave the existing %'s."""
    try:
        index_start=value.find("url=")
        index_stop=value.find("&",index_start)
        return "%s%s%s" % (value[:index_start],
                        quote(value[index_start:index_stop],safe="%="),
                        value[index_stop:])
    except:
        return ""

