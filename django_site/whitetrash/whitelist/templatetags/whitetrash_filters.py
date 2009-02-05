#!/usr/bin/env python

from django import template
from django.template.defaultfilters import stringfilter
from whitetrash.whitelist.models import Whitelist
from socket import inet_aton
import re

register = template.Library()

@stringfilter
@register.filter
def domain(value):
    try:
        re.match("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$",value).group()
        return value
    except:
        return ""

#FIXME:don't need any of these now since django model is doing the validation?

@stringfilter
@register.filter
def ip(value):
    try:
        inet_aton(input)
        return input
    except:
        return ""

@stringfilter
@register.filter
def protocolnum(value):
    try:
        for (num,proto_string) in Whitelist.PROTOCOL_CHOICES:
    	    if int(num) == int(value):
    		    return int(value)
        return ""
    except:
        return ""

@stringfilter
@register.filter
def protocol(value):
    try:
        if Whitelist.get_protocol_choice(value):
            return value
    except:
        return ""

