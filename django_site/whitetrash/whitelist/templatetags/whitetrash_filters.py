#!/usr/bin/env python

from django import template
from django.template.defaultfilters import stringfilter
from whitetrash.whitelist.models import get_protocol_choice
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
def protocol(value):
    try:
        get_protocol_choice(input)
        return input
    except:
        return ""


