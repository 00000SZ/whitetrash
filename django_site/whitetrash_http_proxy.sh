#!/bin/sh

# Whitetrash uses this in the situation where:
#   1. Recaptcha is enabled; and
#   2. An upstream proxy is in place
# This allows whitetrash to check the captcha result with recaptcha.net
# File to go in /etc/profile.d with root:root 755

#Actually, seems to work better in /etc/apache2/envvars
#not sure which change worked...
export http_proxy="http://whitetrash:3128"

