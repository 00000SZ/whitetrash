#!/usr/bin/env python

#import unittest
from whitetrash.whitelist.models import Whitelist
#from django.test.client import Client
from django.test import TestCase


class WhitetrashTestCase(TestCase):
    fixtures = ["testing.json"]

    def testIndexRedirect(self):
        response = self.client.get('/')
        self.assertRedirects(response, "http://whitetrash/whitelist/view/list/",
                status_code=301, target_status_code=200)
    
    def testFormNoLogin(self):
        response = self.client.get('/whitelist/getform')
        self.assertRedirects(response, "whitelist/getform/",
                status_code=301, target_status_code=302)

    def testFormLogin(self):
        #TODO fix this - fixtures working?
        self.client.login(username='testuser', password='passwd')

