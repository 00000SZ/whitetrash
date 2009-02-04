#!/usr/bin/env python

from whitetrash.whitelist.models import Whitelist
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

    def testGetForm(self):
        self.client.login(username='testuser', password='passwd')
        response = self.client.get("/whitelist/getform/", {"url":"http%3A//sldjflksjdf.com/","domain":"sldjflksjdf.com"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, '<input name="domain" id="hostInputText" value="sldjflksjdf.com"', status_code=200)
        self.assertContains(response, 'Protocol: </b>HTTP', status_code=200)
        self.assertContains(response, 'Client Username: </b>testuser', status_code=200)
        self.assertContains(response, '<input type="hidden" name="url" value="http%3A//sldjflksjdf.com/"', status_code=200)

    def testGetFormXSS(self):
        self.client.login(username='testuser', password='passwd')
        response = self.client.get("/whitelist/getform/", 
                    {"url":"http://sldjflksjdf.com/<xss>/\"<xss><b","domain":"sldjflksjdf.com\"<xss><b"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_error.html')
        self.assertNotContains(response, "<xss>", status_code=200)
    
    def testGetFormErrorXSS(self):
        self.client.login(username='testuser', password='passwd')
        response = self.client.get("/whitelist/getform/?\"<xss>")
        self.assertTemplateUsed(response, 'whitelist/whitelist_error.html')
        self.assertNotContains(response, "<xss>", status_code=200)
