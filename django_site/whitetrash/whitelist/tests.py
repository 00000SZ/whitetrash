#!/usr/bin/env python

from whitetrash.whitelist.models import Whitelist
from django.test import TestCase

class WhitetrashTestGeneral(TestCase):
    fixtures = ["testing.json"]

    def testIndexRedirect(self):
        response = self.client.get('/')
        self.assertRedirects(response, "http://whitetrash/whitelist/view/list/",
                status_code=301, target_status_code=200)
    
    def testFormNoLogin(self):
        response = self.client.get('/whitelist/addentry')
        self.assertRedirects(response, "whitelist/addentry/",
                status_code=301, target_status_code=302)

class WhitetrashTestGetForm(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='testuser', password='passwd')

    def testGetFormHTTP(self):
        response = self.client.get("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/","domain":"sldjflksjdf.com"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, 'name="domain" value="sldjflksjdf.com"', status_code=200)
        self.assertContains(response, 'selected="selected">HTTP', status_code=200)
        self.assertContains(response, 'Client Username: </b>testuser', status_code=200)
        self.assertContains(response, '<input type="hidden" name="url" value="http%3A//sldjflksjdf.com/"', status_code=200)

    def testGetFormXSS(self):
        response = self.client.get("/whitelist/addentry/", 
                    {"url":"http://sldjflksjdf.com/<xss>/\"<xss><b","domain":"sldjflksjdf.com\"<xss><b"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        #i.e. domain has been blanked
        self.assertContains(response, 'name="domain" maxlength', status_code=200)
        self.assertNotContains(response, "<xss>", status_code=200)

        #XSS in error message
        response = self.client.get("/whitelist/addentry/?\"<xss>")
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertNotContains(response, "<xss>", status_code=200)

class WhitetrashTestAddEntry(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='testuser', password='passwd')

    def testAddHTTP(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/",
                        "domain":"test1.com",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
        self.assertContains(response, "Thank you testuser", status_code=200)
        self.assertTrue(Whitelist.objects.filter(domain="test1.com",protocol=Whitelist.get_protocol_choice("HTTP")))

    def testAddSSL(self):
        response = self.client.post("/whitelist/addentry/", {"url":"",
                        "domain":"test1.com",
                        "protocol":Whitelist.get_protocol_choice("SSL"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_added.html')
        self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
        self.assertContains(response, "Thank you testuser", status_code=200)
        self.assertTrue(Whitelist.objects.filter(domain="test1.com",protocol=Whitelist.get_protocol_choice("SSL")))

    def testEnableDomain(self):
        response = self.client.post("/whitelist/addentry/", {"url":"",
                        "domain":"testing4.com",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_added.html')
        self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
        self.assertTrue(Whitelist.objects.filter(domain="testing4.com",protocol=Whitelist.get_protocol_choice("HTTP"),enabled=True))
        #Make sure we didn't create a new entry and leave the old one there.
        self.assertFalse(Whitelist.objects.filter(domain="testing4.com",protocol=Whitelist.get_protocol_choice("HTTP"),enabled=False))

    def testAlreadyWhitelisted(self):
        response = self.client.post("/whitelist/addentry/", {"url":"",
                        "domain":"testing1.com",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, "Domain already whitelisted", status_code=200)

    def testAddBadDomain(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/","domain":"test1.invalidtoolong",
                                                            "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, 'class="errorlist"', status_code=200)
        self.assertFalse(Whitelist.objects.filter(domain="test1.invalidtoolong",protocol=Whitelist.get_protocol_choice("HTTP")))

    def testAddBlank(self):
        response = self.client.post("/whitelist/addentry/", {"url":"","domain":""} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, 'class="errorlist"', status_code=200)
        
    def testAddNoDomain(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http://sdlfjksldfjl"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, 'class="errorlist"', status_code=200)

#class WhitetrashTestCaptcha(TestCase):
#    """Test captcha display.

#    It is really annoying to test things that require changes in django.settings.
#    I tried this snippet http://www.djangosnippets.org/snippets/1011/ but it didn't work.
#    For now will have to leave this commented out and change settings manually. Suck!
#    """
#    fixtures = ["testing.json"]

#    def setUp(self):
#        self.client.login(username='testuser', password='passwd')

#    def testGetFormHTTP(self):
#        response = self.client.get("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/","domain":"sldjflksjdf.com"} )
#        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
#        self.assertContains(response, 'name="domain" value="sldjflksjdf.com"', status_code=200)
#        self.assertContains(response, 'selected="selected">HTTP', status_code=200)
#        self.assertContains(response, 'Client Username: </b>testuser', status_code=200)
#        self.assertContains(response, '<input type="hidden" name="url" value="http%3A//sldjflksjdf.com/"', status_code=200)
#        self.assertContains(response, '<img id="captchaImage"', status_code=200)

class WhitetrashTestDelEntry(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='testuser', password='passwd')

    def delMultipleEntries(self):
        self.assertTrue(Whitelist.objects.filter(pk=1))
        self.assertTrue(Whitelist.objects.filter(pk=3))
        response = self.client.post("/whitelist/delete/", {"DeleteId":"1,3"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_deleted.html')
        self.assertFalse(Whitelist.objects.filter(pk=1))
        self.assertFalse(Whitelist.objects.filter(pk=3))

    def delEntryOwnedByDifferentUser(self):
        """ID 2 is owned by a different user, so shouldn't have been deleted."""
        self.assertTrue(len(Whitelist.objects.filter(pk__in=[1,2,3]) == 3))
        response = self.client.post("/whitelist/delete/", {"DeleteId":"1,2,3"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_deleted.html')
        self.assertFalse(Whitelist.objects.filter(pk=1))
        self.assertTrue(Whitelist.objects.filter(pk=2))
        self.assertFalse(Whitelist.objects.filter(pk=3))

    def delBadIds(self):
        """If any IDs are bad, the operation is aborted so ID 1 should still be there"""
        response = self.client.post("/whitelist/delete/", {"DeleteId":"1,'--"} )
        self.assertTrue(Whitelist.objects.filter(pk=1))
        self.assertTemplateUsed(response, 'whitelist/whitelist_error.html')
