#!/usr/bin/env python

from whitetrash.whitelist.models import Whitelist
from django.test import TestCase
from django.conf import settings

class WhitetrashTestGeneral(TestCase):
    fixtures = ["testing.json"]

    def testIndexRedirect(self):
        response = self.client.get('/')
        self.assertRedirects(response, "http://%s/whitelist/view/list/" % settings.DOMAIN,
                status_code=301, target_status_code=200)
    
    def testFormNoLogin(self):
        response = self.client.get('/whitelist/addentry')
        self.assertRedirects(response, "whitelist/addentry/",
                status_code=301, target_status_code=302)

    def testPostLoginRedirect(self):
        """This test only really works (see commented out version) when SSL is disabled,
        because the inbuilt client doesn't have SSL post, and a HTTP post causes a redirect
        to SSL."""
        response = self.client.post("/accounts/login/", {"username":"whitetrashtestuser",
                            "password":"passwd",
                            "next":"/whitelist/addentry/?url=http%3A%2F%2Fwww.testing.com%2F%26domain=www.testing.com"} )
        #self.assertRedirects(response, "whitelist/addentry/?url=http%3A%2F%2Fwww.testing.com%2F%26domain=www.testing.com",
        self.assertRedirects(response, "https://testserver/accounts/login/",
                status_code=301, target_status_code=301)

    def testErrorDisplay(self):
        response = self.client.get("/whitelist/error/")
        self.assertContains(response, 'An error has been logged', status_code=200)
        response = self.client.get("/whitelist/error=something%20url%20encoded")
        self.assertContains(response, 'something url encoded', status_code=200)
        response = self.client.get("/whitelist/error=someth<xss>ing%20url%20encoded")
        self.assertNotContains(response, '<xss>', status_code=200)
        response = self.client.get("/whitelist/error=someth%3Cxssing%20url%20encoded")
        self.assertNotContains(response, '<xss', status_code=200)

class WhitetrashTestSafeBrowsing(TestCase):
    fixtures = ["testing.json"]

    def testAttack(self):
        response = self.client.get("/whitelist/attackdomain/")
        self.assertContains(response, 'This web site has been reported', status_code=200)
        response = self.client.get("/whitelist/attackdomain=slkdfj.com")
        self.assertContains(response, 'This web site at slkdfj.com has been reported', status_code=200)
        response = self.client.get("/whitelist/attackdomain=slkdfj%3Cxss%3Ecom")
        self.assertNotContains(response, '<xss>', status_code=200)

    def testForgery(self):
        response = self.client.get("/whitelist/forgerydomain/")
        self.assertContains(response, 'This web site has been reported', status_code=200)
        response = self.client.get("/whitelist/forgerydomain=slkdfj.com")
        self.assertContains(response, 'This web site at slkdfj.com has been reported', status_code=200)
        response = self.client.get("/whitelist/forgerydomain=slkdfj%3Cxss%3Ecom")
        self.assertNotContains(response, '<xss>', status_code=200)

    def testAddBlacklistedDomain(self):
        """Adding a known bad blacklisted domain should fail if safebrowsing is enabled."""

        if settings.SAFEBROWSING:
            self.client.login(username='whitetrashtestuser', password='passwd')
            response = self.client.post("/whitelist/addentry/", {"url":"http://malware.testing.google.test/testing/malware/",
                            "domain":"malware.testing.google.test",
                            "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
            self.assertRedirects(response, "%s%s/whitelist/attackdomain=malware.testing.google.test" % (settings.SERV_PREFIX,settings.DOMAIN),
                status_code=302, target_status_code=200)
            self.assertFalse(Whitelist.objects.filter(domain="malware.testing.google.test",protocol=Whitelist.get_protocol_choice("HTTP")))

            #Same for SSL
            response = self.client.post("/whitelist/addentry/", {"url":"https://malware.testing.google.test/testing/malware/",
                            "domain":"malware.testing.google.test",
                            "protocol":Whitelist.get_protocol_choice("SSL"),"comment":"testing"} )
            self.assertRedirects(response, "%s%s/whitelist/attackdomain=malware.testing.google.test" % (settings.SERV_PREFIX,settings.DOMAIN),
                status_code=302, target_status_code=200)
            self.assertFalse(Whitelist.objects.filter(domain="malware.testing.google.test",protocol=Whitelist.get_protocol_choice("SSL")))

class WhitetrashTestGetForm(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='whitetrashtestuser', password='passwd')

    def testGetFormHTTP(self):
        response = self.client.get("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/","domain":"sldjflksjdf.com"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, 'name="domain" value="sldjflksjdf.com"', status_code=200)
        self.assertContains(response, 'selected="selected">HTTP', status_code=200)
        self.assertContains(response, 'Client Username: </b>whitetrashtestuser', status_code=200)
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
        self.client.login(username='whitetrashtestuser', password='passwd')

    def testAddHTTP(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/",
                        "domain":"test1.com",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
        self.assertContains(response, "Thank you whitetrashtestuser", status_code=200)
        self.assertTrue(Whitelist.objects.filter(domain="test1.com",protocol=Whitelist.get_protocol_choice("HTTP")))

    def testAddSSL(self):
        response = self.client.post("/whitelist/addentry/", {"url":"",
                        "domain":"test1.com",
                        "protocol":Whitelist.get_protocol_choice("SSL"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_added.html')
        self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
        self.assertContains(response, "Thank you whitetrashtestuser", status_code=200)
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

        if settings.MEMCACHE:
            result=settings.MEMCACHE.get("testing4.com|%s" % Whitelist.get_protocol_choice("HTTP"))
            self.assertTrue(result,"Domain should be present because of the save operation when enabled")
            (id,enabled)=result
            self.assertTrue(enabled,"Domain should be enabled in the memcache")

    def testAlreadyWhitelisted(self):
        response = self.client.post("/whitelist/addentry/", {"url":"",
                        "domain":"testing1.com",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, "Domain already whitelisted", status_code=200)
        self.assertFormError(response, 'form', 'domain', 'Domain already whitelisted.')

    def testAddBadDomain(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/","domain":"test1.invalidtoolong",
                                                            "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertFalse(Whitelist.objects.filter(domain="test1.invalidtoolong",protocol=Whitelist.get_protocol_choice("HTTP")))
        self.assertFormError(response, 'form', 'domain', 'Bad domain name.')

    def testAddLongComment(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/",
                        "domain":"testlong1.com",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),
                        "comment":"hundredandonehundredandonehundredandonehundredandonehundredandonehundredandonehundredandonehundredand"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertFalse(Whitelist.objects.filter(domain="testlong1.com",protocol=Whitelist.get_protocol_choice("HTTP")))
        self.assertFormError(response, 'form', 'comment', 'Ensure this value has at most 100 characters (it has 101).')

    def testAddBadProtocol(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/",
                        "domain":"testbadproto.com",
                        "protocol":78,
                        "comment":"bad"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertFalse(Whitelist.objects.filter(domain="testbadproto.com",protocol=78))
        self.assertFormError(response, 'form', 'protocol', 'Select a valid choice. 78 is not one of the available choices.')

    def testAddBlank(self):
        response = self.client.post("/whitelist/addentry/", {"url":"","domain":""} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertFormError(response, 'form', 'domain', 'This field is required.')
        
    def testAddNoDomain(self):
        response = self.client.post("/whitelist/addentry/", {"url":"http://sdlfjksldfjl"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, 'class="errorlist"', status_code=200)
        self.assertFormError(response, 'form', 'domain', 'This field is required.')

class WhitetrashTestCaptcha(TestCase):
    """Test captcha display.

    It is really annoying to test things that require changes in django.settings.
    I tried this snippet http://www.djangosnippets.org/snippets/1011/ but it didn't work.
    For now will have to leave this commented out and change settings manually. Suck!
    """
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='whitetrashtestuser', password='passwd')

    def testGetFormHTTP(self):
        if settings.CAPTCHA_HTTP:
            response = self.client.get("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/","domain":"sldjflksjdf.com"} )
            self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
            self.assertContains(response, 'name="domain" value="sldjflksjdf.com"', status_code=200)
            self.assertContains(response, 'selected="selected">HTTP', status_code=200)
            self.assertContains(response, 'Client Username: </b>whitetrashtestuser', status_code=200)
            self.assertContains(response, '<input type="hidden" name="url" value="http%3A//sldjflksjdf.com/"', status_code=200)
            self.assertContains(response, '<img id="captchaImage"', status_code=200)
            

class WhitetrashTestDelEntry(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='whitetrashtestuser', password='passwd')

    def testdelMultipleEntries(self):
        self.assertTrue(Whitelist.objects.filter(pk=1))
        self.assertTrue(Whitelist.objects.filter(pk=3))
        response = self.client.post("/whitelist/delete/", {"DeleteId":[1,3]} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_deleted.html')
        self.assertFalse(Whitelist.objects.filter(pk=1))
        self.assertFalse(Whitelist.objects.filter(pk=3))

    def testdelEntryOwnedByDifferentUser(self):
        """ID 2 is owned by a different user, so shouldn't have been deleted."""
        self.assertTrue(len(Whitelist.objects.filter(pk__in=[1,2,3])) == 3)
        response = self.client.post("/whitelist/delete/", {"DeleteId":[1,2,3]} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_deleted.html')
        self.assertFalse(Whitelist.objects.filter(pk=1))
        self.assertTrue(Whitelist.objects.filter(pk=2))
        self.assertFalse(Whitelist.objects.filter(pk=3))

    def testdelBadIds(self):
        """If any IDs are bad, the operation is aborted so ID 1 should still be there"""
        response = self.client.post("/whitelist/delete/", {"DeleteId":"'--"} )
        self.assertTrue(Whitelist.objects.filter(pk=1))
        self.assertTemplateUsed(response, 'whitelist/whitelist_error.html')

    def testdelMultipleEntriesMemcache(self):
        if settings.MEMCACHE:
            self.assertTrue(Whitelist.objects.filter(pk=1))
            self.assertTrue(Whitelist.objects.filter(pk=5))
            id_5_key="testwhitetrash.sf.net|%s" % Whitelist.get_protocol_choice("HTTP")
            settings.MEMCACHE.set(id_5_key,(5,False))
            response = self.client.post("/whitelist/delete/", {"DeleteId":[1,5]} )
            self.assertTemplateUsed(response, 'whitelist/whitelist_deleted.html')
            self.assertFalse(Whitelist.objects.filter(pk=1))
            self.assertFalse(Whitelist.objects.filter(pk=5))

            result=settings.MEMCACHE.get(id_5_key)
            self.assertFalse(result,"Domain should have been removed from memcache")


class WhitetrashTestDomainCheck(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='whitetrashtestuser', password='passwd')

    def testCheckDomainInList(self):
        response = self.client.get("/whitelist/checkdomain/", {"domain":"testing1.com","protocol":Whitelist.get_protocol_choice("HTTP")} )
        self.assertContains(response, "1", status_code=200)

    def testCheckDomainWildcarded(self):
        """If testing.com is in the whitelist, one level of subdomain should be allowed.""" 
        response = self.client.get("/whitelist/checkdomain/", {"domain":"www.testing1.com","protocol":Whitelist.get_protocol_choice("HTTP")} )
        self.assertContains(response, "1", status_code=200)

    def testCheckDomainNotWildcarded(self):
        """If testing.com is in the whitelist, ONLY one level of subdomain should be allowed.""" 
        response = self.client.get("/whitelist/checkdomain/", {"domain":"www.test.testing1.com","protocol":Whitelist.get_protocol_choice("HTTP")} )
        self.assertContains(response, "0", status_code=200)

    def testCheckDomainNotInList(self):
        response = self.client.get("/whitelist/checkdomain/", {"domain":"notinwhitelist.com","protocol":Whitelist.get_protocol_choice("HTTP")} )
        self.assertContains(response, "0", status_code=200)

        response = self.client.get("/whitelist/checkdomain/", {"domain":"testing4.com","protocol":Whitelist.get_protocol_choice("HTTP")} )
        self.assertContains(response, "0", status_code=200)

    def testCheckError(self):
        """Attempt checks with bad domain and bad protocol"""
        response = self.client.get("/whitelist/checkdomain/", {"domain":"testing1.comsdfsds","protocol":Whitelist.get_protocol_choice("HTTP")} )
        self.assertContains(response, "Error", status_code=200)

        response = self.client.get("/whitelist/checkdomain/", {"domain":"testing1.com","protocol":"'"} )
        self.assertContains(response, "Error", status_code=200)


