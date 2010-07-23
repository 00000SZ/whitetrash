#!/usr/bin/env python

from whitetrash.whitelist.models import Whitelist
from whitetrash.tlds import TLDHelper
from whitetrash.wtdomains import WTDomainUtils
from django.test import TestCase
from django.conf import settings
from django.db.models import Q

import sys
from os.path import join
import os

sys.path.append(join(settings.ROOT,"../../"))
from whitetrash_redir import WTSquidRedirector
from whitetrash_redir import WTSquidRedirectorCached
from whitetrash_cert_server import get_domain,get_cert,get_certfilepath
try:
    import blacklistcache
except ImportError:
    pass


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
        if settings.AUTO_WILDCARD == "ALL":

            response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/",
                            "domain":"www.test1.com",
                            "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
            self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
            self.assertContains(response, "Thank you whitetrashtestuser", status_code=200)
            self.assertTrue(Whitelist.objects.filter(domain="%stest1.com" % settings.ALL_WILD_CHR,protocol=Whitelist.get_protocol_choice("HTTP")))

        elif settings.AUTO_WILDCARD == "ONE_LABEL":

            response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/",
                            "domain":"www.test1.com",
                            "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
            self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
            self.assertContains(response, "Thank you whitetrashtestuser", status_code=200)
            self.assertTrue(Whitelist.objects.filter(domain="%stest1.com" % settings.ONE_WILD_CHR,protocol=Whitelist.get_protocol_choice("HTTP")))

        elif settings.AUTO_WILDCARD == "NONE":

            response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com/",
                            "domain":"www.test1.com",
                            "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
            self.assertContains(response, "Whitetrash: Access Granted", status_code=200)
            self.assertContains(response, "Thank you whitetrashtestuser", status_code=200)
            self.assertTrue(Whitelist.objects.filter(domain="www.test1.com",protocol=Whitelist.get_protocol_choice("HTTP")))



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
        response = self.client.post("/whitelist/addentry/", {"url":"http://anewurl",
                        "domain":"testing1.com",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"anewcomment"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_already_listed.html')
        self.assertContains(response, "http://anewurl", status_code=200)
        #Check we didn't set a new url or comment - the original is intact.
        self.assertTrue(Whitelist.objects.filter(domain="testing1.com",protocol=Whitelist.get_protocol_choice("HTTP"),url="http://testing1.com", comment="to be deleted"))

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

class WhitetrashWildcarding(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.client.login(username='whitetrashtestuser', password='passwd')

    def testWhitelistPublicSuffix(self):

        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//sldjflksjdf.com.au/",
                        "domain":"com.au",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"testing"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_getform.html')
        self.assertContains(response, 'class="errorlist"', status_code=200)
        self.assertFormError(response, 'form', 'domain', "Public suffixes cannot be whitelisted.")

    def testAlreadyWhitelistedWithWildcard(self):

        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//one.wildcardonelabel.com.au/",
                        "domain":"one.wildcardonelabel.com.au",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"anewcomment"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_already_listed.html')
        self.assertContains(response, "http://one.wildcardonelabel.com.au", status_code=200)
        #Check we didn't add a new entry
        self.assertFalse(Whitelist.objects.filter(domain="one.wildcardonelabel.com.au",protocol=Whitelist.get_protocol_choice("HTTP")))
        #Check we didn't set a new url or comment - the original is intact.
        self.assertTrue(Whitelist.objects.filter(domain="wildcardonelabel.com.au",protocol=Whitelist.get_protocol_choice("HTTP"),url="http://wildcardonelabel.com.au",comment="to be deleted"))

        response = self.client.post("/whitelist/addentry/", {"url":"http%3A//one.two.three.wildcardall.com.au/",
                        "domain":"one.two.three.wildcardall.com.au",
                        "protocol":Whitelist.get_protocol_choice("HTTP"),"comment":"anewcomment"} )
        self.assertTemplateUsed(response, 'whitelist/whitelist_already_listed.html')
        self.assertContains(response, "http://one.two.three.wildcardall.com.au", status_code=200)
        #Check we didn't add a new entry
        self.assertFalse(Whitelist.objects.filter(domain="one.two.three.wildcardall.com.au",protocol=Whitelist.get_protocol_choice("HTTP")))
        #Check we didn't set a new url or comment - the original is intact.
        self.assertTrue(Whitelist.objects.filter(domain="wildcardall.com.au",protocol=Whitelist.get_protocol_choice("HTTP"),url="http://wildcardall.com.au",comment="to be deleted"))



class WhitetrashTestWTDomains(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.du = WTDomainUtils()

    def testDomains(self):
        self.tldtester = TLDHelper("effective_tld_names.dat")
        tt= self.tldtester
        self.assertTrue(tt.is_public("com"))
        self.assertTrue(tt.is_public("net"))
        self.assertTrue(tt.is_public("org"))
        self.assertTrue(tt.is_public("info"))
        self.assertTrue(tt.is_public("com.au"))
        self.assertTrue(tt.is_public("co.uk"))
        self.assertTrue(tt.is_public("md.us"))
        self.assertTrue(tt.is_public("us"))
        self.assertTrue(tt.is_public("wa.au"))
        self.assertTrue(tt.is_public("!"))
        self.assertTrue(tt.is_public("*"))
        self.assertTrue(tt.is_public(""))

        self.assertFalse(tt.is_public("linux.conf.au"))
        self.assertFalse(tt.is_public("bit.ly"))
        self.assertFalse(tt.is_public("del.icio.us"))
        self.assertFalse(tt.is_public("act.gov.au"))
        self.assertFalse(tt.is_public("csiro.au"))
        self.assertFalse(tt.is_public("whitetrash.com.au"))
        self.assertFalse(tt.is_public("one.whitetrash.com.au"))
        self.assertFalse(tt.is_public("whitetrash.net.au"))
        self.assertFalse(tt.is_public("whitetrash.co.uk"))
        self.assertFalse(tt.is_public("whitetrash.com"))

    def testWildCardAll(self):
        self.assertEquals(self.du.all_wildcard("a.a.c.us.co.uk.com.au"),"uk.com.au")
        self.assertEquals(self.du.all_wildcard("test.com.au"),"test.com.au")
        self.assertRaises(ValueError,self.du.all_wildcard,"com.au")
        self.assertRaises(ValueError,self.du.all_wildcard,"com")

    def testWildCardOneLabel(self):
        self.assertEquals(self.du.one_label_wildcard("a.a.c.us.co.uk.com.au"),"a.c.us.co.uk.com.au")
        self.assertEquals(self.du.all_wildcard("test.com.au"),"test.com.au")
        self.assertRaises(ValueError,self.du.all_wildcard,"com.au")
        self.assertRaises(ValueError,self.du.all_wildcard,"com")

    def testIsWhitelisted(self):
        self.assertTrue(self.du.is_whitelisted("onelabel.wildcardonelabel.com.au",1)) 
        self.assertTrue(self.du.is_whitelisted("wildcardonelabel.com.au",1)) 
        self.assertFalse(self.du.is_whitelisted("multiple.sub.labels.wildcardonelabel.com.au",1)) 

        self.assertTrue(self.du.is_whitelisted("lots.of.labels.wildcardall.com.au",1)) 
        self.assertTrue(self.du.is_whitelisted("wildcardall.com.au",1)) 
        self.assertTrue(self.du.is_whitelisted("one.wildcardall.com.au",1)) 

    def testUpdateHitcount(self):

        self.du.update_hitcount(domain = "onelabel.wildcardonelabel.com.au", protocol = 1) 
        self.assertEqual(Whitelist.objects.filter(domain="wildcardonelabel.com.au",protocol=1)[0].hitcount,1)

        #check we only incremented "twomatchingrules.com"
        self.du.update_hitcount(domain = "twomatchingrules.com", protocol = 1) 
        self.assertEqual(Whitelist.objects.filter(domain="twomatchingrules.com",protocol=1)[0].hitcount,1)
        self.assertEqual(Whitelist.objects.filter(domain="label.twomatchingrules.com",protocol=1)[0].hitcount,30)

        #check we only incremented "twomatchingrules.com" *and* "label.twomatchingrules.com"
        self.du.update_hitcount(domain = "label.twomatchingrules.com", protocol = 1) 
        self.assertEqual(Whitelist.objects.filter(domain="twomatchingrules.com",protocol=1)[0].hitcount,2)
        self.assertEqual(Whitelist.objects.filter(domain="label.twomatchingrules.com",protocol=1)[0].hitcount,31)

        #try to update non-existent row, check it doesn't exist
        self.du.update_hitcount(domain = "notinthewhitelist.com.au", protocol = 1) 
        self.assertFalse(Whitelist.objects.filter(domain="notinthewhitelist.com.au",protocol=1))
        
        #pass a queryset, ensure we only update the entry passed.
        self.du.update_hitcount(queryset = Whitelist.objects.filter(domain="label.twomatchingrules.com",protocol=1) ) 
        self.assertEqual(Whitelist.objects.filter(domain="label.twomatchingrules.com",protocol=1)[0].hitcount,32)
        self.assertEqual(Whitelist.objects.filter(domain="twomatchingrules.com",protocol=1)[0].hitcount,2)

    def testGetOrCreateDisabled(self):

        #existing disabled domain
        w = self.du.get_or_create_disabled("twomatchingrules.com",1,"http://sdflkjs","10.10.10.10")
        self.assertEqual(w.domain,Whitelist.objects.filter(domain="twomatchingrules.com",protocol=1)[0].domain)

        #new domain
        self.assertTrue(self.du.get_or_create_disabled("notwhitelisted.com",1,"http://sdflkjs","10.10.10.10"))
        self.assertEqual(Whitelist.objects.filter(domain="notwhitelisted.com",protocol=1,enabled=False)[0].hitcount,0)

        #existing enabled domain
        #this shouldn't happen, but in case it does, we want to just increment the hitcount, not create
        #a disabled entry for a domain that is already enabled.
        w = self.du.get_or_create_disabled("wildcardall.com.au",1,"http://sdflkjs","10.10.10.10")
        self.assertEqual(w.hitcount,1)
        self.assertFalse(Whitelist.objects.filter(domain="wildcardall.com.au",protocol=1,enabled=False))




class WhitetrashTestCertServer(TestCase):

    def setUp(self):
        self.config = settings.CONFIG
        get_cert("bugs.launchpad.net")
        testdomains = ["testing.whitetrash.sf.net.wt","whitetrash.sf.net.wt"]
        for dom in testdomains:
            cert = get_certfilepath("*.",dom)
            if os.path.exists(cert):
                os.unlink(cert)

    def testGetDomain(self):
        self.assertEqual(("*.","com.au"),get_domain("blah.com.au"))        
        self.assertEqual(("*.","blah.blah.com.au"),get_domain("blah.blah.blah.com.au"))        
        self.assertEqual(("","blah.com"),get_domain("blah.com"))        

    def testGetCert(self):
        """Check certs get created.  The first label of the domains supplied will be stripped and wildcarded"""

        assert(os.path.exists(self.config["dynamic_certs_dir"]))
        get_cert("blah.testing.whitetrash.sf.net.wt")
        assert(os.path.exists(os.path.join(self.config["dynamic_certs_dir"],"wt/net/sf/whitetrash/star.testing.whitetrash.sf.net.wt.pem")))
        get_cert("whitetrash.sf.net.wt")
        assert(os.path.exists(os.path.join(self.config["dynamic_certs_dir"],"wt/net/star.sf.net.wt.pem")))
        get_cert("launchpad.net")
        assert(os.path.exists(os.path.join(self.config["dynamic_certs_dir"],"net/launchpad.net.pem")))
        get_cert("bugs.launchpad.net")
        assert(os.path.exists(os.path.join(self.config["dynamic_certs_dir"],"net/star.launchpad.net.pem")))


    def testGetCertFilePath(self):
        """Get file path, get_certfilepath assumes first label has already been stripped."""

        self.assertEqual(get_certfilepath("","launchpad.net"),os.path.join(self.config["dynamic_certs_dir"],"net/launchpad.net.pem"))
        self.assertEqual(get_certfilepath("*.","launchpad.net"),os.path.join(self.config["dynamic_certs_dir"],"net/star.launchpad.net.pem"))
        self.assertEqual(get_certfilepath("","whitetrash.sf.net.wt"),os.path.join(self.config["dynamic_certs_dir"],"wt/net/sf/whitetrash.sf.net.wt.pem"))
        self.assertEqual(get_certfilepath("*.","com.au"),os.path.join(self.config["dynamic_certs_dir"],"au/star.com.au.pem"))


class WhitetrashTestSquidRedirector(TestCase):
    fixtures = ["testing.json"]

    def setUp(self):
        self.config = settings.CONFIG
        self.wt_redir=WTSquidRedirector(self.config)

    def testURLParsing(self):

        squid_inputs=[
                        "http://whitetrash.sf.net.wt/ 10.10.9.60/- greg GET",
                        "whitetrash.sf.net.wt:443 10.10.9.60/- greg CONNECT",
                        "http://'or1=1--.com 10.10.9.60/something.com.au - GET",
                        "http://testwhitetrash.sf.net.wt bad baduser 10.10.9.60/- greg GET",
                        "testwhitetrash.sf.net.wt 10.10.9.60/- greg GET",
                        "whitetrash.sf.net.wt:443 10.10.9.60/- greg CO##ECT",
                        "http://whitetrash.sf.aaaanet/ 10.10.9.60/- greg GET",
                        ]
        squid_inputs_results=[True,True,False,False,False,False,False]
        squid_inputs_results_url=["%s://whitetrash/whitelist/addentry?url=http%%3A//whitetrash.sf.net.wt/&domain=whitetrash.sf.net.wt" % self.wt_redir.wtproto,
            "whitetrash.sf.net.wt.sslwhitetrash:3456",
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            "%s://whitetrash/whitelist/error=Bad%%20request%%20logged.%%20%%20See%%20your%%20sysadmin%%20for%%20assistance.\n" % self.wt_redir.wtproto,
            ]

        for i in range(len(squid_inputs)):
            res=self.wt_redir.parseSquidInput(squid_inputs[i])
            self.assertEqual(res,squid_inputs_results[i],
                                    "Got %s, Expected %s for %s" %(res,squid_inputs_results[i],squid_inputs[i]))
            self.assertEqual(self.wt_redir.fail_url,squid_inputs_results_url[i],
                                    "Got %s, Expected %s for %s" %(self.wt_redir.fail_url,
                                    squid_inputs_results_url[i],squid_inputs[i]))


    def testGetWhitelistID(self):
        #Get the ID for an entry we know is whitelisted
        thisid=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "alreadywhitelisted.whitetrash.sf.net.wt","whitetrash.sf.net.wt",wild=False)
        (proto,domain)=self.wt_redir.get_proto_domain(thisid)
        self.assertEqual(proto,self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                        "Got %s, Expected %s for protocol" % (proto,self.wt_redir.PROTOCOL_CHOICES["HTTP"]))
        self.assertEqual(domain,"alreadywhitelisted.whitetrash.sf.net.wt",
                        "Got %s, Expected alreadywhitelisted.whitetrash.sf.net.wt" % (domain))

    def testEnableNonExistantDomainID(self):
        whitelist_id=99999
        test=self.wt_redir.get_proto_domain(whitelist_id)
        self.assertFalse(test,"Tried to pick a whitelist_id that didn't exist (%s), but already in database" % (whitelist_id))
        self.assertRaises(ValueError,lambda: self.wt_redir.enable_domain(whitelist_id))

    def testEnableDomain(self):

        (thisid,enabled)=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "www.disabled.testwhitetrash.sf.net.wt","disabled.testwhitetrash.sf.net.wt",wild=True)
        self.assertFalse(enabled,"This domain was added disabled, should be false")

        #do this twice to exercise memcache
        (thisid,enabled)=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "www.disabled.testwhitetrash.sf.net.wt","disabled.testwhitetrash.sf.net.wt",wild=True)
        self.assertFalse(enabled,"This domain was added disabled, should be false")

        self.wt_redir.enable_domain(thisid)
        (thisid,enabled)=self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                    "www.disabled.testwhitetrash.sf.net.wt","disabled.testwhitetrash.sf.net.wt",wild=True)
        self.assertTrue(enabled,"This domain should be enabled.")

    def testAddToWhitelist(self):
        self.wt_redir.add_to_whitelist("insertme.new.whitetrash.sf.net.wt",
                                        self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                        "http%3A//www.whitetrash.sf.net.wt/FAQ",
                                        "192.168.3.1")

        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                              "insertme.new.whitetrash.sf.net.wt",
                                              "new.whitetrash.sf.net.wt",wild=False):
            self.fail("Domain not added")

        if self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                                "www.new.whitetrash.sf.net.wt","new.whitetrash.sf.net.wt",wild=True):
            self.fail("Should return empty because wild was not inserted")

    def testGetWhitelistID(self):

        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                                "www.testwild.whitetrash.sf.net.wt","testwild.whitetrash.sf.net.wt",wild=True):
            self.fail("Did not return wild whitelist id")
        self.wt_redir.url_domain_only="images.testwild.whitetrash.sf.net.wt"
        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                                "www.testwild.whitetrash.sf.net.wt",
                                                "testwild.whitetrash.sf.net.wt",wild=False):
            self.fail("Did not return whitelist id")

    def testWhitelistCheckingRedirectPOST(self):
        """When receiving a POST for a non-whitelisted domain, redirector should respond
        with a 302: indicating client should go request the form with a GET"""

        self.wt_redir.fail_url=self.wt_redir.http_fail_url
        form=self.wt_redir.http_fail_url+"\n"
        url="http%3A//www.whitetrash.sf.net.wt/FAQ"
        orig_url="http://testwhitetrash.sf.net.wt"
        ip="192.168.1.1"
        method="POST"
        proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        self.wt_redir.auto_add_all=False

        dom="testwhitetrash.sf.net.wt"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,form))

    def testSafeBrowsing(self):
        if self.config["safebrowsing"].upper() == "TRUE":
            url="http%3A//malware.testing.google.test/testing/malware/"
            orig_url="http://malware.testing.google.test/testing/malware/"
            ip="192.168.1.1"
            method="GET"
            proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
            self.wt_redir.auto_add_all=False
            dom="malware.testing.google.test"
            self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),
                                        (False,'302:https://whitetrash/whitelist/attackdomain=malware.testing.google.test\n'))
            proto=self.wt_redir.PROTOCOL_CHOICES["SSL"]
            self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),
                                        (False,'302:https://whitetrash/whitelist/attackdomain=malware.testing.google.test\n'))


    def testSafeBrowsingURL(self):
        url = self.wt_redir.get_sb_fail_url(blacklistcache.PHISHING,"phishing.domain.com")
        self.assertEqual(url,"%s://%s/whitelist/forgerydomain=%s" % 
                                    (self.wt_redir.wtproto,self.config["whitetrash_domain"],"phishing.domain.com"))
        url = self.wt_redir.get_sb_fail_url(blacklistcache.MALWARE,"malware.domain.com")
        self.assertEqual(url,"%s://%s/whitelist/attackdomain=%s" % 
                                    (self.wt_redir.wtproto,self.config["whitetrash_domain"],"malware.domain.com"))
        
    def testWhitelistChecking(self):
        self.wt_redir.fail_url=self.wt_redir.http_fail_url
        form=self.wt_redir.http_fail_url+"\n"
        url="http%3A//www.whitetrash.sf.net.wt/FAQ"
        orig_url="http://testwhitetrash.sf.net.wt"
        ip="192.168.1.1"
        method="GET"
        proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        self.wt_redir.auto_add_all=False

        dom="testwhitetrash.sf.net.wt"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,form),
                        "No testwhitetrash.sf.net.wt domains should be in the whitelist")

        self.wt_redir.auto_add_all=True
        #Auto add is enabled so should always return true
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"))
        dom="www.thing.anothertestwhitetrash.sf.net.wt"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"))

        dom="images.thing.anothertestwhitetrash.sf.net.wt"
        self.wt_redir.auto_add_all=False
        #We added www.thing.anothertestwhitetrash.sf.net.wt so this should be wildcarded
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"))

        dom="testwhitetrash.sf.net.wt"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"),
                        "We added this so it should be true")

        dom="this.another.testwhitetrash.sf.net.wt"
        orig_url="http://testwhitetrash.sf.net.wt/blah.js"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,self.wt_redir.dummy_content_url+"\n"),
                        "The orig_url ends in known non-html content so give back dummy url")

        proto=self.wt_redir.PROTOCOL_CHOICES["SSL"]
        self.wt_redir.fail_url=self.wt_redir.ssl_fail_url
        form=self.wt_redir.ssl_fail_url+"\n"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(False,form),
                        "This domain not whitelisted for SSL so we should get the form")

        self.wt_redir.auto_add_all=True
        dom="ssltestwhitetrash.sf.net.wt"
        self.assertEqual(self.wt_redir.check_whitelist_db(dom,proto,method,url,orig_url,ip),(True,"\n"),
                        "Auto add ssl domain")

        dom="testwhitetrash.sf.net.wt"
        self.wt_redir.auto_add_all=False
        #generate an error by destroying the protocol choices dictionary 
        self.wt_redir.PROTOCOL_CHOICES={}
        self.assertRaises(KeyError,self.wt_redir.check_whitelist_db,dom,proto,method,url,orig_url,ip)


    def testWhitelistCheckingMultipleResults(self):
        """If mozilla.org is in the DB disabled, and wiki.mozilla.org is enabled, multiple entries will be returned by
        our OR query when checking wiki.mozilla.org."""
        proto=self.wt_redir.PROTOCOL_CHOICES["HTTP"]
        dom="sub.testwhitetrash.sf.net.wt"

        wild_id = 9

        subdom_id = 10

        # Check we have 2 results
        # The OR doesn't seem to be deterministic, but there is code addressing this issue in the redirector
        # Just check we always get the subdomain result.
        self.wt_redir.cursor.execute("select whitelist_id,enabled from whitelist_whitelist where protocol=%s and ((domain=%s) or (domain=%s))", (proto,dom,"testwhitetrash.sf.net.wt"))
        res =self.wt_redir.cursor.fetchall()
        self.assertEqual(len(res),2)

        self.assertEqual(self.wt_redir.get_whitelist_id(proto,dom,"testwhitetrash.sf.net.wt",wild=False),(subdom_id,1))

class CachedSquidRedirectorUnitTests(WhitetrashTestSquidRedirector):

    def setUp(self):
        super(CachedSquidRedirectorUnitTests, self).setUp() 
        self.wt_redir=WTSquidRedirectorCached(self.config)
        self.wt_redir.cache.flush_all()

    def testRepeatedGet(self):
        """Make two gets to make sure the cache is used
        The first get will grab from the DB.  The second will grab from the cache, so we want to test that.
        """
        self.testAddToWhitelist()
        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                              "insertme.new.whitetrash.sf.net.wt",
                                              "new.whitetrash.sf.net.wt",wild=False):
            self.fail("Domain insertme.new.whitetrash.sf.net.wt not added")

        if not self.wt_redir.get_whitelist_id(self.wt_redir.PROTOCOL_CHOICES["HTTP"],
                                              "insertme.new.whitetrash.sf.net.wt",
                                              "new.whitetrash.sf.net.wt",wild=False):
            self.fail("Second get failed where first succeeded.  Problem with memcache.")

