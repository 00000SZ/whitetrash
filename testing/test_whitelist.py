# -*- coding: iso-8859-15 -*-
"""Whitelist Tests

"""
import unittest
import urllib
from random import random
from base64 import encodestring
from funkload.FunkLoadTestCase import FunkLoadTestCase
from funkload.Lipsum import Lipsum

class whitelist(FunkLoadTestCase):
    """This test uses whitelist.conf.
    
    Note I am assuming that there are no proxy exclusions (ie all requests are sent through the proxy).
    This is bad if you are using browser exclusion lists to serve your stylesheets off internal servers...
    
    """

    def setUp(self):
        """Setting up whitelist test."""
        self.title=self.conf_get('main', 'title')
        self.logd("Setting up test: %s\n" % self.title)
        self.lipsum = Lipsum()

    def test_viewwebpages(self):
        
        nb_time = self.conf_getInt('test_viewwebpages', 'nb_time')
        urls = self.conf_getList('test_viewwebpages', 'urls')
        for i in range(nb_time):
            self.logd('Try %i' % i)
            for url in urls:
                response=self.get("http://"+url, description='Get %s' % url)
                self.assert_(response.body.find("<img")>=0,"URL: %s returned with no <img> tags.  Probably means the request failed." % url)

    def testGetFormNonHTTP(self):
        """Test we are blocking the blocked domain to avoid returning forms that are
        not requests for renderable HTML - e.g. *.jpg"""

        url_404 = self.conf_get('test_404_for_blocked_nonhtml', 'url_404')
        response=self.get(url_404)
        self.assertEquals(response.code,404,"Got %s, should have been 404" % response.code)

        response = self.client.get("https://blockedwhitetrash/empty")
        self.failUnlessEqual(response.status_code, 200)

    def test_viewwhitelist(self):
        """This test is pretty CPU intensive as it parses the whole page each time looking for a /table tag (which is at the very end) to make sure we got a complete page.
        Might be a better way to do this...."""
        
        nb_time = self.conf_getInt('test_viewwhitelist', 'nb_time')
        whitelist_url = self.conf_get('test_viewwhitelist', 'whitelist_url')

        #Add a refresh header to really test the server and proxy caching
        self.addHeader("Cache-Control","max-age=0")

        response=self.get(self.conf_get('test_viewwhitelist', 'not_whitelist_url'), description='Get whitelist')
        self.assertEquals(response.getDOM().getByName('title')[0][0],"Whitetrash: *Not* Whitelist Report","Expected 'Whitetrash: *NOT* Whitelist Report' in HTML title'")
        self.assert_(response.body.find("</table>"),"Page returned with no closing </table>.  We may have got an incomplete table.")

        first_timestamp=""
        for i in range(nb_time):
            self.logd('Try %i' % i)
            #The next step is very slow for large tables, not sure why.  Is fine when using Firefox.
            response=self.get(whitelist_url, description='Get whitelist')
            self.assertEquals(response.getDOM().getByName('title')[0][0],"Whitetrash Whitelist Report","Expected 'Whitetrash Whitelist Report' in HTML title'")
            #Check page is being cached
            timestamp=response.getDOM().getByName('p')[0][0]
            if not first_timestamp:
                first_timestamp=timestamp
            self.assertEquals(timestamp,first_timestamp,"Caching check failed.  Page should not have regenerated.  Timestamp should be %s, but got %s" % (first_timestamp,timestamp))

    def add_pages(self,protocol="HTTP"):

        num_pages = self.conf_getInt('test_addto%swhitelist' % protocol, 'num_pages')
        prefix = self.conf_get('test_addto%swhitelist' % protocol, 'prefix')
        suffix = self.conf_get('test_addto%swhitelist' % protocol, 'suffix')
        
        for i in range(num_pages):
            self.addHeader("Accept","text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
            self.addHeader("Accept-Language","en-us,en;q=0.5")
            self.addHeader("Accept-Encoding","gzip,deflate")
            self.addHeader("Accept-Charset","ISO-8859-1,utf-8;q=0.7,*;q=0.7")
            self.addHeader("Keep-Alive","300")
            self.addHeader("Proxy-Connection","keep-alive")

            page = self.lipsum.getUniqWord(length_min=5,length_max=40)
            self.setHeader("Host","www.%s.com" % page)
            
            if protocol=="HTTP":
                url="http://www."+page+".com"
            elif protocol=="SSL":
                #Funkload picks up that this is SSL by the https identifier, we don't need to tell it explicitly.
                url="https://www."+page+".com"
                
            self.logd('Requesting %s page %i: %s' % (protocol,i,url))
            response=self.get(url, description='Get %s' % url)
            self.assertEquals(response.getDOM().getByName('title')[0][0],"Internet Access Request Form","Expected 'Internet Access Request Form' in HTML title'")
    
            if protocol=="HTTP":
                postparams=[['domain','www.'+page+'.com'],
                        ['comment',urllib.quote_plus(self.lipsum.getSentence())],
                        ['url',urllib.quote_plus(url)],
                        ['protocol',protocol]]

                self.logd('Adding %s page %i: %s' % (protocol,i,postparams))
                response=self.post("http://whitetrash/addentry?",params=postparams,description='Post params:%s' % postparams)

            elif protocol=="SSL":
                #Emulate the actual process here by submitting user=ssl.
                self.logd('Adding %s page %i' % (protocol,i))
                response=self.post("https://whitetrash/addentry?",params=None)

            self.assertEquals(response.getDOM().getByName('title')[0][0],"Access Granted","Expected 'Access Granted' in HTML title'")
            self.assert_(response.body.find(urllib.quote_plus(url))>=0,"URL %s expected but not found in response" % urllib.quote_plus(url))
            self.assert_(response.body.find(self.user)>=0,"Username %s expected but not found in response" % self.user)

    def test_addtoHTTPwhitelist(self):
        self.add_pages(protocol="HTTP")
    
    def test_addtoSSLwhitelist(self):
        #self.add_pages(protocol="SSL")
        pass

if __name__ in ('main', '__main__'):
    unittest.main()



