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
    """This test uses whitelist.conf."""

    def setUp(self):
        """Setting up whitelist test."""
        self.title=self.conf_get('main', 'title')
        self.logd("Setting up test: %s\n" % self.title)
        self.user = self.conf_get('main', 'proxy_username')
        self.passwd = self.conf_get('main', 'proxy_password')
        self.basic_auth=encodestring(self.user+":"+self.passwd).strip()
        self.lipsum = Lipsum()

    def test_viewwebpages(self):
        # The description should be set in the configuration file
        # begin of test ---------------------------------------------
        nb_time = self.conf_getInt('test_viewwebpages', 'nb_time')
        urls = self.conf_getList('test_viewwebpages', 'urls')

        self.addHeader("Proxy-Authorization","Basic %s" % self.basic_auth)
        for i in range(nb_time):
            self.logd('Try %i' % i)
            for url in urls:
                response=self.get("http://"+url, description='Get %s' % url)
                self.assert_(response.body.find("<img")>=0,"Page returned with no <img> tags.  Probably means the request failed.")


        # end of test -----------------------------------------------

    def test_viewwhitelist(self):
        # The description should be set in the configuration file
        # begin of test ---------------------------------------------
        nb_time = self.conf_getInt('test_viewwhitelist', 'nb_time')
        whitelist_url = self.conf_get('test_viewwhitelist', 'url')
        self.addHeader("Proxy-Authorization","Basic %s" % self.basic_auth)

        #Add a refresh header to really test the server and proxy caching
        self.addHeader("Cache-Control","max-age=0")

        first_timestamp=""
        for i in range(nb_time):
            self.logd('Try %i' % i)
            response=self.get(whitelist_url, description='Get whitelist')
            self.assertEquals(response.getDOM().getByName('title')[0][0],"HTTP Whitelist Report","Expected 'HTTP Whitelist Report' in HTML title'")
            self.assert_(response.body.find("</table>"),"Page returned with no closing </table>.  We may have got an incomplete table.")
            #Check page is being cached
            timestamp=response.getDOM().getByName('p')[0][0]
            if not first_timestamp:
                first_timestamp=timestamp
            self.assertEquals(timestamp,first_timestamp,"Caching check failed.  Page should not have regenerated.  Timestamp should be %s, but got %s" % (first_timestamp,timestamp))

        # end of test -----------------------------------------------

    def test_addtowhitelist(self):
        # The description should be set in the configuration file
        # begin of test ---------------------------------------------
        num_pages = self.conf_getInt('test_addtowhitelist', 'num_pages')
        prefix = self.conf_get('test_addtowhitelist', 'prefix')
        suffix = self.conf_get('test_addtowhitelist', 'suffix')
        
        for i in range(num_pages):
            self.addHeader("Accept","text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
            self.addHeader("Accept-Language","en-us,en;q=0.5")
            self.addHeader("Accept-Encoding","gzip,deflate")
            self.addHeader("Accept-Charset","ISO-8859-1,utf-8;q=0.7,*;q=0.7")
            self.addHeader("Keep-Alive","300")
            self.addHeader("Proxy-Connection","keep-alive")
            self.setHeader("Proxy-Authorization","Basic %s" % self.basic_auth)

            page = self.lipsum.getUniqWord(length_min=5,length_max=40)
            url="http://www."+page+".com"
            self.logd('Requesting page %i: %s' % (i,url))
            response=self.get(url, description='Get %s' % url)
            self.assertEquals(response.getDOM().getByName('title')[0][0],"Internet Access Request Form","Expected 'Internet Access Request Form' in HTML title'")
    
            #Bizzare.  First param gets \r\n appended to the front.  To workaround I added a rubbish param "a".  This will be first as they get ordered alphabetically.
            postparams=[['domain','www.'+page+'.com'],
                        ['user',self.user],
                        ['comment',urllib.quote_plus(self.lipsum.getSentence())],
                        ['url',urllib.quote_plus(url)],
                        ['consent','I+Agree']]
            
            self.logd('Adding page %i: %s' % (i,postparams))
            response=self.post("http://whitelistproxy/",params=postparams,description='Post params:%s' % postparams)
            self.assertEquals(response.getDOM().getByName('title')[0][0],"Access Granted","Expected 'Access Granted' in HTML title'")
            self.assert_(response.body.find(urllib.quote_plus(url))>=0,"URL %s expected but not found in response" % urllib.quote_plus(url))
            self.assert_(response.body.find(self.user)>=0,"Username %s expected but not found in response" % self.user)

        # end of test -----------------------------------------------

    def tearDown(self):
        """Finishing test."""
        self.logd("Teardown test: %s\n" % self.title)


if __name__ in ('main', '__main__'):
    unittest.main()



