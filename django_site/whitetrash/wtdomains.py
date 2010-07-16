from django.conf import settings
from django_site.whitetrash.whitelist.models import Whitelist
from django.db.models import Q,F
from urlparse import urlparse

class WTDomainUtils():

    def domain_chunk_reverse(self,domain):
        """Generator that outputs cumulative labels of a domain starting
        from the rightmost label."""

        spdom = domain.rsplit(".")
        output = ""
        try:
            while(1):
                chunk = spdom.pop()
                if not output:
                    output = chunk
                else:
                    output = ".".join((chunk,output))
                yield output
        except IndexError:
            pass

    def all_wildcard(self,domain):
        """Strip all subdomains, leaving the 'bare' domain registration.
        The model checking should refuse any domains that are public suffixes
        before this is called."""
        #work backwards until we have a non-public-suffix domain
        for part in self.domain_chunk_reverse(domain):
            if not settings.TLD.is_public(part):
                return part

        raise ValueError("Domain is a public suffix")

    def one_label_wildcard(self,domain):
        """Strip off the first label"""
        dom = domain.split(".",1)[1]
        if settings.TLD.is_public(dom):
            if settings.TLD.is_public(domain):
                raise ValueError("Domain is a public suffix")
            else:
                return domain
        else:
            return dom

    def is_whitelisted(self,domain,protocol):
        """Return true (the queryset) if the domain is whitelisted"""
        lall = Whitelist.get_wildcard_choice("ALL")
        lone =  Whitelist.get_wildcard_choice("ONE")
        return Whitelist.objects.filter(Q(enabled=True,domain=domain,protocol=protocol) | 
                Q(enabled=True,domain=self.all_wildcard(domain),protocol=protocol,wildcard=lall) |
                Q(enabled=True,domain=self.one_label_wildcard(domain),protocol=protocol,wildcard=lone))

    def update_hitcount(self,domain,protocol):
        """Look for matching domains and update all matching entries regardless
        of whether they are enabled or not.
        We are allowing general rules to co-exist with specific ones, e.g:
        images.slashdot.org and *.slashdot.org could both be in the database.
        Hitcount will updated on both entries for the images.slashdot.org domain."""

        lall = Whitelist.get_wildcard_choice("ALL")
        lone =  Whitelist.get_wildcard_choice("ONE")
        return Whitelist.objects.filter(Q(domain=domain,protocol=protocol) | 
                Q(domain=self.all_wildcard(domain),protocol=protocol,wildcard=lall) |
                Q(domain=self.one_label_wildcard(domain),protocol=protocol,wildcard=lone)).update(hitcount = F('hitcount')+1)

    def add_domain(self,domain,protocol,url,comment,src_ip,user):
        #settings.LOG.debug("Checking dom:%s, proto:%s to see if it has been whitelisted by a wildcard" % (domain,protocol))
        qs = self.is_whitelisted(domain,protocol)
        if qs:
            i=qs.get()
            return ('whitelist/whitelist_already_listed.html', 
                    { 'url':url,'domain':i.domain,'client_ip':i.client_ip,
                    'prev_user':i.user, 'date_added': i.date_added }) 

        w,created = Whitelist.objects.get_or_create(domain=domain,protocol=protocol, 
                            defaults={'user':user,'url':url,
                            'comment':comment,'enabled':True,'client_ip':src_ip,
                            'wildcard':Whitelist.get_wildcard_choice(settings.AUTO_WILDCARD)})

        if not url:
            #Handle SSL by refreshing to the domain added
            if protocol == Whitelist.get_protocol_choice('SSL'):
                url="https://%s" % domain
            else:
                url="http://%s" % domain

        if not created and w.enabled:
            #already in the db, so just redirect,
            #show the info in the db but redirect to the new url
            #This often happens if people open tabs with links to same domain.
            return ('whitelist/whitelist_already_listed.html', 
                    { 'url':url,'domain':w.domain,'client_ip':w.client_ip,
                    'prev_user':w.user, 'date_added': w.date_added }) 
            
        elif not created and not w.enabled:
            w.user = user
            w.url = url
            w.comment = comment
            w.enabled = True
            w.client_ip = src_ip
            w.wildcard = Whitelist.get_wildcard_choice(settings.AUTO_WILDCARD)
            w.save()

        return ('whitelist/whitelist_added.html', 
            { 'url':url,'protocol':protocol,'domain':domain,'client_ip':src_ip,'comment':comment}) 


    def _parse_domain(self, url):
        return urlparse(url).netloc.lower()

    def _parse_protocol(self, url):
        return urlparse(url).scheme.lower()

