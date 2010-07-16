from django.conf import settings
from django_site.whitetrash.whitelist.models import Whitelist
from django.db.models import Q

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
        """Return true if the domain is whitelisted"""
        lall = Whitelist.get_wildcard_choice("ALL")
        lone =  Whitelist.get_wildcard_choice("ONE")
        return Whitelist.objects.filter(Q(enabled=True,domain=domain,protocol=protocol) | 
                Q(enabled=True,domain=self.all_wildcard(domain),protocol=protocol,wildcard=lall) |
                Q(enabled=True,domain=self.one_label_wildcard(domain),protocol=protocol,wildcard=lone))

