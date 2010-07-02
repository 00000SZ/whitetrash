from django.db import models
from django.contrib.auth.models import User
from datetime import datetime
from django.forms import ModelForm,HiddenInput,CharField,ValidationError,Widget
from django.conf import settings
import re


class Whitelist(models.Model):
    """Model describes the whitelist.  Contains entries for ALL domains that have ever been requested
    Sites are not whitelisted until the enabled flag is set to true.  This allows us to track malware,
    banner ads etc. that are typically highly requested but never whitelisted."""

    PROTOCOL_CHOICES = (
        (1,'HTTP'),
        (2,'SSL'),
    )

    WILDCARD_CHOICES = (
        (1,'ALL'),
        (2,'ONE'),
        (3,'NONE'),
    )

    def get_protocol_choice(cls,this_string):
        """Return the database short version of the protocol string."""

        for (num,proto_string) in cls.PROTOCOL_CHOICES:
    	    if proto_string == this_string:
    		    return num
        settings.LOG.debug("No such protocol: %s" % this_string)
    	raise ValueError("No such protocol")

    def get_wildcard_choice(cls,this_string):
        """Return the database short version of the wildcard string."""

        for (num,proto_string) in cls.WILDCARD_CHOICES:
    	    if proto_string == this_string:
    		    return num
        settings.LOG.debug("No such wildcard: %s" % this_string)
    	raise ValueError("No such wildcard")

    get_protocol_choice = classmethod(get_protocol_choice)
    get_wildcard_choice = classmethod(get_wildcard_choice)

    whitelist_id=models.AutoField("ID",primary_key=True)
    domain=models.CharField("Domain Name",max_length=70,blank=False)
    wildcard=models.PositiveSmallIntegerField(db_index=True,choices=WILDCARD_CHOICES,blank=False)
    date_added=models.DateTimeField(db_index=True,auto_now_add=True,
           help_text="""If the domain is whitelisted, this timestamp is the time it was added
           to the whitelist.  If the domain is not whitelisted, it is the time the domain was 
           first requested.""",blank=False)
    protocol=models.PositiveSmallIntegerField(db_index=True,choices=PROTOCOL_CHOICES,blank=False)
    user=models.ForeignKey(User,verbose_name="Added By User",db_index=True,blank=False)
    client_ip=models.IPAddressField(db_index=True,blank=False)
    url=models.CharField(max_length=255,blank=True)
    comment=models.CharField(max_length=100,blank=True)
    enabled=models.BooleanField(db_index=True,default=False,help_text="If TRUE the domain is whitelisted",blank=False)
    hitcount=models.PositiveIntegerField(db_index=True,default=0,editable=False,blank=False)
    last_accessed=models.DateTimeField(default=datetime.now(),db_index=True,
                                    help_text="Time this domain was last requested",blank=False,editable=False)

    def save(self,force_insert=False, force_update=False):
        """If this is a new entry add it with timestamp=NOW()
        If we are using memcache, update the memcache entry.  Note
        only existing domains will be added to memcache because we need to 
        store the whitelist id and we don't have it until the entry is in the DB.
        """
        if not self.whitelist_id:
        	#This must be a new entry
            self.date_added = datetime.now()
        super(Whitelist, self).save(force_insert) 
        if settings.MEMCACHE and self.whitelist_id and self.domain and self.protocol:
            settings.MEMCACHE.set("|".join((self.domain,str(self.protocol))),(self.whitelist_id,self.enabled))


    class Meta:
        #This is more correct, but it causes problems with form submission
        #I want to be able to enable an existing entry, with this constraint
        #django invalidates my form submission because an entry already exists.
        #unique_together = (("domain", "protocol"),)
        unique_together = (("domain", "protocol","enabled"),)

    def __str__(self):
        return "%s: %s - %s %s %s hits" % (self.whitelist_id,self.get_protocol_display(),self.domain,self.user.username,self.hitcount)

class WhiteListForm(ModelForm):
    url=CharField(max_length=255,widget=HiddenInput,required=False)
    captcha_response = CharField(max_length=20,required=False)

    def clean_domain(self):
        data = self.cleaned_data['domain']
        try:
            settings.DOMAIN_REGEX.match(data).group()
            if settings.TLD.is_public:
                settings.LOG.debug("Attempt to whitelist public suffix: %s" % data)
                raise ValidationError("Public suffixes cannot be whitelisted.")
            return data
        except AttributeError:
            settings.LOG.debug("Bad domain: %s" % data)
            raise ValidationError("Bad domain name.")

    class Meta:
        model = Whitelist 
        fields = ("domain", "protocol", "url", "comment")

    def clean_url(self):
        """We want to use the URL escaping because it protects us
        from XSS, but unfortunately it screws up our links because it converts
        http: to http%3A.  Use this function to fix this and we are good."""

        try:
            data = re.sub(r"^(https?)%3A",r"\1:",self.cleaned_data['url'])
            return data
        except Exception,e:
            settings.LOG.debug("Bad url: %s" % self.cleaned_data['url'])
            raise ValidationError("Bad url.")

class WhiteListCheckDomainForm(WhiteListForm):
    """Form for checking if a domain is in the whitelist via AJAX."""

    class Meta:
        model = Whitelist 
        fields = ("domain", "protocol")

