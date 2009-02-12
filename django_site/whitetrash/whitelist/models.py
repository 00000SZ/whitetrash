from django.db import models
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

    def get_protocol_choice(cls,this_string):
        """Return the database short version of the protocol string."""

        for (num,proto_string) in cls.PROTOCOL_CHOICES:
    	    if proto_string == this_string:
    		    return num
    	raise ValueError("No such protocol")

    get_protocol_choice = classmethod(get_protocol_choice)

    whitelist_id=models.AutoField("ID",primary_key=True)
    domain=models.CharField("Domain Name",max_length=70,blank=False)
    date_added=models.DateTimeField(db_index=True,auto_now_add=True,
                            help_text="""If the domain is whitelisted, this timestamp is the time it was added
                            to the whitelist.  If the domain is not whitelisted, it is the time the domain was 
                            first requested.""",blank=False)
    protocol=models.PositiveSmallIntegerField(db_index=True,choices=PROTOCOL_CHOICES,blank=False)
    username=models.CharField("Added By User",max_length=30,db_index=True,blank=False)
    client_ip=models.IPAddressField(db_index=True,blank=False)
    url=models.CharField(max_length=255,blank=True)
    comment=models.CharField(max_length=100,blank=True)
    enabled=models.BooleanField(db_index=True,default=False,help_text="If TRUE the domain is whitelisted",blank=False)
    hitcount=models.PositiveIntegerField(db_index=True,default=0,editable=False,blank=False)
    last_accessed=models.DateTimeField(default=datetime.now(),db_index=True,
                                    help_text="Time this domain was last requested",blank=False,editable=False)

    def save(self,force_insert=False, force_update=False):
        if not self.whitelist_id:
            self.date_added = datetime.now()
        super(Whitelist, self).save(force_insert) 

    class Meta:
        #This is more correct, but it causes problems with form submission
        #I want to be able to enable an existing entry, with this constraint
        #django invalidates my form submission because an entry already exists.
        #unique_together = (("domain", "protocol"),)
        unique_together = (("domain", "protocol","enabled"),)

    def __str__(self):
        return "%s: %s - %s %s %s hits" % (self.whitelist_id,self.get_protocol_display(),self.domain,self.username,self.hitcount)

class WhiteListForm(ModelForm):
    url=CharField(max_length=255,widget=HiddenInput,required=False)
    captcha_response = CharField(max_length=20,required=False)

    def clean_domain(self):

        data = self.cleaned_data['domain']
        try:
            re.match("^([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6}$",data).group()
            return data
        except AttributeError:
            raise ValidationError("Bad domain name.")

    class Meta:
        model = Whitelist 
        fields = ("domain", "protocol", "url", "comment")

