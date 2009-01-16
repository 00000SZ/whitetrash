from django.db import models
from datetime import datetime

# Create your models here.

def get_protocol_choice(string):
    """Return the database short version of the protocol string"""
    choices={'HTTP':1,'SSL':2}
    return choices[string]

class Whitelist(models.Model):
    """Model describes the whitelist.  Contains entries for ALL domains that have ever been requested
    Sites are not whitelisted until the enabled flag is set to true.  This allows us to track malware,
    banner ads etc. that are typically highly requested but never whitelisted."""

    PROTOCOL_CHOICES = (
        (1,'HTTP'),
        (2,'SSL'),
    )
    # would prefer if autofield created unsigned int, but will go with this
    # to get the auto increment.
    whitelist_id=models.AutoField("ID",primary_key=True)
    domain=models.CharField("Domain Name",maxlength=70,blank=False)
    date_added=models.DateTimeField(db_index=True,auto_now_add=True,
                            help_text="""If the domain is whitelisted, this timestamp is the time it was added
                            to the whitelist.  If the domain is not whitelisted, it is the time the domain was 
                            first requested.""",blank=False)
    protocol=models.PositiveSmallIntegerField(db_index=True,choices=PROTOCOL_CHOICES,blank=False)
    username=models.CharField("Added By User",maxlength=30,db_index=True,blank=False)
    original_request=models.CharField(maxlength=255,blank=False)
    comment=models.CharField(maxlength=100,blank=True)
    enabled=models.BooleanField(db_index=True,default=False,help_text="If TRUE the domain is whitelisted",blank=False)
    hitcount=models.PositiveIntegerField(db_index=True,default=0,editable=False,blank=False)
    last_accessed=models.DateTimeField(default=datetime.now(),db_index=True,
                                    help_text="Time this domain was last requested",blank=False)

    def save(self):
        if not self.whitelist_id:
            self.date_added = datetime.now()
        super(Whitelist, self).save() 

    class Meta:
        unique_together = (("domain", "protocol"),)

    class Admin:
        list_display=("whitelist_id","enabled","domain","protocol","date_added","last_accessed","hitcount","username","original_request","comment")
        search_fields=["domain"]
        list_filter=["enabled","date_added","last_accessed","username","protocol"]
        date_hierarchy="date_added"

    def __str__(self):
        return "%s: %s - %s %s %s hits" % (self.whitelist_id,self.get_protocol_display(),self.domain,self.username,self.hitcount)

