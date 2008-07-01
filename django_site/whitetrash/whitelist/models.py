from django.db import models

# Create your models here.


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
    #TODO: merge hitcount and maybe notwhitelisted too?
    whitelist_id=models.AutoField("ID",primary_key=True)
    #whitelist_id=models.ForeignKey(Hitcount,primary_key=True)
    domain=models.CharField("Domain Name",maxlength=70)
    timestamp=models.DateTimeField("Date Added",db_index=True,auto_now=True,
                            help_text="""If the domain is whitelisted, this timestamp is the time it was added
                            to the whitelist.  If the domain is not whitelisted, it is the time the domain was 
                            first requested.""")
    protocol=models.PositiveSmallIntegerField(db_index=True,choices=PROTOCOL_CHOICES)
    username=models.CharField("Added By User",maxlength=50,db_index=True)
    originalrequest=models.CharField("Original Request",maxlength=255)
    comment=models.CharField(maxlength=100,blank=True)
    enabled=models.BooleanField(db_index=True,default=False,help_text="If TRUE the domain is whitelisted")

    def save(self):
        whitelist_obj=super(Person, self).save()
        WhitelistHitcount(hitcount_whitelist=whitelist_obj).save()

    class Meta:
        unique_together = (("domain", "protocol"),)

    class Admin:
        list_display=("whitelist_id","enabled","domain","protocol","timestamp","username","originalrequest","comment")
        search_fields=["domain"]
        list_filter=["enabled","timestamp","username","protocol"]
        date_hierarchy="timestamp"

    def __str__(self):
        return "%s: %s - %s %s" % (self.whitelist_id,self.get_protocol_display(),self.domain,self.username)

class WhitelistHitcount(models.Model):
    """Hitcount gets incremented and timestamp updated every time the domain is requested"""

    #hitcount_id=models.AutoField("ID",primary_key=True)
    #hit=models.ForeignKey(Whitelist,primary_key=True)
    hitcount_whitelist = models.OneToOneField(Whitelist, primary_key=True)
    hitcount=models.PositiveIntegerField(db_index=True,default=0)
    timestamp=models.DateTimeField(auto_now=True,db_index=True,help_text="Time this domain was last requested")



