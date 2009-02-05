from django.contrib import admin
from whitetrash.whitelist.models import Whitelist

class WhitelistAdmin(admin.ModelAdmin):
    list_display=("whitelist_id","enabled","domain","protocol","date_added","last_accessed","hitcount","username","client_ip","original_request","comment")
    search_fields=["domain"]
    list_filter=["enabled","date_added","last_accessed","username","client_ip","protocol"]
    date_hierarchy="date_added"

admin.site.register(Whitelist, WhitelistAdmin)

