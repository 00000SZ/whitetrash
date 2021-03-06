from django.contrib import admin
from whitetrash.whitelist.models import Whitelist

class WhitelistAdmin(admin.ModelAdmin):
    list_display=("whitelist_id","enabled","domain","protocol","date_added","last_accessed","hitcount","user","client_ip","url","comment")
    search_fields=["domain"]
    list_filter=["enabled","date_added","last_accessed","user","client_ip","protocol"]
    date_hierarchy="date_added"

admin.site.register(Whitelist, WhitelistAdmin)

