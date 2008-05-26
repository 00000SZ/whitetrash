/**
 * Protect the javascript global namespace!
 * http://blogger.ziesemer.com/2007/10/respecting-javascript-global-namespace.html
 * **/
var whitetrashOverlay=null;

whitetrashOverlay = {

    createMenuItem: function(aPopup) {

        var domainDupChecker = {
            domains: {},
            check: function(d) {
                return this.domains[d] || !(this.domains[d] = true);
            }
        };
 
        var item = document.createElement("menuitem"); // create a new XUL menuitem
        //whitetrashOverlay.getBlockedDomains();
        var domain="temptest.com";
        if (!domainDupChecker.check(domain)) {
            item.setAttribute("label", domain);
            item.setAttribute("class", "menuitem-iconic whitetrash-can");
            item.setAttribute("oncommand", "whitetrashOverlay.addToWhitelist(\"blah.com\")");
            aPopup.appendChild(item);
        }


    }//createMenuItem
,
    onContentLoad: function() {

        var logger = Components.classes["@mozilla.org/consoleservice;1"].
        getService(Components.interfaces.nsIConsoleService)
        try{
            //var =document.getElementById("host");
            var frames = window.frames; // or // var frames = window.parent.frames;
            logger.logStringMessage("frames.length:"+frames.length);
            for (var i = 0; i < frames.length; i++) { 
            // do something with each subframe as frames[i]
                var wtdomain={};
                logger.logStringMessage("frame "+i+" content:"+frames[i].document.body.innerHTML); 
                if (wtdomain = frames[i].document.getElementById("host")) {
                    alert("ssdf"+wtdomain.innerHTML);
                }
            }

        
        }catch(e){
            try{
                if(e.stack){
                Components.utils.reportError(e.stack);
                }
                // Show the error console.
                toJavaScriptConsole();
            }finally{
                throw e;
            }

        }


    }//getBlockedDomains
,
    addToWhitelist: function(domain) {
        alert('added domain:'+domain);
    }//addToWhitelist
,
    install: function() {
        // this.wt.dump("*** OVERLAY INSTALL ***\n");
        var prefs = this.prefService = Components.classes["@mozilla.org/preferences-service;1"]
            .getService(Components.interfaces.nsIPrefService).getBranch("whitetrash.");
        
        window.addEventListener("DOMFrameContentLoaded", this.onContentLoad, true);
    }

}//end namespace encapsulation
whitetrashOverlay.install();

