/**
 * Protect the javascript global namespace!
 * http://blogger.ziesemer.com/2007/10/respecting-javascript-global-namespace.html
 * **/

var whitetrashOverlay=null;

whitetrashOverlay = {

    domainDupChecker: {
        domains: {},
        isDup: function(d) {
            return this.domains[d] || !(this.domains[d] = true);
        }
    }
,
    createMenuItem: function(aPopup,domain,uri,protocol) {

        var item = document.createElement("menuitem"); // create a new XUL menuitem
        item.setAttribute("label", domain);
        item.setAttribute("class", "menuitem-iconic whitetrash-can");
        item.setAttribute("oncommand", "whitetrashOverlay.addToWhitelist(\""+domain+'","'+protocol+'","'+uri+"\")");
        aPopup.appendChild(item);

    }//createMenuItem
,
    deleteDynamicMenuItems: function(popup) {

        var logger = Components.classes["@mozilla.org/consoleservice;1"].
        getService(Components.interfaces.nsIConsoleService);

        logger.logStringMessage("Removing domains");
        whitetrashOverlay.domainDupChecker.domains={};
        var dynamic_sep = document.getElementById("dynamic_content_sep");
        while (popup.lastChild != dynamic_sep) {
            logger.logStringMessage("Removing id: "+popup.lastChild.id);
        	popup.removeChild(popup.lastChild);
        }
    }
,
    parseHTML: function(wt_sb_menu_popup,tag_name,attribute,this_doc) {

        var logger = Components.classes["@mozilla.org/consoleservice;1"].
        getService(Components.interfaces.nsIConsoleService);


        var tags = this_doc.getElementsByTagName(tag_name); 
        domain_re = /^(https?):\/\/(([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6})\//;
        for (var i = 0; i < tags.length; i++) { 
            uri = tags[i].getAttribute(attribute); 
            var domain=null;
            if (domain=domain_re.exec(uri)) {
                if (!whitetrashOverlay.domainDupChecker.isDup(domain[2])) {
                    logger.logStringMessage("Good domain: "+domain[2]+uri+domain[1]);
                    whitetrashOverlay.createMenuItem(wt_sb_menu_popup,domain[2],uri,domain[1].toUpperCase())
                }
            } else {
                logger.logStringMessage("Bad domain: "+uri);
            }
        }

    }
,
    onContentLoad: function(ev) {

        var doc = ev.originalTarget;
        if (doc instanceof HTMLDocument) {

            var logger = Components.classes["@mozilla.org/consoleservice;1"].
            getService(Components.interfaces.nsIConsoleService)

                var wt_sb_menu_popup = document.getElementById("wt_sb_menu");
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"iframe","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"img","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"script","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"link","href",doc);
            
        }

    }
,
    tabChanged: function(ev) {
        var logger = Components.classes["@mozilla.org/consoleservice;1"].
        getService(Components.interfaces.nsIConsoleService)
        logger.logStringMessage("Tab change");
        var wt_sb_menu_popup = document.getElementById("wt_sb_menu");
        whitetrashOverlay.deleteDynamicMenuItems(wt_sb_menu_popup);
    }
,
    addToWhitelist: function(domain,protocol,uri) {
        var http = new XMLHttpRequest();

        http.open("POST", "http://whitetrash/addentry", true);
        //TODO:Fix hard-coded username, remove from form since ignored anyway.
        var params="domain="+domain+"&comment=&url="+escape(uri)+"&user=greg&protocol="+protocol+"&consent=I+Agree";

        //Send the proper header information along with the request
        http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        http.setRequestHeader("Content-length", params.length);
        http.setRequestHeader("Connection", "close");
        http.send(params);
        var tab = getBrowser().mCurrentBrowser;
        var entry=tab.webNavigation.sessionHistory.getEntryAtIndex(tab.webNavigation.sessionHistory.index, false);
        var referrer = entry.QueryInterface(Components.interfaces.nsISHEntry).referrerURI;
        tab.webNavigation.loadURI(tab.webNavigation.currentURI.spec, null, referrer, null, null);
    }
,
    onLoad: function(ev) {
        var logger = Components.classes["@mozilla.org/consoleservice;1"].
        getService(Components.interfaces.nsIConsoleService)
        logger.logStringMessage("Onload fired");
        window.removeEventListener("load", arguments.callee, false);
        var prefs = this.prefService = Components.classes["@mozilla.org/preferences-service;1"]
            .getService(Components.interfaces.nsIPrefService).getBranch("whitetrash.");

        gBrowser.mPanelContainer.addEventListener("TabSelect", this.tabChanged, false);
    }   
,
    install: function() {
        /** Contrary to http://developer.mozilla.org/en/docs/Gecko-Specific_DOM_Events 
         * DOMFrameContentLoaded is not "the same as DOMContentLoaded, but also fired for enclosed frames."
         * it was only giving me empty document objects. 
         * **/
        window.addEventListener("DOMContentLoaded", this.onContentLoad, false);

    	//Don't want to execute too early.  Wait until window has loaded.
        window.addEventListener("load", this.onLoad, false);

    }

}//end namespace encapsulation
whitetrashOverlay.install();

