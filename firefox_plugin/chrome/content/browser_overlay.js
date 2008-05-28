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
    createMenuItem: function(aPopup,display_domain,domain,uri,protocol,this_class) {

        var item = document.createElement("menuitem"); // create a new XUL menuitem
        item.setAttribute("label", display_domain);
        item.setAttribute("class", this_class);
        item.setAttribute("oncommand", "whitetrashOverlay.addToWhitelist(\""+domain+'","'+protocol+'","'+uri+"\")");
        aPopup.appendChild(item);

    }//createMenuItem
,
    deleteDynamicMenuItems: function(popup) {

        var logger = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
        logger.logStringMessage("Removing domains");
        whitetrashOverlay.domainDupChecker.domains={};
        var dynamic_sep = document.getElementById("dynamic_content_sep");
        while (popup.lastChild != dynamic_sep) {
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
        	var uri=null;
            if (uri = tags[i].getAttribute(attribute)) {

                var domain=null;
                if (domain=domain_re.exec(uri)) {

                    if (!whitetrashOverlay.domainDupChecker.isDup(domain[2])) {
                        logger.logStringMessage("Good domain: "+domain[2]+uri+domain[1]);
                        var	display_domain=this_doc.domain+": "+domain[2];
                        whitetrashOverlay.createMenuItem(wt_sb_menu_popup,display_domain,domain[2],uri,domain[1].toUpperCase(),"menuitem-iconic whitetrash-can");
                    }
                } else {
                    logger.logStringMessage("Bad domain: "+uri);
                }
            }
        }

    }
,
    wrapOnContentLoad: function(ev) {
        whitetrashOverlay.onContentLoad(ev.originalTarget);
    }
,
    onContentLoad: function(doc) {

        var logger = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
        logger.logStringMessage("Parsing content");

        if (doc instanceof HTMLDocument) {

            logger.logStringMessage("domain"+doc.domain);
            if ((doc.body) && (doc.body.innerHTML.length!=null)) {

                var wt_sb_menu_popup = document.getElementById("wt_sb_menu");
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"iframe","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"img","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"script","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"link","href",doc);

            }else {
                logger.logStringMessage("Empty document");
            }
        }
    }
,
    tabChanged: function(ev) {
    	//Known limitation: on tab change I only re-parse the top level window.  If there is remote iframe 
    	//that loads more content from another domain, it won't be in the list.
        var logger = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
        logger.logStringMessage("Tab change");
        var wt_sb_menu_popup = document.getElementById("wt_sb_menu");
        whitetrashOverlay.deleteDynamicMenuItems(wt_sb_menu_popup);
        whitetrashOverlay.onContentLoad(ev.document); 

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
    install: function() {

        window.addEventListener("load", this.listeners.onLoad, false);
        window.addEventListener("DOMContentLoaded", this.wrapOnContentLoad, false);

    }
,
    listeners: {
    
    webProgressListener: {

        QueryInterface: function(aIID)
        {
        if (aIID.equals(Components.interfaces.nsISupportsWeakReference) ||
            aIID.equals(Components.interfaces.nsIObserver) ||
            aIID.equals(Components.interfaces.nsISupports))
            return this;
        throw Components.results.NS_NOINTERFACE;
        },

        STATE_STOP: Components.interfaces.nsIWebProgressListener.STATE_STOP,
        onLocationChange: function(aWebProgress, aRequest, aLocation) {
            const domWindow = aWebProgress.DOMWindow;
            if (domWindow) {
            whitetrashOverlay.tabChanged(domWindow);
            }
        },
        onStatusChange: function() {}, 
        onStateChange: function() {},
        onSecurityChange: function() {}, 
        onProgressChange: function() {}
        },
    
    onLoad: function(ev) {
        window.removeEventListener("load", arguments.callee, false);
        window.addEventListener("unload", whitetrashOverlay.listeners.onUnload, false);
        whitetrashOverlay.listeners.setup(); 
    },

    onUnload: function(ev) {
      window.removeEventListener("unload", arguments.callee, false);
      whitetrashOverlay.listeners.teardown();
      window.browserDOMWindow = null;
      whitetrashOverlay.dispose();
    },
    
    setup: function() {
      
    var logger = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
      var b = getBrowser();
      const nsIWebProgress = Components.interfaces.nsIWebProgress;
      b.addProgressListener(this.webProgressListener, nsIWebProgress.NOTIFY_STATE_WINDOW | nsIWebProgress.NOTIFY_LOCATION);
  
    logger.logStringMessage("setup finished");

    },
      
    teardown: function() {

      var b = getBrowser();
      if (b) {
        b.removeProgressListener(this.webProgressListener);
      }
  
      window.removeEventListener("DOMContentLoaded", this.wrapOnContentLoad, false);
    }
    
  } // END listeners


}//end namespace encapsulation
whitetrashOverlay.install();

