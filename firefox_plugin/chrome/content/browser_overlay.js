/**
 * Protect the javascript global namespace!
 * http://blogger.ziesemer.com/2007/10/respecting-javascript-global-namespace.html
 * **/

var whitetrashOverlay=null;

whitetrashOverlay = {

    prefs:null,
    logger:null,
    ss:null,
    whitelist_http: {},
    whitelist_ssl: {},

    domainMenuList: {
        domains: {},
        domainStruct: function(domain,disp_domain,uri,proto) {
        	this.domain=domain;
        	this.disp_domain=disp_domain;
        	this.uri=uri;
        	this.proto=proto;
        	this.printString=this.domain+","+this.disp_domain+","+this.uri+","+this.proto;
        }
        ,
        countDomains: function(hash) {
        	var count=0;
        	for (var i in hash) {
                count+=1;
        	    whitetrashOverlay.logger.logStringMessage("dom:"+hash[i].printString);
            }
            return count;
        }
        ,
        isDup: function(d) {
        	if (this.domains[d]) {
        		return true;
            } else {
            	return false;
            }
        }
        ,
        clearList: function() {
            for (var i in this.domains) {
        	    delete i;
            }
            this.domains={};
        }
        ,
        flattenList: function() {
        	//I would have liked to avoid this string pickling by just storing the object.
        	//Unfortunately the store/restore didn't work properly, even when just doing set
        	//then get straight-away, the object I got back was bad.  Maybe it can't handle
        	//an associative array of objects?
        	whitetrashOverlay.logger.logStringMessage("flattening list");
        	var result="";
            for (var d in this.domains) {
                result+=this.domains[d].printString+"|";
            }
            //Strip the last separator
            return result.substring(0,result.length-1);
        }
        ,
        inflateList: function(flatlist) {
        	this.clearList();
        	var dlist = flatlist.split("|");
        	for (var i = 0; i < dlist.length; i++) {
            	var thisd = dlist[i].split(",");
            	this.storeDomainInfo(thisd[0],thisd[1],thisd[2],thisd[3]);
            }
        }
        ,
        restoreMenu: function() {
        	for (var d in this.domains) {
                whitetrashOverlay.createMenuItem(document.getElementById("wt_sb_menu"),
                                        this.domains[d].disp_domain,this.domains[d].domain,
                                        this.domains[d].uri,this.domains[d].proto,"menuitem-iconic whitetrash-can");
        	}
        }
        ,
        storeDomainInfo: function(domain,disp_domain,uri,proto) {
            this.domains[domain]= new this.domainStruct(domain,disp_domain,uri.replace(",","%2c"),proto);
        	whitetrashOverlay.logger.logStringMessage("storing entry:"+this.domains[domain].printString);
        }
        ,
        saveList: function() {
            var currentTab = getBrowser().selectedTab;
        	var count=this.countDomains(this.domains);
        	if (count!=0) {
        	    whitetrashOverlay.logger.logStringMessage("list length:"+count);
                whitetrashOverlay.ss.setTabValue(currentTab, "whitetrash.test.list",this.flattenList());
        	    whitetrashOverlay.logger.logStringMessage("post save tab state:"+ whitetrashOverlay.ss.getTabState(currentTab));
            } else {
        	    whitetrashOverlay.logger.logStringMessage("not saving empty list");
            }
        }
        ,
        loadList: function() {
            var currentTab = getBrowser().selectedTab;
        	whitetrashOverlay.logger.logStringMessage("current tab:"+currentTab.label);
        	whitetrashOverlay.logger.logStringMessage("current tab state:"+ whitetrashOverlay.ss.getTabState(currentTab));
            var retrievedList = whitetrashOverlay.ss.getTabValue(currentTab, "whitetrash.test.list");
            if (retrievedList) {
            	this.inflateList(retrievedList);
            	this.restoreMenu();
            } else {
                whitetrashOverlay.logger.logStringMessage("ignoring retrieved null list");
            }
        }

    }//end MenuList class
,
    onLoad: function(e,aPopup,display_domain,domain,uri,protocol,this_class) {
    	//Maybe use XML instead?  This way is giving me a javascript syntax error.
        this.logger.logStringMessage(e.responseText);
        var item = document.createElement("menuitem"); // create a new XUL menuitem
        item.setAttribute("label", display_domain);
        item.setAttribute("class", this_class);
        item.setAttribute("oncommand", "whitetrashOverlay.addToWhitelist(\""+domain+'","'+protocol+'","'+uri+"\")");
        aPopup.appendChild(item);

    }
,
    onError: function(e) {
        this.logger.logStringMessage(e.responseText);
    }
,
    checkDomainInWhitelist: function(aPopup,display_domain,domain,uri,protocol,this_class) {
    	//Assuming domain and protocol have already been sanitised.
        var url="http://whitetrash/check_domain?domain="+domain+"&protocol="+protocol
        var req = new XMLHttpRequest();
        req.open("GET", url, false);
        req.onload = this.onLoad(aPopup,display_domain,domain,uri,protocol,this_class);
        req.onerror = this.onError;
        req.send(null);
    }
    ,
    createMenuItem: function(aPopup,display_domain,domain,uri,protocol,this_class) {
    	//Don't display item in the menu if it is already in the whitelist.
        if (protocol=="HTTP") {
    	    if (whitetrashOverlay.whitelist_http[domain]) { return }
    	} else if (protocol=="SSL") {
    	    if (whitetrashOverlay.whitelist_ssl[domain]) { return }
    	} else {
            this.logger.logStringMessage("CreateMenuItem bad protocol: "+protocol);
            return;
    	}

        this.checkDomainInWhitelist(aPopup,display_domain,domain,uri,protocol,this_class);

    }
,
    deleteDynamicMenuItems: function(popup) {

        this.logger.logStringMessage("Removing domains");
        this.domainMenuList.clearList();
        var dynamic_sep = document.getElementById("dynamic_content_sep");
        while (popup.lastChild != dynamic_sep) {
        	popup.removeChild(popup.lastChild);
        }
    }
,
    parseHTML: function(wt_sb_menu_popup,tag_name,attribute,this_doc) {

        var tags = this_doc.getElementsByTagName(tag_name); 
        domain_re = /^(https?):\/\/(([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6})\//;

        for (var i = 0; i < tags.length; i++) { 
        	var uri=null;
            if (uri = tags[i].getAttribute(attribute)) {

                var domain=null;
                if (domain=domain_re.exec(uri)) {

                    if (!whitetrashOverlay.domainMenuList.isDup(domain[2])) {
                        var	display_domain=this_doc.domain+":"+domain[2];
                        whitetrashOverlay.createMenuItem(wt_sb_menu_popup,display_domain,domain[2],uri,domain[1].toUpperCase(),"menuitem-iconic whitetrash-can");

                        whitetrashOverlay.domainMenuList.storeDomainInfo(domain[2],display_domain,uri,domain[1].toUpperCase());
                    }
                } else {
                    this.logger.logStringMessage("Bad domain: "+uri);
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

        this.logger.logStringMessage("Parsing content");

        if (doc instanceof HTMLDocument) {

            try {
            	//This domain check is necessary otherwise we end up parsing rubbish like
            	//Loading... and Untitled empty tabs on every tab changed
            	var valid_domain = doc.domain;
            } catch(e) {
                this.logger.logStringMessage("No domain, ignoring");
            }

            if ((doc.body) && (doc.body.innerHTML.length!=null) && (valid_domain)) {

                this.logger.logStringMessage("Parsing domain:"+doc.domain);
                //TODO: only display options for img and script elements with no content, i.e. they were 404ed
                //maybe only iframes with the form in them?  what about nesting?
                //this way I don't have to keep a list of whitelisted stuff.
                var wt_sb_menu_popup = document.getElementById("wt_sb_menu");
                //Need to do link too because it is used to load css.
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"link","href",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"iframe","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"img","src",doc);
                whitetrashOverlay.parseHTML(wt_sb_menu_popup,"script","src",doc);

                this.domainMenuList.saveList();

            }else {
                this.logger.logStringMessage("Empty document");
            }
        }
    }
,
    tabChanged: function(ev) {
        //Clear the current menu list and load the stored domain list if present.  
        //If this is a new tab the oncontent load listener will build the new list.
        this.logger.logStringMessage("Tab change");
        var wt_sb_menu_popup = document.getElementById("wt_sb_menu");
        whitetrashOverlay.deleteDynamicMenuItems(wt_sb_menu_popup);
        whitetrashOverlay.domainMenuList.loadList()
    }
,
    addToWhitelist: function(domain,protocol,uri) {
        var http = new XMLHttpRequest();

        http.open("POST", "http://whitetrash/addentry", true);
        //TODO:Fix hard-coded username, remove from form since ignored anyway.
        var params="domain="+domain+"&comment=&url="+escape(uri)+"&protocol="+protocol;

        //Send the proper header information along with the request
        http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        http.setRequestHeader("Content-length", params.length);
        http.setRequestHeader("Connection", "close");
        http.send(params);
        var tab = getBrowser().mCurrentBrowser;
        var entry=tab.webNavigation.sessionHistory.getEntryAtIndex(tab.webNavigation.sessionHistory.index, false);
        var referrer = entry.QueryInterface(Components.interfaces.nsISHEntry).referrerURI;
        tab.webNavigation.loadURI(tab.webNavigation.currentURI.spec, null, referrer, null, null);
        this.addToPrefsWhitelist(domain,protocol);
    }
,
    install: function() {
        this.prefs = Components.classes["@mozilla.org/preferences-service;1"]
                        .getService(Components.interfaces.nsIPrefBranch);
        
        this.logger = Components.classes["@mozilla.org/consoleservice;1"]
                                .getService(Components.interfaces.nsIConsoleService);
        this.ss = Components.classes["@mozilla.org/browser/sessionstore;1"].
                             getService(Components.interfaces.nsISessionStore);

        this.loadPrefsWhitelist();
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
        var b = getBrowser();
        const nsIWebProgress = Components.interfaces.nsIWebProgress;
        b.addProgressListener(this.webProgressListener, nsIWebProgress.NOTIFY_STATE_WINDOW | nsIWebProgress.NOTIFY_LOCATION);
    
        whitetrashOverlay.logger.logStringMessage("setup finished");

    },
      
    teardown: function() {

      var b = getBrowser();
      if (b) {
        b.removeProgressListener(this.webProgressListener);
      }
  
      window.removeEventListener("DOMContentLoaded", this.wrapOnContentLoad, false);
    }
    
  } // END listeners
    ,
    splitIntoHash: function(str) {
	    var split_str = str.split("|");
	    var new_list = {};
        for (var i = 0; i < (split_str.length-1); i++) {
            new_list[split_str[i]]=true;
        }
        return new_list;
    }
    ,
    loadPrefsWhitelist: function() {
    	this.whitelist_http=this.splitIntoHash(this.getPref("whitetrash.HTTP.whitelist"));
    	this.whitelist_ssl=this.splitIntoHash(this.getPref("whitetrash.SSL.whitelist"));
    }
    ,
    addToPrefsWhitelist: function(domain,proto) {
    	//Add the domain to a whitelist stored in memory and browser preferences so
    	//we know not to display those domains in the menu.
    	//Problem is if domain is whitelisted, then removed it will not show up.
    	//perhaps don't store in prefs so list is only maintained for browser session?
        this.logger.logStringMessage("adding to prefs:"+domain+proto);
    	var cur=this.getPref("whitetrash."+proto+".whitelist");
    	if (proto=="HTTP") {
    	    this.whitelist_http[domain]=true;
    	} else if (proto=="SSL") {
    	    this.whitelist_ssl[domain]=true;
    	}
    	this.setPref("whitetrash."+proto+".whitelist",cur+=domain+"|");
    }
,
  getPref: function(name, def) {
  	var IPC=Components.interfaces.nsIPrefBranch;
    try {
      switch (this.prefs.getPrefType(name)) {
        case IPC.PREF_STRING:
          return this.prefs.getCharPref(name);
        case IPC.PREF_INT:
          return this.prefs.getIntPref(name);
        case IPC.PREF_BOOL:
          return this.prefs.getBoolPref(name);
      }
    } catch(e) {}
    return def || "";
  }
,
  setPref: function(name, value) {

    switch (typeof(value)) {
      case "string":
          this.prefs.setCharPref(name,value);
          break;
      case "boolean":
        this.prefs.setBoolPref(name,value);
        break;
      case "number":
        this.prefs.setIntPref(name,value);
        break;
      default:
        throw new Error("Unsupported type "+typeof(value)+" for preference "+name);
    }
  }



}//end namespace encapsulation
whitetrashOverlay.install();

