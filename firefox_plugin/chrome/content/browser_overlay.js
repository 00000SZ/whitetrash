/**
 * Protect the javascript global namespace!
 * http://blogger.ziesemer.com/2007/10/respecting-javascript-global-namespace.html
 * **/

var whitetrashOverlay=null;

whitetrashOverlay = {

    prefs:null,
    logger:null,
    ss:null,
    wt_protocol: "https",
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
        isDup: function(thislist,d) {
        	if (thislist[d]) {
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
            	this.storeDomainInfo(this.domains,thisd[0],thisd[1],thisd[2],thisd[3]);
            }
        }
        ,
        getArrayElement: function(list) {
        	//Get any element from the list.  This is a bit retarded but
        	//needed to get an element from a dictionary when you don't know any keys.
        	var element;

            for (var i in list) {
            	element=list[i];
            	break;
            }

            return element;
        }
        ,
        restoreMenu: function() {
        	//Restore menu list from list of saved domains
        	var popup = document.getElementById("wt_sb_menu");
            var trim;

            //We leave all the historical domains in the list and only display
            //the relevant ones, but if the list gets big we trim it down.
            //It is possible that the list could get pretty big if the user visits
            //many sites in a single tab without clicking the menu icon.
            //FIXME: could do this check in the page parser and trim the array there?
            if (this.countDomains(this.domains) > 50) {trim="true";}

        	for (var dom in this.domains) {
                whitetrashOverlay.createMenuItem(popup,
                                        this.domains[dom].disp_domain,this.domains[dom].domain,
                                        this.domains[dom].uri,this.domains[dom].proto,trim);
        	}
        	if (trim) {this.saveList(getBrowser().selectedTab);}
        }
        ,
        storeDomainInfo: function(domainlist,domain,disp_domain,uri,proto) {
        	//Shouldn't the key be by protocol too???
            domainlist[domain]= new this.domainStruct(domain,disp_domain,uri.replace(",","%2c"),proto);
        }
        ,
        saveList: function(tab) {
        	var count=this.countDomains(this.domains);
        	if (count!=0) {
        	    whitetrashOverlay.logger.logStringMessage("list length:"+count);
                whitetrashOverlay.ss.setTabValue(tab, "whitetrash.domain.list",this.flattenList());
        	    whitetrashOverlay.logger.logStringMessage("post save tab state:"+ whitetrashOverlay.ss.getTabState(tab));
            } else {
        	    whitetrashOverlay.logger.logStringMessage("deleting empty list");
                whitetrashOverlay.ss.deleteTabValue(tab, "whitetrash.domain.list");
            }
        }
        ,
        loadList: function(tab) {
        	whitetrashOverlay.logger.logStringMessage("current tab state:"+ whitetrashOverlay.ss.getTabState(tab));
            var retrievedList = whitetrashOverlay.ss.getTabValue(tab, "whitetrash.domain.list");
            if (retrievedList) {
            	this.inflateList(retrievedList);
                this.restoreMenu();
            } else {
                whitetrashOverlay.logger.logStringMessage("ignoring retrieved null list");
            }
        }

    }//end MenuList class
,
    onError: function(e) {
        this.logger.logStringMessage(e.responseText);
    }
,
    checkDomainInWhitelist: function(aPopup,display_domain,domain,uri,protocol) {
    	//Currently I am caching whitelisted entries for the duration of the session.  See addtoPrefsWhitelist
    	//if you want to cache across sessions.  Non-whitelisted domains are checked when the user clicks the menu
    	//Assuming domain and protocol have already been sanitised.
    	
    	//Add element disabled, then enable asynchronously when XMLhttprequest returns
	    this.addDisabledMenuItem(aPopup,display_domain,domain,uri,protocol,"menuitem-iconic whitetrash-can");

        var url=this.wt_protocol+"://whitetrash/whitelist/checkdomain?domain="+domain+"&protocol="+protocol
        var pagetab = getBrowser().selectedTab;
        var req = new XMLHttpRequest();
        req.open("GET", url, true);

        req.onreadystatechange = function () {
            if (req.readyState == 4) {
        	    if(req.status == 200) {
                    whitetrashOverlay.logger.logStringMessage("domain: "+domain+", resp: "+req.responseText);

                    var disableditem = document.getElementById(domain+protocol);
        	    	if (req.responseText=="0") {

                        //Check this is still our original tab, if the user has moved on we shouldn't
                        //be displaying domains from other tabs.
                        var newcurrentTab = getBrowser().selectedTab;
                        if (newcurrentTab == pagetab) {
                            disableditem.setAttribute("disabled","false");
                        }

                    } else if (req.responseText=="1") {
                    	//Add to our session whitelist
                        whitetrashOverlay.addToPrefsWhitelist(domain,protocol);
                        disableditem.setAttribute("class","menuitem-iconic whitetrash-can-tick");
                    } else {
                        whitetrashOverlay.logger.logStringMessage("Error checking domain: "+req.responseText);
                    }

                }else{
                    whitetrashOverlay.logger.logStringMessage(req.responseText);
                }
            }
        };
        req.send(null);
    }
,
    addDisabledMenuItem: function(aPopup,display_domain,domain,uri,protocol,this_class) {
    	var item = document.createElement("menuitem"); // create a new XUL menuitem
        item.setAttribute("label", display_domain);
        item.setAttribute("id", domain+protocol);
        item.setAttribute("class",this_class);
        item.setAttribute("disabled", "true");
        item.setAttribute("oncommand", "whitetrashOverlay.addToWhitelist(\""+domain+'","'+protocol+'","'+uri+"\")");
        aPopup.appendChild(item);
    }
,
    createMenuItem: function(aPopup,display_domain,domain,uri,protocol,trim_list) {
        var new_domain = getBrowser().currentURI.host;

        //Only display menuitem if it is for the current domain in the tab
        if (display_domain.split(":")[0]==new_domain) {

    	    //Display ticks for domains already in the whitelist.
            if (protocol==this.getProtocolCode("HTTP")) {
    	        if (whitetrashOverlay.whitelist_http[domain]) { 
                    this.addDisabledMenuItem(aPopup,display_domain,domain,uri,
                                        protocol,"menuitem-iconic whitetrash-can-tick");
    	    	    return }
    	    } else if (protocol==this.getProtocolCode("SSL")) {
    	        if (whitetrashOverlay.whitelist_ssl[domain]) { 
    	    	    this.addDisabledMenuItem(aPopup,display_domain,domain,uri,
                                        protocol,"menuitem-iconic whitetrash-can-tick");
    	    	    return }

    	    } else {
                this.logger.logStringMessage("CreateMenuItem bad protocol: "+protocol);
                return;
    	    }

            this.checkDomainInWhitelist(aPopup,display_domain,domain,uri,protocol);

        } else {

            if (trim_list){
                //whitetrashOverlay.logger.logStringMessage("removing from array"+display_domain);
                delete this.domainMenuList.domains[domain];
            } else {
                whitetrashOverlay.logger.logStringMessage("not displaying"+display_domain);
            }
        }

    }
,
    deleteDynamicMenuItems: function(popup) {

        this.domainMenuList.clearList();
        var dynamic_sep = document.getElementById("dynamic_content_sep");
        while (popup.lastChild != dynamic_sep) {
        	popup.removeChild(popup.lastChild);
        }
    }
,
    getProtocolCode: function(stringname) {
        if (stringname == "HTTP") {
        	return 1;
        } else if (stringname == "SSL") {
            return 2;
        } else {
        	return -1;
        }
    }
,
    parseHTML: function(wt_sb_menu_popup,tag_name,attribute,this_doc) {
    	//Parse HTML, add domains to the whitelist in the relevant tab.
    	//There may be a locking problem here since this is called asynchronously on content load
    	//A page with lots of iframes may cause conflict over the session store for whitetrash.domain.list

        var tags = this_doc.getElementsByTagName(tag_name); 
        //The normal case is uri = "http://www.iinet.net.au/index.html"
        //which results in (http://www.iinet.net.au/,http:,http,www.iinet.net.au,net)
        //however we also handle these because people use them, we assume http for each case:
        //"//www.iinet.net.au/index.html" gives (http://www.iinet.net.au/,,,www.iinet.net.au,net)
        //"/www.iinet.net.au/index.html" gives (http://www.iinet.net.au/,,,www.iinet.net.au,net)
        //"www.iinet.net.au/index.html" gives (http://www.iinet.net.au/,,,www.iinet.net.au,net)
        domain_re = /^((https?):)?\/?\/?(([a-z0-9-]{1,50}\.){1,6}[a-z]{2,6})\//;

        //Check this event was for the current tab:
        var targetBrowserIndex = getBrowser().getBrowserIndexForDocument(this_doc);
        
        //handle the case where there was no tab associated with the request (rss, etc)
        if (targetBrowserIndex != -1) {

            var thistab = gBrowser.tabContainer.childNodes[targetBrowserIndex];
            var tabWhitelistData = this.ss.getTabValue(thistab, "whitetrash.domain.list");
            if (tabWhitelistData!=""){
            	//If the list already has something in it, we'll need a pipe.
            	tabWhitelistData+="|";
            }
            var domainslist = {};

            for (var i = 0; i < tags.length; i++) { 
        	    var uri=null;
                if (uri = tags[i].getAttribute(attribute)) {

                    var domain=null;
                    if (domain=domain_re.exec(uri.toLowerCase())) {

                        if (domain[2]) {
                            var proto = this.getProtocolCode(domain[2].toUpperCase());
                        }else{
                        	//assume http if it isn't explicit
                            var proto = this.getProtocolCode("HTTP");
                        }
                        var thedomain = domain[3];

                        if (proto!= -1) {

                            if (!whitetrashOverlay.domainMenuList.isDup(domainslist,thedomain)) {

                                var	display_domain=this_doc.domain+":"+thedomain;
                                tabWhitelistData+=thedomain+","+display_domain+","+escape(uri)+","+proto+"|";
                                whitetrashOverlay.domainMenuList.storeDomainInfo(domainslist,thedomain,display_domain,uri,proto);
                            }
                        } else {
                            this.logger.logStringMessage("Bad protocol: "+uri);
                        }
                    } else {
                        this.logger.logStringMessage("Bad domain: "+uri);
                    }
                }
            }

            //Strip off the last pipe and save.
            //this.logger.logStringMessage("Whitelistdata final: "+tabWhitelistData.substring(0,tabWhitelistData.length-1));
            this.ss.setTabValue(thistab, "whitetrash.domain.list",tabWhitelistData.substring(0,tabWhitelistData.length-1));
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

            }else {
                this.logger.logStringMessage("Empty document");
            }
        }
    }
,
    reloadMenu: function() {
        //Clear the current menu list and load the stored domain list if present.  
        //If this is a new tab the oncontent load listener will build the new list.
        this.logger.logStringMessage("Reloading Menu");
        var wt_sb_menu_popup = document.getElementById("wt_sb_menu");
        whitetrashOverlay.deleteDynamicMenuItems(wt_sb_menu_popup);
        whitetrashOverlay.domainMenuList.loadList(getBrowser().selectedTab);
    }
,
    addToWhitelist: function(domain,protocol,uri) {
        var http = new XMLHttpRequest();

        http.open("POST", this.wt_protocol+"://whitetrash/whitelist/addentry/", true);
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
    
        onLoad: function(ev) {
    	    //Install our listener that will cleanup on unload
    	    //Remove the load listener so we only run once.
            window.removeEventListener("load", arguments.callee, false);
            window.addEventListener("unload", whitetrashOverlay.listeners.onUnload, false);
        },

        onUnload: function(ev) {
    	    //cleanup
    	    //Remove the unload listener, so we only run once.
            window.removeEventListener("unload", arguments.callee, false);
            window.removeEventListener("DOMContentLoaded", this.wrapOnContentLoad, false);
            window.browserDOMWindow = null;
            whitetrashOverlay.domainMenuList.clearList();
            //TODO: make sure I clean up everything here
        },
    
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
    	//This is what I'm doing, uncomment lines below to store in prefs

        //this.logger.logStringMessage("adding to prefs:"+domain+proto);
    	//var cur=this.getPref("whitetrash."+proto+".whitelist");
    	if (proto==this.getProtocolCode("HTTP")) {
    	    this.whitelist_http[domain]=true;
    	} else if (proto==this.getProtocolCode("SSL")) {
    	    this.whitelist_ssl[domain]=true;
    	}
    	//this.setPref("whitetrash."+proto+".whitelist",cur+=domain+"|");
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

