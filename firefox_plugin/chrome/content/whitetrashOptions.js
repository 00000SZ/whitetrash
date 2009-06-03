/**
 * Protect the javascript global namespace!
 * http://blogger.ziesemer.com/2007/10/respecting-javascript-global-namespace.html
 * **/

var whitetrashOpt=null;

whitetrashOpt = {
    
  init: function() {
      document.getElementById("wtserverdomain").value = whitetrashOverlay.getPref("whitetrash.domain","whitetrash");
  }
  ,
  save: function() {
      whitetrashOverlay.setPref("whitetrash.domain",document.getElementById("wtserverdomain").value);
  }

}//end namespace encapsulation

