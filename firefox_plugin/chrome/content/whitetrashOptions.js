/**
 * Protect the javascript global namespace!
 * http://blogger.ziesemer.com/2007/10/respecting-javascript-global-namespace.html
 * **/

var whitetrashOpt=null;

whitetrashOpt = {
  logger : null
  ,
  init: function() {
      document.getElementById("wtserverdomain").value = whitetrashOverlay.getPref("whitetrash.domain","whitetrash");
      document.getElementById("ml-wtproto").selectedItem = document.getElementById("wtproto-"+whitetrashOverlay.getPref("whitetrash.protocol","https"));
  }
  ,
  save: function() {

      whitetrashOverlay.setPref("whitetrash.domain",document.getElementById("wtserverdomain").value);
      whitetrashOverlay.setPref("whitetrash.protocol",document.getElementById("ml-wtproto").selectedItem.value);
  }

}//end namespace encapsulation

