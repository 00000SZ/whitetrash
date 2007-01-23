===============================================
Whitetrash - Dynamic Web Whitelisting for Squid
===============================================

The goal of Whitetrash is to provide a user-friendly and sysadmin-friendly proxy that makes it **significantly** harder for malware to use HTTP and SSL for:

- initial compromise;
- data exfiltration; and
- command and control.

Whitetrash implements a whitelisted web proxy as a Squid plugin.

Generally whitelisting is defined as having a default deny policy, and only allowing specific types of objects/packets/requests/strings/accounts - those that are known to be 'good'.  Blacklisting is the opposite of this process where all types of objects/packets/requests/strings/accounts etc. are allowed by default, and only specifc 'bad' entities on the blacklist are denied.

Whitetrash whitelists web traffic at the domain level, and is a powerful technique to eliminate communications for a lot of malware. 

See INSTALL for installation instructions.  Further documentation is available from http://whitetrash.sf.net

Contact the author at: gregsfdev@users.sourceforge.net

