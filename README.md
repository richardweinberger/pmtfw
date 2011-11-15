A poor man's TCP firewall
=========================

This tiny program terminates all TCP connections which are not from a trusted
source.

Usage
-----

pmtfw [-f] [-i dev] -a AllowedIP1,AllowedIP2,...,AllowedIPN

  -f      : stay in foreground

  -i DEV  : only filter traffic on interface DEV

  -a LIST : comma separated list of allowed IPs

  -h      : show help


FAQ
---

Q: Which operation systems are supported?

A: The program is designed to run on GNU/Linux but porting it to any other UNIX 
should be easy.


Q: Why should I use this tool?

A: It was written to allow minimal firewalling on embedded systems where no 
iptables or hosts.{allow,deny} files are available.
The author is using it to have firewalling on crappy IPMI devices.
