## Overview ##
First ensure that you've enabled port-forwarding for TCP and UDP 9293 to the internal IP address of your PlayStation 3.  The easiest way is to enable UPnP on your firewall, then the PS3 can configure that part for you.

Since Open Remote Play version 1.1, when game launching was added, you can no longer establish an external connection by simply port-forwarding TCP 9293 to your PlayStation 3.  The UDP portion of the protocol uses UDP 9293 and should be easy to forward.  However the problem is that Sony designed the protocol so that external connections come in via the PSN.  So what they've done is set the TTL of the PlayStation 3 UDP reply packets to 1. This means that the replies will never make it back to you across the Internet as they can not cross more than one router/gateway before being discarded.

## Solutions ##
There are three solutions and unfortunately, none of them are that easy.  Listed below in order of difficulty, from least to most difficult:

  * Set-up a VPN between your laptop/office and home.
> I won't go in to detail, you can find many guides and software on-line about this.

  * For those who are running more advanced firewall/gateways, there is a simple solution.
> Increase the UDP packet's TTL.  The example I'll give here is specific to IPtables, but can be easily translated to other firewall types.  Your firewall requires the TTL module.  If you use OpenWRT, you'll need to install the iptables-extra package first.  Load the module if it's not already loaded:

> `# insmod ipt_TTL`

> In the example rule below, 192.168.1.10 is the internal IP address of the PlayStation 3.

> `# iptables -t mangle -I PREROUTING -p udp -s 192.168.1.10 --sport 9293 -j TTL --ttl-set 60`

  * Completely reverse-engineer the external connection portion of the Remote Play protocol.
> I may get around to this at some point.  I've already looked at it a little, and it's fairly complicated.  At the moment, I have more important things on the TODO list to complete first.  If someone else out there wants to take a stab at it... :)

  * I know I said there were only three solutions, but here is another.  It's not a real solution because it means that game launching will not work across the Internet.
> Add a check-box to the profile edit page for external connections which would disable the UDP portion of the protocol and connect directly to TCP 9293.  This would at least allow access to the XMB.  **NOTE:** This has been implemented in SVN trunk.