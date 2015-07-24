### How do I find the IP address of my PlayStation 3? ###

> You can see the current IP address of the PS3 under:
> > Settings > Network Settings > Setting & Connection Status List

### How do I connect to my PlayStation 3 from the Internet (work, school, cafe, etc.)? ###


> If you are running PS3 FW 2.76 or below, see the ExternalConnection page for details.  For PS3 FW 2.80 or above, you will have to properly configure a VPN.  The PS3 must see the source MAC address as if it were the registered PSP (spoofed).  Visually, this would look something like:
![http://open-rp.googlecode.com/svn/wiki/images/orp-vpn.png](http://open-rp.googlecode.com/svn/wiki/images/orp-vpn.png)

### How do I enable and use Remote Start (turn-on the PS3 remotely)? ###

> First, ensure you have Remote Start enabled.  Go to:
> > Settings > Remote Play > Remote Start


> Choose On, check the Enable Remote Start via the Internet box, and then click on OK.

> NOTE: Depending on how long your PS3 has been off, your Internet gateway/router may have cleared the PS3's ARP address from the cache.  When this happens, the gateway/router will not forward incoming Wake-on-LAN (WoL) packets to your PS3.  You can over come this problem if you can save a _static_ ARP entry.  For example, under most Unix-based operating systems, the command would be similar to (substitue XXX.XXX.XXX.XXX and FF:FF:FF:FF:FF:FF with the IP address and MAC address of your PS3, and eth0 with the appropriate interface):

> <pre> # arp -s XXX.XXX.XXX.XXX FF:FF:FF:FF:FF:FF</pre>
> Or
> <pre> # ip neigh add XXX.XXX.XXX.XXX lladdr FF:FF:FF:FF:FF:FF nud permanent dev eth0</pre>

> Second, ensure you're Internet firewall/gateway either has UPnP enabled, or that you have manually port forwarded 9293 (TCP and UDP) to the PS3's IP address.  If you are at home, on your LAN, then ensure you have selected "Enable WoL Reflector" from the Edit page for your PS3 settings.

### How do I turn-off my PlayStation 3 remotely? ###

> If you wish to turn the PS3 off, go to:
> > Users > Turn Off System

### I updated my PS3 to Firmware 2.80, and now ORP crashes (Corrupt video stream) ###

Sony has changed Remote Play as of 2.80 to require the client's MAC address to match that of the registered PSP's MAC address.  We're still working on a proper solution for this, but in the mean-time you can spoof your PSP's MAC address to get local connections working again.  In Linux, this would look something like (change aa:bb:cc:dd:ee:ff to your PSP's MAC address):

> <pre> # ifconfig wlan0 hw ether aa:bb:cc:dd:ee:ff</pre>

For OSX, this works similar:
> <pre> # sudo ifconfig en0 lladdr aa:bb:cc:dd:ee:ff</pre>

Apparently this does work with the AirPort interface (en1), but you have to disassociate first.  See j.altan's comment below.

For Windows, apparently you can use this (thanks mechos):
> http://www.technitium.com/tmac/index.html

Another Windows MAC address changer, apparently works with Windows 7 (thanks UK\_Robbie):
> http://www.voidnish.com/articles/ShowArticle.aspx?code=MacIdChanger

### How Do I Build ORP for Windows? ###

Read the following guide: WindowsBuildGuide