<table>
<tr>
<td>
<h3>Name</h3>
<blockquote>Enter a profile name here, any name you like.  I like to append <b>Public</b> or <b>Private</b> in order to help me remember the type of profile.</blockquote>

<h3>Connection Type</h3>
<blockquote>A profile can be one of two types; <b>Public</b> (when you connect to your PS3 from the Internet), and <b>Private</b> (for local LAN connections).  Public connections require you to enter your PSN login name (<b>not</b> your PSN ID), in to the box below.</blockquote>

<b>NOTE</b>: Public connection types are not currently supported!  Make sure to set the connection type to <b>private</b>.<br>
<br>
<h3>Address / Port</h3>
<blockquote>Enter either the hostname or IP address of your PS3.  For Public connections, this would be the public IP address assigned by your ISP.  For Private connections, this would be something like: 192.168.x.x or 10.x.x.x.</blockquote>

<ul><li><b>Disable UDP Search?</b>
<blockquote>For Private connection types, this should always be enabled.  For Public connections, this may need to be disabled if you are unable to properly configure your gateway for <a href='http://code.google.com/p/open-rp/wiki/ExternalConnection'>External</a> connections.  <b>NOTE</b>: At this time, disabling UDP Search will inhibit game/application launching.  Thats is, launching a game, or an application (PlayTV, Life with PlayStation) will not work.<br>
</blockquote></li><li><b>Enable WoL Reflector?</b>
<blockquote>Wake-on-LAN reflector will echo the packet back to your private network, allowing you to turn-on your PlayStation 3.  For Private connections types, this should always be enabled.  Not required for Public connections, though it is harmless to leave it enabled for all profiles.</blockquote></li></ul>

<h3>Default Bitrate</h3>
<blockquote>You may select a default bitrate for each connection profile.  The general rule is Public connections should be set lower, and Private connections should be set to the highest value (1024k).  You can change the bitrate <i>on-the-fly</i> by pressing CTRL+1 (1024k), CTRL+2 (768k), and CTRL+3 (384k) during an active session.</td>
<td><img src='http://open-rp.googlecode.com/svn/wiki/images/orpui-edit.png' /></td>
</tr>
</table>