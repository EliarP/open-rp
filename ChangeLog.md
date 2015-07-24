## Open Remote Play v1.3 ##
  * Added default bitrate profile setting.
  * Fixed threading issue which corrupted AES IV (fixes Windows crashes and video corruption issues).
  * Added public/private connection types and authentication changes.
  * Added error messages to the player instead of just bailing silently.
  * Fixed the annoying MacOSX input lag.
  * Added "virtual keyboard" mode.  Thanks to MohammadAG for the idea!
  * Added Wake-on-LAN (WoL) support.  You can now turn on your PS3 remotely.
  * Added keys to toggle through three bit-rates: 384k, 768k, and 1024k
  * Added "Disable UDP Search" check-box and configuration option for external connections where the TTL can not be changed at the gateway/firewall.  This will also disable game launching.
  * Added preliminary a/v sync.  Video is now synchronized with the audio clock.

## Open Remote Play v1.2 ##
  * Fixed Edit profile page height under Windows.  Save, Delete, and Cancel buttons are now visible.
  * Mouse motion events are now sent only while holding the ALT key down from within full-screen mode.
  * Vastly improved full-screen mode. Scales video to desktop resolution, much faster and now works as expected under Windows.
  * Added proper padding for audio/video packets. This fixes the random read access violation crashes under Windows.
  * Switched to AVPacket structures in preparation for implementing proper audio/video synchronization (PTS/DTS).
  * Added PS3 'chime' sample which plays when a connection has been established.
  * Fixed missing windows icon.
  * Added support for left and right analog sticks.
  * Added support for all SIXAXIS/DS3 buttons.
  * Added mouse support.
  * Added SELECT (F3) and START (F4) keyboard mappings.
  * Fixed CTRL-key issues, thanks to lethalwp for the patch.