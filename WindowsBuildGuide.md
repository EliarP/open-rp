### Introduction ###

Welcome to the Open Remote Play Windows Build Guide.  For those who wish to build (compile) ORP from SVN, this guide is for you.  If you find any errors in this guide, please leave a comment, or even edit the page yourself.

### Prerequisites ###

You only need two things to start:

  1. SVN to download and update the source code.  I use [TortoiseSVN](http://tortoisesvn.tigris.org/).  You can find a list of others [here](http://subversion.tigris.org/links.html#clients).
  1. A complete MINGW32 + MSYS development environment which I have already done for you and can be downloaded [here](http://orp.ps3-hacks.com/packages/MINGW32-ORP.zip).

### Installation ###

  * Install TortoiseSVN.
  * Extract MINGW32-ORP.zip to C:\

Optional:

  * Create a desktop or start menu shortcut icon for MSYS.  The shortcut should point to: C:\msys\1.0\msys.bat and if you'd like to use the official icon, browse and select: C:\msys\1.0\msys.ico

### Start MSYS and SVN Checkout ORP ###

  * Test that MSYS runs properly by either clicking on the shortcut you created above, or by running C:\msys\1.0\msys.bat from a DOS shell prompt.

This should open a shell and leave you at a dollar sign prompt: **$**

  * Now use TortoiseSVN or whichever SVN client you have installed to download the latest ORP SVN trunk source code.  Ensure you checkout in to your MSYS home directory.  This will be: C:\msys\1.0\home\_username_

Example command-line SVN syntax:
```
svn checkout http://open-rp.googlecode.com/svn/trunk/ open-rp
```

### Build Open Remote Play ###

  * From the MSYS shell prompt, enter the open-rp directory and start a build.

```
$ cd open-rp
$ make release
```

### Running ORP ###

  * To run ORP, open My Computer -> msys -> 1.0 -> home -> _username_ -> open-rp -> ORP-_version_-SVN-W32
  * Run orpui.exe

### Updating ###

  * When new updates are available, you can SVN update the open-rp directory.

Example command-line SVN syntax (you must be in the open-rp directory):
```
svn update
```