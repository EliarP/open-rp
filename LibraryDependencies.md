Here is the list of packages that are required to build ORP from source.  All of these packages are available for Windows, Mac, and Linux.  Some of these packages can not be built from source under Windows (with MSVC), however, pre-compiled shared library (DLL) versions are available for download.

## Simple Direct Media Library (libSDL) ##

Source: http://www.libsdl.org/

libSDL is available in source and as a shared library (DLL).  It is very stable on all platforms and well supported.  This project uses libSDL for the following:
  * audio output
  * video output (RGB images and YUV overlay)
  * thread support
  * events (keyboard, mouse, joystick, window manager, etc.)

## libz ##

Source: http://www.zlib.net/

Used by libpng (below) to handle the compression within PNG images.  Not an essential library.

## libpng ##

Source: http://libpng.org/

Used to display the logo splash image.  Not an essential library.


## SDL\_image ##

Source: http://www.libsdl.org/projects/SDL_image/

Used to convert a PNG image in to an SDL\_Surface.  Used to display the logo splash image.  Not an essential library.

## SDL\_net ##

Source: http://www.libsdl.org/projects/SDL_net/

Portable network library used by ORP to send/recv UDP packets to/from a PlayStation 3.  Also used to open a TCP connection to the PlayStation 3 for sending "pad" (button presses, etc) events.

Under Mac OSX, it is critical that you patch SDL\_net to fix the key lag issue.  The patch is in the 'patches' sub-directory:

http://code.google.com/p/open-rp/source/browse/trunk/patches/SDL_net-1.2.7-TCP_NODELAY.patch

## FreeType 2 ##

Source: http://www.freetype.org/

The FreeType 2 font API is required to display error messages in the player window.  It is used by SDL\_ttf.

## SDL\_ttf ##

Source: http://www.libsdl.org/projects/SDL_ttf/

Portable font rendering library used by the ORP player to display error messages.  Depends on FreeType 2.

## libCURL ##

Source: http://curl.haxx.se/libcurl/

libCURL handles 99% of the Remote Play HTTP protocol.  The remaining 1% (sending "pad" data - see above), is handled directly.

Under Windows, you should apply the following patch to fix a bug where libCURL exits from socket reads upon receiving SIGINT:

http://code.google.com/p/open-rp/source/browse/trunk/patches/curl-7.19.4-EINTR.patch

## libfaad2 ##

Source: http://www.audiocoding.com/faad2.html

This is the AAC decoder that seems to work best with Remote Play.  I'm using this rather than the built-in FFmpeg version because the built-in version doesn't work at all (latest SVN).  Install this first, and then when you build FFmpeg, enable the libfaad codec.

## FFmpeg ##

Source: http://www.ffmpeg.org/

The ORP project requires FFmpeg for audio and video decode.  The following codecs are required:
  * AAC (libfaad)
  * MPEG4 (mpeg4, and the m4v muxer)
  * ATRAC3 (atrac3)
  * AVC (h264)

## OpenSSL (libcrypto) ##

Source: http://www.openssl.org/

Open Remote Play depends on AES CBC support from the OpenSSL library, libcrypto specifically.

## MinGW (Windows only) ##

Source: http://www.mingw.org/

**NOTE** Building FFmpeg under Windows requires the MinGW and MSYS build environment.
See this [guide](http://ffmpeg.arrozcru.org/wiki/index.php?title=Main_Page) for more information.

I have not tried using the available FFmpeg DLLs.  Namely because the built-in AAC decoder doesn't seem to work.  However, before install MinGW and building FFmpeg from source, someone should try using the pre-compiled DLLs.  They may work **much** better than building from source.

## wxWidgets ##

Source: http://wxwidgets.org/

The GUI front-end uses wxWidgets.  Available on all platforms as source code or pre-compiled libraries.