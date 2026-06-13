# Interoperable Train Control Monitoring software v0.3

Updates since v0.2:
  added SDR ppm error correction value to mcr.json
  improved deinterleave and fec code in s2p for better reception
  added i2a program that translates PTC messages to ATCSMON server messages
  
----------------------------------------------------------------------------
This release runs on Windows (tested on Win 11) and
needs an RTL-SDR, a 220mhz antenna, and the
regular Windows Zadig RTL/USB drivers installed.

Download the ZIP file, unzip it into a new directory, read the files
in the docs directory (start with quick-start.txt)

Please use Groups.IO PTCTalk for discussion of the software and related topics.

The software was built with Cygwin (see cygwin.com for more info).

![Screenshot](itcmon-screenshot.png)
