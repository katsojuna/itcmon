# Interoperable Train Control Monitoring software v0.5

Updates since v0.3:
  - greatly improved performance and reception
  - added "-d directory" flag it itcmon to have it read all json files from subdirectory
  - added locomotives display to itcmon
  - new packets.txt format has initial "I" for ITC to allow for future protocols
  - mcr no longer has built-in rtl-sdr driver, it uses rtl_tcp program for reception
  - mcr must be given device number (no longer accepts -1 to find device)
  - mcr has new "-e #" flag to set ppm correction value
  - mcr has new "-q #" flag to set squelch level
  - new igw program for aggregating multiple servers

Updates since v0.2:
  - added SDR ppm error correction value to mcr.json
  - improved deinterleave and fec code in s2p for better reception
  - added i2a program that translates PTC messages to ATCSMON server messages
  
----------------------------------------------------------------------------
This release runs on Windows (tested on Win 11) and
needs an RTL-SDR, a 220mhz antenna, and the
regular Windows Zadig RTL/USB drivers installed.

Download the ZIP file, unzip it into a new directory, read the files
in the docs directory (start with quick-start.txt)

Please use Groups.IO PTCTalk for discussion of the software and related topics.

The software was built with Cygwin (see cygwin.com for more info).

![Screenshot](itcmon-screenshot.png)
