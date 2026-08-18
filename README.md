# Interoperable Train Control Monitoring software v1.0

Also see <https://github.com/katsojuna/itcwatch> for the ITC Watch program.

To upgrade, copy/unzip the new release, the copy your WIUS subdirectory into the new release folder.  You may also need to copy over some of your config files such as mcr.json, itcmon.json, etc.  With v1.0 you can now place your config files in the "local" subdirectory which will make future upgrades easier.

Updates since v0.9:
  - mcr,igw,i2a,itcmon now search for json config files in a subdirectory "local" before the connected directory.  this will make it easier to upgrade to new release by just copying your local and wius subdirectories to the new dist dir.
  - itcmon, minor fixes, starts monitoring on startup
  - igw, fixes some crashes and issues with poor connectivity
  - igw and i2a now have a "-b" option to place them in the background for server operation
  - i2a json can now have a zmq server source option like "server":{"host":"1.2.3.4","port":18001}

Updates since v0.8:
  - itcmon now supports milepost entries like "MP":"CP42" for each WIU and lets you sort on that column
  - igw has many bug fixes, should fix hanging problem, rewrote how auth protocol works (if you were using this you need to update both ends of any igw connections)
  - mcr will now look for channel# to frequencies in channels.json (if not there will revert to built-in table)
  - i2a optional arg "-a" will convert matching and opposing signals that are both not stops to both being stops, possibly useful for ABS signals.  without this option it won't change anything.

Updates since v0.7:
  - mcr and s2p updated with improved signal processing code
  - s2p now handles large unicast type x70 fragments and reassembles them
  - itcmon has gui improvements in handling column widths and remembering changes
  - itcmon now handles type x70 packets correctly
  - itcmon adds a CTC tab to show CTC/ATCS/Codeline data, and outputs this in a new json zmjpub message
  - i2a can be used to convert PTC to ATCSMON, *or* CTC to ATCSMON (using "i2a -c" option), but not both at the same time
  - igw has some small updates, might fix a bug some people were seeing
  
Updates since v0.6:
  - mcr will pick lowest possible sampling rate depending on the range of channels/frequencies configured
  - updates to i2a packets sent to atcsmon
  - new itcdir program is a start on having a directory service to locate public servers for particular wiu's (see src directory)
  - itcmon will stop interpreting and sending indications in a future release, so you will need to use the data field and interpret them yourself if developing an app (can use wiu json data files to do this)

Updates since v0.5:
  - Split the wius.json file up by railroad and next 3 digits of wiu#, so they are now stored in a subdirectory path such as "wius/802/802456.json".  You can run the program "split-wius" to read your old wius.json file and split it up into the right subfiles.   Keep a copy of your wius.json just in case something goes wrong.  However, before running ITCMON delete wius.json or rename it to something else.
  - The auto-export command is replaced with "Save WIUs" which will add any newly discovered ones to your existing files.
  - ITCMON will attempt to decode the signal and switch bits automatically when it discovers new WIUs (based on original idea of Robert Romaine)
  - ITCMON now displays the local time instead of UTC
  - Previous versions had a typo in the frequency for channel 102 and 142, this has been fixed!

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
  - first release of raspberry pi code

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

![Diagram](doc/itcmon-diagram.png)

