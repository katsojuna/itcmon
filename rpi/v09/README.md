This directory is for the Raspberry Pi.

You should be able to use this to set up a remote receiver but will still need ITCMON on a PC, or other software to display the data.

It has only been tested on a PI 3 running 64-bit Debian Trixie, but it should run on a Pi 4 or 5.

Install the rtl-sdr package and run rtl_test to make sure that stuff is working first.

You made need to install some additional packages for the itcmon programs to work: libsodium libcjson

Let me know how it goes.
