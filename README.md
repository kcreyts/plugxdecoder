plugxdecoder
============

Basic Python script which Decodes PlugX traffic and encrypted/compressed 
artifacts. 

Accepting pull requests from those who wish to contribute. 

Currently requires:
CTypes (with ntdll), 
dpkt (http://code.google.com/dpkt)

Tested with Python 2.7, on Windows.


Long-term goal is to make a pure Python plugin for MITRE's ChopShop.

https://github.com/MITRECND/chopshop


Since I want it to be pure Python, I'll have to do away with the 
RtlCompressBuffer call to ntdll...


USE THIS AT YOUR OWN RISK, I GUARANTEE NOTHING.
