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
Since I want it to be pure Python, I'll have to do away with the 
RtlCompressBuffer call to ntdll...

As of today, MITRE has pushed a new module for performing LZNT1 decompression
in Python, (real cool implications for various forensics applications), which 
means I no longer have a good excuse for not making this decoder into a real
ChopShop module to thank them. 

I'll soon be rolling out new Plugin Identifiers and processing for UDP traffic
as well. 

USE THIS AT YOUR OWN RISK, I GUARANTEE NOTHING.
