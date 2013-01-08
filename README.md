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

As of today, no one seems to have implemented the MS compression algorithms
in Python, (despite implications for various forensics applications), which 
means implementing my own version of at least LZNT1 (based on work done by 
coderforlife: https://github.com/coderforlife/ms-compress): http://github.com/kcreyts/pyrtlcompressbuffer
