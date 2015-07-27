Tor Consensus and Server Descriptor Parser
------------------------------------------

Script that parses Tor consensuses and server descriptors to create csv files
that can be used for Tor visualization data.

`parse2.py` is for Python 2.7+

`parse3.py` is for Python 3.3+

The generated CSV files are written in the `data/` directory (created if non
existent).

Example:

	$ python3 parse3.py 2010 07 09
	> Only July 9th, 2010 will be processed.

	$ python3 parse3.py 2010 08
	> August of 2010 will be processed.

	$ python3 parse3.py 2010
	> All 2010 will be processed.

Note
----

Decompression of lzma file (.xz) is not yet supported for Python 2. You'll have
to uncompress them yourself for now.

Requirements
------------

	- Maxmind Geo IP city database in binary format (GeoLiteCity.dat).
      https://dev.maxmind.com/geoip/legacy/geolite

	- pygeoip
		$ pip install pygeoip

	- tarfile (Only for parse3.py)
		$ pip install tarfile

	- Stem library - https://stem.torproject.org/
		$ pip install stem
