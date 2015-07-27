Tor Consensus and Server Descriptor Parser
------------------------------------------

Script that parses Tor consensuses and server descriptors to create csv files
that can be used for Tor visualization data.

`parse2.py` is for Python 2.7+

`parse3.py` is for Python 3.3+

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
