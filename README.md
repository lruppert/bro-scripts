Lou's bro scripts
===============

Python
-------

cert2bro.py - Converts a PEM format certificate into a config stanza for 
Bro-IDS.  Needs hexdump and openssl installed on system.

restart_bro.py - Restarts bro nodes that have hung or crashed or passed a 
certain threshold for packet loss.

Shell
------

bro-ids - init script for Debian-based systems, poorly written, but it works.

Prelude
--------

bro-2.0.rules - Parsing rules for prelude-ids to turn bro notices into events.

Bro
----

sensitive-dns.bro - Uses a datastructure of malicious domains and descriptors
to alert on lookups to malicious dns addresses.  Also demonstrates a heuristics
rule for potential Zeus C2 domains.

tune-md5.bro - Tunes out md5 notices on systems in certain commonly used and
trusted networks.

