#!/usr/bin/env python3
"""Traceroute one or more targets and draw the path on a world map.

Needs /data/GeoLite.mmdb mounted into the container.
Output PDF is written to /tmp/world_trace.pdf — copy it out with
`docker cp` or `kubectl cp`.

Usage:  python3 /app/scripts/recon/traceroute_world.py saidsef.co.uk
        python3 /app/scripts/recon/traceroute_world.py google.com github.com
"""
import os
import sys
from scapy.all import conf, traceroute_map

GEOIP = "/data/GeoLite.mmdb"
if not os.path.exists(GEOIP):
    sys.exit(f"missing {GEOIP} — mount it with `-v /path/to/geoip:/data`")

conf.geoip_city = GEOIP
conf.temp_files = "/tmp"

targets = sys.argv[1:] or ["saidsef.co.uk"]
res = traceroute_map(targets, verbose=0)
out = "/tmp/world_trace.pdf"
res.world_trace(filename=out)
print(f"wrote {out}")
