#!/usr/bin/env python3
"""Extract NGAP PDUs (SCTP DATA chunks with PPID 60) from a pcap as "<frame> <hex>" lines.

Usage (needs tshark, e.g. in WSL): python3 tools/gen/pcap_ngap_to_hex.py capture.pcapng > pdus.hex
"""
import json
import struct
import subprocess
import sys

raw = subprocess.run(["tshark", "-r", sys.argv[1], "-Y", "sctp", "-T", "json", "-x"],
                     capture_output=True, text=True, check=True).stdout
for pkt in json.loads(raw):
    layers = pkt["_source"]["layers"]
    frame = bytes.fromhex(layers["frame_raw"][0])
    eth_len = 14  # Ethernet link layer (capture on lo)
    ihl = (frame[eth_len] & 0x0F) * 4
    sctp = frame[eth_len + ihl:]
    pos = 12  # skip SCTP common header
    while pos + 4 <= len(sctp):
        ctype, _flags, clen = struct.unpack(">BBH", sctp[pos:pos + 4])
        if clen < 4:
            break
        if ctype == 0 and clen > 16:  # DATA
            ppid = struct.unpack(">I", sctp[pos + 12:pos + 16])[0]
            if ppid == 60:
                print(layers["frame"]["frame.number"], sctp[pos + 16:pos + clen].hex())
        pos += (clen + 3) & ~3
