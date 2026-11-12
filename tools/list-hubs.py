#!/usr/bin/env python3
"""List the RRC hubs a Reticulum node has heard announced.

    list-hubs.py ~/.reticulum/storage/known_destinations

Needs the rns package (for its bundled msgpack). Prints the newest first:
when it was heard, the hub's destination hash and the name it announces.
"""
import hashlib
import sys
import time

import RNS.vendor.umsgpack as msgpack


def cbor_text_map(data):
    """Decode a CBOR map whose keys and values are short texts or small ints
    (what hubs announce: {"proto": "rrc", "v": 1, "hub": "Name"})."""
    pos = 0

    def head():
        nonlocal pos
        ib = data[pos]
        pos += 1
        major, info = ib >> 5, ib & 0x1F
        if info < 24:
            return major, info
        n = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        value = int.from_bytes(data[pos:pos + n], "big")
        pos += n
        return major, value

    def item():
        nonlocal pos
        major, value = head()
        if major == 0:
            return value
        if major == 3:
            text = data[pos:pos + value].decode("utf-8", "replace")
            pos += value
            return text
        raise ValueError("unsupported item")

    major, count = head()
    if major != 5:
        raise ValueError("not a map")
    return {item(): item() for _ in range(count)}

known = msgpack.unpackb(open(sys.argv[1], "rb").read())
name_hash = hashlib.sha256(b"rrc.hub").digest()[:10]
hubs = []
for dest, entry in known.items():
    identity_hash = hashlib.sha256(entry[2]).digest()[:16]
    if hashlib.sha256(name_hash + identity_hash).digest()[:16] != dest:
        continue
    name = ""
    app_data = entry[3] if len(entry) > 3 else None
    if app_data:
        try:
            name = str(cbor_text_map(app_data).get("hub", ""))
        except Exception:
            name = app_data.decode("utf-8", "replace")
    hubs.append((entry[0], dest.hex(), name))

for heard, dest, name in sorted(hubs, reverse=True):
    print(time.strftime("%Y-%m-%d %H:%M", time.gmtime(heard)), dest, name)
