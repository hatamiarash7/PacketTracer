"""Portmap / rpcbind."""

from packetracer import packetracer

PMAP_PROG = 100000
PMAP_PROCDUMP = 4
PMAP_VERS = 2


class Pmap(packetracer.Packet):
    __hdr__ = (
        ("prog", "I", 0),
        ("vers", "I", 0),
        ("prot", "I", 0),
        ("port", "I", 0),
    )
