"""Internetwork Packet Exchange."""

from packetracer import packetracer

IPX_HDR_LEN = 30


class IPX(packetracer.Packet):
    __hdr__ = (
        ("sum", "H", 0xFFFF),
        ("len", "H", IPX_HDR_LEN),
        ("tc", "B", 0),
        ("pt", "B", 0),
        ("dst", "12s", b""),
        ("src", "12s", b"")
    )
