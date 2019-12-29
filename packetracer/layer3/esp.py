"""Encapsulated Security Protocol."""

from packetracer import packetracer


class ESP(packetracer.Packet):
    __hdr__ = (
        ("spi", "I", 0),
        ("seq", "I", 0)
    )
