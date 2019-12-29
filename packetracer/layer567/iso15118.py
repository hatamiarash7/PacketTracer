"""
ISO15118
"""
import logging

from packetracer.packetracer import Packet

logger = logging.getLogger("packetracer")

MSGTYPE_EXI = 0x8001
MSGTYPE_SDP_REQ = 0x9000
MSGTYPE_SDP_RSP = 0x9001


class SDP(Packet):
    __hdr__ = (
        ("id", "B", 0),
        ("idrev", "B", 0),
        ("msgtype", "H", 0),
        ("msglen", "I", 0)
    )
