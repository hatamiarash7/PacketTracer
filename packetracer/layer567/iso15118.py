"""
ISO15118
"""
import logging
import sys

from packetracer.packetracer import Packet
from packetracer.structcbs import pack_H_le, unpack_H, unpack_H_le
from packetracer.triggerlist import TriggerList

logger = logging.getLogger("packetracer")

MSGTYPE_EXI	= 0x8001
MSGTYPE_SDP_REQ	= 0x9000
MSGTYPE_SDP_RSP	= 0x9001


class SDP(Packet):
	__hdr__ = (
		("id", "B", 0),
		("idrev", "B", 0),
		("msgtype", "H", 0),
		("msglen", "I", 0)
	)
