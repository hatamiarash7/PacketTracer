"""
Scalable service-Oriented MiddlewarE over IP (SOME/IP)
https://www.autosar.org/fileadmin/user_upload/standards/foundation/1-2/AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol.pdf
"""
import logging

from packetracer.packetracer import Packet
from packetracer.packetracer_meta import FIELD_FLAG_AUTOUPDATE

logger = logging.getLogger("packetracer")

RET_CODE_E_OK = 0x00
RET_CODE_E_NOT_OK = 0x01
RET_CODE_E_UNKNOWN_SERVICE = 0x02
RET_CODE_E_UNKNOWN_METHOD = 0x03
RET_CODE_E_NOT_READY = 0x04
RET_CODE_E_NOT_REACHABLE = 0x05
RET_CODE_E_TIMEOUT = 0x06
RET_CODE_E_WRONG_PROTOCOL_VERSION = 0x07
RET_CODE_E_WRONG_INTERFACE_VERSION = 0x08
RET_CODE_E_MALFORMED_MESSAGE = 0x09
RET_CODE_E_WRONG_MESSAGE_TYPE = 0x0A


# Other codes: RESERVED


class SomeIP(Packet):
    __hdr__ = (
        ("messageid", "I", 1),
        ("length", "I", 8, FIELD_FLAG_AUTOUPDATE),  # in bytes, inclusive 8 bytes of header
        ("reqid", "I", 0),
        ("protoversion", "B", 0),
        ("ifaceversion", "B", 0),
        ("msgtype", "B", 0),
        ("retcode", "B", 0)
    )

    def _update_fields(self):
        if not self._changed():
            return

        if self.length_au_active:
            self.length = 8 + len(self.body_bytes)
