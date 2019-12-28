"""Protocol Independent Multicast."""

from packetracer import packetracer, checksum
from packetracer.packetracer import FIELD_FLAG_AUTOUPDATE


class PIM(packetracer.Packet):
	__hdr__ = (
		("v_type", "B", 0x20),
		("rsvd", "B", 0),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE)  # _sum = sum
	)

	def __get_v(self):
		return self.v_type >> 4

	def __set_v(self, v):
		self.v_type = (v << 4) | (self.v_type & 0xF)
	v = property(__get_v, __set_v)

	def __get_type(self):
		return self.v_type & 0xF

	def __set_type(self, pimtype):
		self.v_type = (self.v_type & 0xF0) | pimtype
	type = property(__get_type, __set_type)

	def _update_fields(self):
		if self.sum_au_active and self._changed():
			self.sum = 0
			self.sum = checksum.in_cksum(packetracer.Packet.bin(self))
