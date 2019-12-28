"""
Internet Control Message Protocol for IPv4.
https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
https://tools.ietf.org/html/rfc792
"""
import logging

from packetracer import packetracer, checksum
from packetracer.packetracer import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD

logger = logging.getLogger("packetracer")


# Types (icmp_type) and codes (icmp_code) -
# http://www.iana.org/assignments/icmp-parameters


ICMP_ECHO_REPLY			= 0		# echo reply
ICMP_UNREACH			= 3		# dest unreachable
ICMP_SRCQUENCH			= 4		# packet lost, slow down
ICMP_REDIRECT			= 5		# shorter route
ICMP_ALTHOSTADDR		= 6		# alternate host address
ICMP_ECHO			= 8		# echo service
ICMP_RTRADVERT			= 9		# router advertise
ICMP_RTRSEL			= 10		# router selection
ICMP_TIMEXCEED			= 11		# time exceeded, code:
ICMP_PARAMPROB			= 12		# ip header bad
ICMP_TSTAMP			= 13		# timestamp request
ICMP_TSTAMPREPLY		= 14		# timestamp reply
ICMP_INFO			= 15		# information request
ICMP_INFOREPLY			= 16		# information reply
ICMP_MASK			= 17		# address mask request
ICMP_MASKREPLY			= 18		# address mask reply
ICMP_TRACEROUTE			= 30		# traceroute
ICMP_DATACONVERR		= 31		# data conversion error
ICMP_MOBILE_REDIRECT		= 32		# mobile host redirect
ICMP_IP6_WHEREAREYOU		= 33		# IPv6 where-are-you
ICMP_IP6_IAMHERE		= 34		# IPv6 i-am-here
ICMP_MOBILE_REG			= 35		# mobile registration req
ICMP_MOBILE_REGREPLY		= 36		# mobile registration reply
ICMP_DNS			= 37		# domain name request
ICMP_DNSREPLY			= 38		# domain name reply
ICMP_SKIP			= 39		# SKIP
ICMP_PHOTURIS			= 40		# Photuris


class ICMP(packetracer.Packet):
	__hdr__ = (
		("type", "B", ICMP_ECHO, FIELD_FLAG_IS_TYPEFIELD),
		("code", "B", 0),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE)
	)
	type_t = packetracer.get_property_translator("type", "ICMP_")

	def _update_fields(self):
		# logger.debug("sum is: %d" % self.sum)
		if self.sum_au_active and self._changed():
			# logger.debug("sum is: %d" % self.sum)
			# logger.debug("header: %r", self.header_bytes)
			# logger.debug("body: %r", self.body_bytes)
			self.sum = 0
			self.sum = checksum.in_cksum(self.header_bytes + self.body_bytes)
			# logger.debug("sum is: %d" % self.sum)

	def _dissect(self, buf):
		# logger.debug("ICMP: adding fields for type: %d" % buf[0])
		self._init_handler(buf[0], buf[4:])
		return 4

	class Echo(packetracer.Packet):
		__hdr__ = (
			("id", "H", 0),
			("seq", "H", 1),
			("ts", "Q", 0)
		)

		def _dissect(self, buf):
			hlen = 12

			if len(buf) < 12:
				# not enough bytes for ts
				self.ts = None
				hlen = 4
			return hlen

	class Unreach(packetracer.Packet):
		__hdr__ = (
			("pad", "I", 0),
		)

		CODE_UNREACH_NET = 0  # bad net
		CODE_UNREACH_HOST = 1  # bad host
		CODE_UNREACH_PROTO = 2  # bad protocol
		CODE_UNREACH_PORT = 3  # bad port
		CODE_UNREACH_NEEDFRAG = 4  # IP_DF caused drop
		CODE_UNREACH_SRCFAIL = 5  # src route failed
		CODE_UNREACH_NET_UNKNOWN = 6  # unknown net
		CODE_UNREACH_HOST_UNKNOWN = 7  # unknown host
		CODE_UNREACH_ISOLATED = 8  # src host isolated
		CODE_UNREACH_NET_PROHIB = 9  # for crypto devs
		CODE_UNREACH_HOST_PROHIB = 10  # ditto
		CODE_UNREACH_TOSNET = 11  # bad tos for net
		CODE_UNREACH_TOSHOST = 12  # bad tos for host
		CODE_UNREACH_FILTER_PROHIB = 13  # prohibited access
		CODE_UNREACH_HOST_PRECEDENCE = 14  # precedence error
		CODE_UNREACH_PRECEDENCE_CUTOFF = 15  # precedence cutoff

	class Quench(packetracer.Packet):
		__hdr__ = (
			("pad", "I", 0),
		)

	class Redirect(packetracer.Packet):
		__hdr__ = (
			("gw", "I", 0),
		)
		CODE_REDIRECT_NET = 0  # for network
		CODE_REDIRECT_HOST = 1  # for host
		CODE_REDIRECT_TOSNET = 2  # for tos and net
		CODE_REDIRECT_TOSHOST = 3  # for tos and host

	class RouterAdvertisement(packetracer.Packet):
		__hdr__ = (
			("numaddr", "B", 0),
			("addrsize", "B", 0),
			("lifetime", "H", 0)
		)

		CODE_RTRADVERT_NORMAL = 0  # normal
		CODE_RTRADVERT_NOROUTE_COMMON = 16  # selective routing
		CODE_RTRSOLICIT = 10  # router solicitation

	class RouterSelection(packetracer.Packet):
		__hdr__ = (
			("numaddr", "B", 0),
			("addrsize", "B", 0),
			("lifetime", "H", 0)
		)

	class TimeExceed(packetracer.Packet):
		__hdr__ = (
			("pad", "I", 0),
		)

		CODE_TIMEXCEED_INTRANS = 0  # ttl==0 in transit
		CODE_TIMEXCEED_REASS = 1  # ttl==0 in reass

	class ParamProblem(packetracer.Packet):
		__hdr__ = (
			("pointer", "B", 0),
			("unused", "3s", b"\x00" * 3)
		)

		CODE_PARAMPROB_ERRATPTR = 0  # req. opt. absent
		CODE_PARAMPROB_OPTABSENT = 1  # req. opt. absent
		CODE_PARAMPROB_LENGTH = 2  # bad length

	class Photuris(packetracer.Packet):
		class ParamProblem(packetracer.Packet):
			__hdr__ = (
				("reserved", "H", 0),
				("pointer", "H", 0)
			)

		CODE_PHOTURIS_UNKNOWN_INDEX = 0  # unknown sec index
		CODE_PHOTURIS_AUTH_FAILED = 1  # auth failed
		CODE_PHOTURIS_DECOMPRESS_FAILED = 2  # decompress failed
		CODE_PHOTURIS_DECRYPT_FAILED = 3  # decrypt failed
		CODE_PHOTURIS_NEED_AUTHN = 4  # no authentication
		CODE_PHOTURIS_NEED_AUTHZ = 5  # no authorization

	__handler__ = {
		(ICMP_ECHO, ICMP_ECHO_REPLY): Echo,
		ICMP_UNREACH: Unreach,
		ICMP_SRCQUENCH: Quench,
		ICMP_REDIRECT: Redirect,
		ICMP_RTRADVERT: RouterAdvertisement,
		ICMP_RTRSEL: RouterSelection,
		ICMP_TIMEXCEED: TimeExceed,
		ICMP_PARAMPROB: ParamProblem,
		ICMP_PHOTURIS: Photuris
	}
