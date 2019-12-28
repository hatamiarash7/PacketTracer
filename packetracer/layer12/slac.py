"""
Signal Level Attenuation Characterization (SLAC)
HomePlug Green PHY Specification
"""
import logging
import sys

from packetracer import packetracer
from packetracer.packetracer import Packet
from packetracer.structcbs import pack_H_le, unpack_H, unpack_H_le
from packetracer.triggerlist import TriggerList

logger = logging.getLogger("packetracer")

MASK_MSGTYPE_LE = 0xFCF9
MASK_MMTYPELSB_LE = 0x0300
MASK_MMTYPEMSB_LE = 0x0006

module_this = sys.modules[__name__]

# who defined all that useless messages???
TYPEINFO_DESCRIPTION = {
	# Central <-> Station
	0x0000: "CC_CCO_APPOINT",
	0x0004: "CC_BACKUP_APP",
	0x0008: "CC_LINK_INFO",
	0x000C: "CC_HANDOVER",
	0x0010: "CC_HANDOVER_INFO",
	0x0014: "CC_DISCOVER_LIST",
	0x0018: "CC_LINK_NEW",
	0x001C: "CC_LINK_MOD",
	0x0020: "CC_LINK_SQZ",
	0x0024: "CC_LINK_REL",
	0x0028: "CC_DETECT_REPORT",
	0x002C: "CC_WHO_RU",
	0x0030: "CC_ASSOC",
	0x0034: "CC_LEAVE",
	0x0038: "CC_SET_TEI_MAP",
	0x003C: "CC_RELAY",
	0x0040: "CC_BEACON_RELIABILITY.REQ",
	0x0044: "CC_ALLOC_MOVE",
	0x0048: "CC_ACCESS_NEW",
	0x004C: "CC_ACCESS_REL",
	0x0050: "CC_DCPPC",
	0x0054: "CC_HP1_DET",
	0x0058: "CC_BLE_UPDATE",
	0x005C: "CC_BCAST_REPEAT",
	0x0060: "CC_MH_LINK_NEW",
	0x0064: "CC_ISP_DetectionReport.IND",
	0x0068: "CC_ISP_StartReSync",
	0x006C: "CC_ISP_FinishReSync",
	0x0070: "CC_ISP_ReSyncDetected.IND",
	0x0074: "CC_ISP_ReSyncTransmit.REQ",
	0x0078: "CC_POWERSAVE.",
	0x007C: "CC_POWERSAVE_EXIT.REQ",
	0x0080: "CC_POWERSAVE_LIST.REQ",
	0x0084: "CC_STOP_POW",
	# Proxy Coordinator
	0x2000: "CP_PROXY_APPOINT",
	0x2004: "PH_PROXY_APPOINT",
	0x2008: "CP_PROXY_WAKE.",
	# CCo - CCo
	0x4000: "NN_INL.REQ",
	0x4004: "NN_NEW_NET.RE",
	0x4008: "NN_ADD_ALLOC.R",
	0x400C: "NN_REL_ALLOC.R",
	0x4010: "NN_REL_NET.IND",
	# Station - Station
	0x6000: "CM_UNASSOCIATED",
	0x6004: "CM_ENCRYPTED_PAYLOAD",
	0x6008: "CM_SET_KEY",
	0x600C: "CM_GET_KEY",
	0x6010: "CM_SC_JOIN",
	0x6014: "CM_CHAN_EST",
	0x6018: "CM_TM_UPDATE",
	0x601C: "CM_AMP_MAP",
	0x6020: "CM_BRG_INFO",
	0x6024: "CM_CONN_NEW",
	0x6028: "CM_CONN_REL",
	0x602C: "CM_CONN_MOD",
	0x6030: "CM_CONN_INFO",
	0x6034: "CM_STA_CAP",
	0x6038: "CM_NW_INFO",
	0x603C: "CM_GET_BEACON",
	0x6040: "CM_HFID",
	0x6044: "CM_MME_ERROR",
	0x6048: "CM_NW_STATS",
	0x604C: "CM_LINK_STATS",
	0x6050: "CM_ROUTE_INFO",
	0x6054: "CM_UNREACHABLE",
	0x6058: "CM_MH_CONN_NEW",
	0x605C: "CM_EXTENDED_TONEMASK",
	0x6060: "CM_STA_IDENTIFY",
	0x6064: "CM_SLAC_PARM",
	0x6068: "CM_START_ATTEN_CHAR",
	0x606C: "CM_ATTEN_CHAR",
	0x6070: "CM_PKCS_CERT",
	0x6074: "CM_MNBC_SOUND",
	0x6078: "CM_VALIDATE",
	0x607C: "CM_SLAC_MATCH",
	0x6080: "CM_SLAC_USER_DATA",
	0x6084: "CM_ATTEN_PROFILE",
	0xA0B8: "VS_PL_LNK_STATUS"
}

# reverse access of message IDs
for msgid, name in TYPEINFO_DESCRIPTION.items():
	setattr(module_this, name, msgid)

# Management message type LSB
MMTYPE_LSB_DESCRIPTION = {
	0x00: "MMTYPELSB_REQUEST",
	0x01: "MMTYPELSB_CONFIRM",
	0x02: "MMTYPELSB_INDICATION",
	0x03: "MMTYPELSB_RESPONSE"
}

for msgid, name in MMTYPE_LSB_DESCRIPTION.items():
	setattr(module_this, name, msgid)

# Management message type MSB
MMTYPE_MSB_DESCRIPTION = {
	0x00: "MMTYPEMSB_STA__CentralCoordinator",
	0x01: "MMTYPEMSB_ProxyCoordinator",
	0x02: "MMTYPEMSB_CentralCoordinator__CentralCoordinator",
	0x03: "MMTYPEMSB_STA__STA",
	0x04: "MMTYPEMSB_Manufacturer_Specific"
}

for msgid, name in MMTYPE_MSB_DESCRIPTION.items():
	setattr(module_this, name, msgid)


class CMSetKeyReq(Packet):
	__hdr__ = (
		("keytype", "B", 0),
		("mynonce", "I", 0),
		("yournonce", "I", 0),
		("pid", "B", 0),
		("prn", "H", 0),
		("pwm", "B", 0),
		("ccocapa", "B", 0),
		("nid", "7s", b"\x00" * 7),
		("neweks", "B", 0),
		# length = 0, 16
		("newkey", None, None),
	)


class CMSetKeyICnf(Packet):
	__hdr__ = (
		("result", "B", 0),
		("mynonce", "I", 0),
		("yournonce", "I", 0),
		("pid", "B", 0),
		("prn", "H", 0),
		("pwm", "B", 0),
		("ccocapa", "B", 0)
	)


class CMAttenCharInd(Packet):
	__hdr__ = (
		("apptype", "B", 0),
		("sectype", "B", 0),
		("sourceaddr", "6s", b"\x00" * 6),
		("runid", "Q", 0),
		("sourceid", "17s", b"\x00" * 17),
		("respid", "17s", b"\x00" * 17),
		("numsounds", "B", 0)
	)

	sourceaddr_s = packetracer.get_property_mac("sourceaddr")


class CMAttenCharRsp(Packet):
	__hdr__ = (
		("apptype", "B", 0),
		("sectype", "B", 0),
		("sourceaddr", "6s", b"\x00" * 6),
		("runid", "Q", 0),
		("sourceid", "17s", b"\x00" * 17),
		("respid", "17s", b"\x00" * 17),
		("result", "B", 0)
	)

	sourceaddr_s = packetracer.get_property_mac("sourceaddr")


class CMSlacParmReq(Packet):
	__hdr__ = (
		("apptype", "B", 0),
		("sectype", "B", 0),
		("runid", "Q", 0),
		# Only present if security type is 1
		("ciphersuitesize", "B", None),
		("ciphersuites", None, TriggerList)
	)


class CMSlacParmCnf(Packet):
	__hdr__ = (
		("msoundtarget", "6s", b"\x00" * 6),
		("numsounds", "B", 0),
		("timeout", "B", 0),
		("resptype", "B", 0),
		("forwardingsta", "6s", b"\x00" * 6),
		("apptype", "B", 0),
		("sectype", "B", 0),
		("runid", "Q", 0),
		# Only present if security type is 1
		("ciphersuite", "H", None)
	)

	msoundtarget_s = packetracer.get_property_mac("msoundtarget")
	forwardingsta_s = packetracer.get_property_mac("forwardingsta")


class CMStartAttenCharInd(Packet):
	__hdr__ = (
		("apptype", "B", 0),
		("sectype", "B", 0),
		("numsounds", "B", 0),
		("timeout", "B", 0),
		("resptype", "B", 0),
		("forwardingsta", "6s", b"\x00" * 6),
		("runid", "Q", 0),
	)

	forwardingsta_s = packetracer.get_property_mac("forwardingsta")


class CMMnbcSoundInd(Packet):
	__hdr__ = (
		("apptype", "B", 0),
		("sectype", "B", 0),
		("senderid", "17s", b"\x00" * 17),
		("cnt", "B", 0),
		("runid", "Q", 0),
		("rsvd", "8s", b"\x00" * 8),
		("rnd", "16s", b"\x00" * 16)
	)


class CMSlacMatchReq(Packet):
	__hdr__ = (
		("apptype", "B", 0),
		("sectype", "B", 0),
		("mvflen", "H", 0),
		("pevid", "17s", b"\x00" * 17),
		("pevmac", "6s", b"\x00" * 6),
		("evseid", "17s", b"\x00" * 17),
		("evsemac", "6s", b"\x00" * 6),
		("runid", "Q", 0),
		("rsvd", "8s", b"\x00" * 8)
	)

	def _get_mvflen_be(self):
		return unpack_H(pack_H_le(self.mvflen))[0]

	def _set_mvflen_be(self, val):
		self.mvflen = unpack_H(pack_H_le(val))[0]

	mvflen_be = property(_get_mvflen_be, _set_mvflen_be)

	pevmac_s = packetracer.get_property_mac("pevmac")
	evsemac_s = packetracer.get_property_mac("evsemac")


class CMSlacMatchCnf(Packet):
	__hdr__ = (
		("apptype", "B", 0),
		("sectype", "B", 0),
		("mvflen", "H", 0),
		("pevid", "17s", b"\x00" * 17),
		("pevmac", "6s", b"\x00" * 6),
		("evseid", "17s", b"\x00" * 17),
		("evsemac", "6s", b"\x00" * 6),
		("runid", "Q", 0),
		("rsvd1", "8s", b"\x00" * 8),
		("nid", "7s", b"\x00" * 7),
		("rsvd2", "B", 0),
		("nmk", "16s", b"\x00" * 16),
	)

	pevmac_s = packetracer.get_property_mac("pevmac")
	evsemac_s = packetracer.get_property_mac("evsemac")


class CMLinkStatsReq(Packet):
	__hdr__ = (
		("reqtype", "B", 0),
		("reqid", "B", 0),
		("nid", "7s", b"\x00" * 7),
		("lid", "B", 0),
		("tlflag", "B", 0),
		("mgmtflag", "B", 0),
		("dasa", "6s", b"\x00" * 6)
	)

	dasa_s = packetracer.get_property_mac("dasa")


# TODO: LinkStats payload as handler for CMLinkStatsCnf, how to differentiate?

class CMLinkStatsCnf(Packet):
	__hdr__ = (
		("reqid", "B", 0),
		("restype", "B", 0),
		("linkstats", "H", 0)
	)


class VSPLLinkStatusReq(Packet):
	__hdr__ = (
		("oui", "3s", b"\x00" * 3),
	)


class VSPLLinkStatusCnf(Packet):
	__hdr__ = (
		("oui", "3s", b"\x00" * 3),
		("link", "H", 0),
	)


class AMPMapReq(Packet):
	__hdr__ = (
		("amlen", "H", 0),
	)


class AMPMapCnf(Packet):
	__hdr__ = (
		("restype", "B", 0),
	)


class CMPKCSCertReq(Packet):
	__hdr__ = (
		("targetmac", "6s", b"\x00" * 6),
		("ciphersuitesize", "B", 0),
		("cipersuite", None, TriggerList)
	)

	targetmac_s = packetracer.get_property_mac("targetmac")


class CMPKCSCertCnf(Packet):
	__hdr__ = (
		("targetmac", "6s", b"\x00" * 6),
		("status", "B", 0),
		("cipersuite", "H", 0),
		("certlen", "H", 0),
		("certpackage", None, TriggerList)
	)

	targetmac_s = packetracer.get_property_mac("targetmac")


class CMPKCSCertInd(Packet):
	"""
	When the CM_SLAC_PARM.CNF indicates that Secure SLAC is required, the PEV-HLE
	shall send a CM_PKCS_CERT.IND message. The Target MAC address for this message
	shall be set to MAC address of the PEV Green PHY station. To ensure reliable
	reception of this message at all EVSEs, it is recommended that this message be
	transmitted at least three times by the PEV-HLE. If the CM_PKCS_CERT.IND message is
	larger than 502 Octets, the message shall be fragmented by the HLE (refer to
	Section 11.1.7).
	"""
	__hdr__ = (
		("targetmac", "6s", b"\x00" * 6),
		("cipersuite", "H", 0),
		("certlen", "H", 0),
		("certpackage", None, TriggerList)
	)

	targetmac_s = packetracer.get_property_mac("targetmac")


class CMPKCSCertRsp(Packet):
	__hdr__ = (
		("targetmac", "6s", b"\x00" * 6),
		("status", "B", 0),
		("ciphersuitesize", "B", 0),  # optional
		("cipersuite", None, TriggerList)
	)

	targetmac_s = packetracer.get_property_mac("targetmac")


MASK_FRAGINDEX = 0xF0
MASK_FRAGCOUNT = 0x0F


class Slac(Packet):
	__hdr__ = (
		("version", "B", 1),
		("typeinfo", "H", 0),  #
		("frag_info", "B", 0),
		("frag_seq", "B", 0)
	)

	__handler__ = {
		CM_SET_KEY | MMTYPELSB_REQUEST: CMSetKeyReq,
		CM_SET_KEY | MMTYPELSB_CONFIRM: CMSetKeyICnf,
		CM_SLAC_MATCH | MMTYPELSB_REQUEST: CMSlacMatchReq,
		CM_SLAC_MATCH | MMTYPELSB_CONFIRM: CMSlacMatchCnf,
		CM_ATTEN_CHAR | MMTYPELSB_INDICATION: CMAttenCharInd,
		CM_ATTEN_CHAR | MMTYPELSB_RESPONSE: CMAttenCharRsp,
		CM_SLAC_PARM | MMTYPELSB_REQUEST: CMSlacParmReq,
		CM_SLAC_PARM | MMTYPELSB_CONFIRM: CMSlacParmCnf,
		# MS:new
		CM_START_ATTEN_CHAR | MMTYPELSB_INDICATION: CMStartAttenCharInd,
		CM_MNBC_SOUND | MMTYPELSB_INDICATION: CMMnbcSoundInd,
		CM_LINK_STATS | MMTYPELSB_REQUEST: CMLinkStatsReq,
		CM_LINK_STATS | MMTYPELSB_CONFIRM: CMLinkStatsCnf,
		VS_PL_LNK_STATUS | MMTYPELSB_REQUEST: VSPLLinkStatusReq,
		VS_PL_LNK_STATUS | MMTYPELSB_CONFIRM: VSPLLinkStatusCnf,
		CM_AMP_MAP | MMTYPELSB_REQUEST: AMPMapReq,
		CM_AMP_MAP | MMTYPELSB_CONFIRM: AMPMapCnf,
		CM_PKCS_CERT | MMTYPELSB_REQUEST: CMPKCSCertReq,
		CM_PKCS_CERT | MMTYPELSB_CONFIRM: CMPKCSCertCnf,
		CM_PKCS_CERT | MMTYPELSB_INDICATION: CMPKCSCertInd,
		CM_PKCS_CERT | MMTYPELSB_RESPONSE: CMPKCSCertRsp
	}

	def _dissect(self, buf):
		typeinfo_be = unpack_H_le(buf[1: 3])[0]
		hlen = 5

		# VS_PL_LNK_STATUS does not have frag
		if typeinfo_be in {0xA0B8, 0xA0B9}:
			# logger.debug("disabling frag")
			self.frag_info = None
			self.frag_seq = None
			hlen = 3
		# logger.debug("Got type %X", typeinfo_be)
		self._init_handler(typeinfo_be, buf[hlen:])
		return hlen

	def _get_fragcount(self):
		return (self.frag_info & MASK_FRAGCOUNT)

	def _set_fragcount(self, fragcount):
		self.frag_info = (self.frag_info & ~MASK_FRAGCOUNT) | (fragcount & MASK_FRAGCOUNT)

	fragcount = property(_get_fragcount, _set_fragcount)

	def _get_fragindex(self):
		return (self.frag_info & MASK_FRAGINDEX) >> 4

	def _set_fragindex(self, fragindex):
		self.frag_info = (self.frag_info & ~MASK_FRAGINDEX) | ((fragindex << 4) & MASK_FRAGINDEX)

	fragindex = property(_get_fragindex, _set_fragindex)

	def _get_msgtype(self):
		typetmp = self.typeinfo & MASK_MSGTYPE_LE
		return unpack_H(pack_H_le(typetmp))[0]

	def _set_msgtype(self, msgtype):
		typetmp = unpack_H(pack_H_le(msgtype))[0]
		self.typeinfo = (self.typeinfo & ~MASK_MSGTYPE_LE) | (typetmp & MASK_MSGTYPE_LE)

	# base message type given as BE
	msgtype = property(_get_msgtype, _set_msgtype)

	def _get_msgtype_full(self):
		return unpack_H(pack_H_le(self.typeinfo))[0]

	def _set_msgtype_full(self, msgtype):
		self.typeinfo = unpack_H(pack_H_le(msgtype))[0]

	# set full typeinfo given as BE
	msgtype_full_be = property(_get_msgtype_full, _set_msgtype_full)

	def _get_msgtype_s(self):
		return TYPEINFO_DESCRIPTION.get(self.msgtype, None)

	msgtype_s = property(_get_msgtype_s)

	def _get_mmtypelsb(self):
		return (self.typeinfo & MASK_MMTYPELSB_LE) >> 8

	def _set_mmtypelsb(self, msgtype):
		typetmp = (self.typeinfo & ~MASK_MMTYPELSB_LE)
		self.typeinfo = typetmp | (msgtype << 8)

	# REQ->CNF, IND->RSP
	mmtypelsb = property(_get_mmtypelsb, _set_mmtypelsb)

	def _get_mmtypelsb_s(self):
		return MMTYPE_LSB_DESCRIPTION.get(self.mmtypelsb, None)

	mmtypelsb_s = property(_get_mmtypelsb_s, None)

	def _get_mmtypemsb(self):
		return (self.typeinfo & MASK_MMTYPEMSB_LE) >> 1

	def _set_mmtypemsb(self, msgtype):
		typetmp = (self.typeinfo & ~MASK_MMTYPEMSB_LE)
		self.typeinfo = typetmp | (msgtype << 1)

	mmtypemsb = property(_get_mmtypemsb, _set_mmtypemsb)

	def _get_mmtypemsb_s(self):
		return MMTYPE_MSB_DESCRIPTION.get(self.mmtypemsb, None)

	mmtypemsb_s = property(_get_mmtypemsb_s, None)
