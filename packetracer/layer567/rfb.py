"""
Remote Framebuffer Protocol
# http://www.realvnc.com/docs/rfbproto.pdf
# RFP uses dynamic ports 5900+, we won't auto-decode this!
"""
from packetracer import packetracer

# Client to Server Messages
CLIENT_SET_PIXEL_FORMAT			= 0
CLIENT_SET_ENCODINGS			= 2
CLIENT_FRAMEBUFFER_UPDATE_REQUEST	= 3
CLIENT_KEY_EVENT			= 4
CLIENT_POINTER_EVENT			= 5
CLIENT_CUT_TEXT				= 6

# Server to Client Messages
SERVER_FRAMEBUFFER_UPDATE		= 0
SERVER_SET_COLOUR_MAP_ENTRIES		= 1
SERVER_BELL				= 2
SERVER_CUT_TEXT				= 3


class RFB(packetracer.Packet):
	__hdr__ = (
		("type", "B", 0),
	)


class SetPixelFormat(packetracer.Packet):
	__hdr__ = (
		("pad", "3s", b"A" * 3),
		("pixel_fmt", "16s", b"A" * 16)
	)


class SetEncodings(packetracer.Packet):
	__hdr__ = (
		("pad", "1s", b"A"),
		("num_encodings", "H", 0)
	)


class FramebufferUpdateRequest(packetracer.Packet):
	__hdr__ = (
		("incremental", "B", 0),
		("x_position", "H", 0),
		("y_position", "H", 0),
		("width", "H", 0),
		("height", "H", 0)
	)


class KeyEvent(packetracer.Packet):
	__hdr__ = (
		("down_flag", "B", 0),
		("pad", "2s", b"A" * 2),
		("key", "I", 0)
	)


class PointerEvent(packetracer.Packet):
	__hdr__ = (
		("button_mask", "B", 0),
		("x_position", "H", 0),
		("y_position", "H", 0)
	)


class FramebufferUpdate(packetracer.Packet):
	__hdr__ = (
		("pad", "1s", b"A" * 1),
		("num_rects", "H", 0)
	)


class SetColourMapEntries(packetracer.Packet):
	__hdr__ = (
		("pad", "1s", b"A" * 1),
		("first_colour", "H", 0),
		("num_colours", "H", 0)
	)


class CutText(packetracer.Packet):
	__hdr__ = (
		("pad", "3s", b"A" * 3),
		("length", "I", 0)
	)
