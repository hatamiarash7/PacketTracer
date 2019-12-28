"""
Simple packet creation and parsing logic.
"""
import inspect
import logging
import random
import re
from ipaddress import IPv6Address, v6_int_to_packed
from struct import Struct

from packetracer.lazydict import LazyDict
# imported to make usable via import "packetracer.[FIELD_FLAG_AUTOUPDATE | FIELD_FLAG_IS_TYPEFIELD]"
from packetracer.packetracer_meta import MetaPacket
from packetracer.structcbs import pack_mac, unpack_mac, pack_ipv4, unpack_ipv4

logger = logging.getLogger("packetracer")
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.WARNING)

logger_streamhandler = logging.StreamHandler()
logger_formatter = logging.Formatter("%(levelname)s (%(funcName)s): %(message)s")
logger_streamhandler.setFormatter(logger_formatter)

logger.addHandler(logger_streamhandler)

PROG_NONVISIBLE_CHARS = re.compile(b"[^\x21-\x7e]")
HEADER_TYPES_SIMPLE = {int, bytes}

DIR_SAME = 1
DIR_REV = 2
DIR_UNKNOWN = 4
DIR_NOT_IMPLEMENTED = 255

ERROR_NONE = 0
ERROR_DISSECT = 1
ERROR_UNKNOWN_PROTO = 2
ERROR_NOT_UNPACKED = 4

VARFILTER_TYPES = {bytes, int}


class InvalidValuetypeException(Exception):
    pass


class Packet(object, metaclass=MetaPacket):
    """
    Base packet class, with metaclass magic to generate members from self.__hdr__ field.
    This class can be instatiated via:

        Packet(byte_string)
        Packet(key1=val1, key2=val2, ...)

    Every packet got a header and a body. Body-data can be raw byte string OR a packet itself
    (the body handler) which itself stores a packet etc. This continues until a packet only
    contains raw bytes (highest layer). The following schema illustrates the Packet-structure:

    Packet structure
    ================

    [Packet:
    headerfield_1
    headerfield_2
    ...
    headerfield_N
    [Body -> Packet:
        headerfield_1
        ...
        headerfield_N
        [Body: -> Packet:
            headerfields
            ...
            [Body: b"some_bytes"]
    ]]]

    A header definition like __hdr__ = (("name", "12s", b"defaultvalue"),) will define a header field
    having the name "name", format "12s" and default value b"defaultvalue" as bytestring. Fields will
    be added in order of definition. Extending classes should overwrite the "_dissect"-method in order to dissect
    given data.

    Requirements
    ============

    - Auto-decoding of headers via given format-patterns (defined via __hdr__)
    - Auto-decoding of body-handlers (IP -> parse IP-data -> add TCP-handler to IP -> parse TCP-data..)
    - Access of higher layers via layer1.higher_layer or "layer1[layerX]" notation
    - There are three types of headers:
    1) Simple constant fields (constant format)
        Format for __hdr__: ("name", "format", value [, FLAGS])

    2) Simple dynamic fields (byte string which changes in length)
        Format for __hdr__: ("name", None, b"bytestring" [, FLAGS])
        Such types MUST get initiated in _dissect() because there is no way in guessing
        the correct format when unpacking values!

    3) TriggerList (List containing Packets, bytes like b"xyz" or tuples like (ID, value))
        Format for __hdr__: ("name", None, TriggerList)

    The FLAGS value for simple constant and dynamic fields can be used to mark auto-update field
    (see packetracer_meta.py). This will create a variable XXX_au_active one time for a field XXX
    which can be used activate/deactivate the auto-update externally and which can be read in
    the bin()-method internally.
    - Convenient access for standard types (e.g. MAC, IP address) using string-representations
        This is done by appending "_s" to the attributename:
        ip.src_s = "127.0.0.1"
        ip_src_str = ip.src_s

        Implementation info:
        Convenient access should be set via varname_s = packetracer.Packet.get_property_XXX("varname")
        Get/set via is always done using strings (not byte strings).
    - Concatination via "layer1 + layer2 + layerX"
    - Header-values with length < 1 Byte should be set by using properties
    - Activate/deactivate non-TriggerList header fields by setting values (None=deactive, value=active)
    - Checksums (static auto fields in general) are auto-recalculated when calling
        bin(update_auto_fields=True) (default: active)
        The update-behaviour for every single field can be controlled via
        "pkt.VARNAME_au_active = [True|False]
    - Ability to check direction to other Packets via "[is_]direction()"
    - Access to next lower/upper layer
    - No correction of given raw packet-bytes e.g. checksums when creating a packet from it
        If the packet can't be parsed without correct data -> raise exception.
        The internal state will only be updated on changes to headers or data later on
    - General rule: less changes to headers/body-data = more performance

    Call-flows
    ==========

        packetracer(bytes)
            -> _dissect(): has to be overwritten, get to know/verify the real header-structure
                -> (optional): call _init_handler() initiating a handler representing an upper-layer
                -> (optional): call _init_triggerlist(name, b"bytes", dissect_callback)
                    to initiate a TriggerList field
                Note: headers won't be updated to buffer values until dissect finishes
            -> (optional) on access to simple headers: _unpack() sets all header values
            -> (optional) on access to TriggerList headers: lazy parsing gets triggered
            -> (optional) on access to body handler next upper layer gets initiated

        packetracer(keyword1=value, ...)
            -> (optional) set headers

        packetracer()
            -> sets standard values for simple headers

    """

    # Dict for saving "body type ids -> handler classes" globaly:
    # { class_name_current : {id_upper : handler_class_upper} }
    _id_handlerclass_dct = {}
    # Dict for saving "handler class -> body type ids" globaly:
    # { class_name_current : {handler_class_upper : id_upper} }
    _handlerclass_id_dct = {}
    # Constants for Packet-directions
    DIR_SAME = DIR_SAME
    DIR_REV = DIR_REV
    DIR_UNKNOWN = DIR_UNKNOWN
    DIR_NOT_IMPLEMENTED = DIR_NOT_IMPLEMENTED

    def __init__(self, *args, **kwargs):
        """
        Packet constructors:

        Packet(bytestring, target_class)
            Note: target_class is only meant for internal usage
        Packet(keyword1=val1, keyword2=val2, ...)

        bytestring -- packet bytes to build packet from, nonempty values are NOT allowed
        target_class -- For internal usage only: unpack until this class (meant eg for __getitem__(...))
        keywords -- keyword arguments correspond to header fields to be set
        """

        if args:
            if len(args) > 1:
                # Assume packet, target class given until which we unpack
                self._final_unpack_clz = args[1]._final_unpack_clz
            # Any Exception will be forwarded (SomePkt(bytes) or lazy dissect)
            # If this is the lowest layer the Exception has to be caught
            # logger.debug("dissecting: %s", self.__class__.__name__)
            header_len = self._dissect(args[0])
            # logger.debug("init header (+ body bytes): %s", self.__class__.__name__)
            # problem: len(args[0]) < _header_len -> can't be unpacked
            if len(args[0]) < header_len:
                raise Exception("Not enough bytes for packet class %s: given=%d < expected=%d" %
                                (self.__class__, len(args[0]), header_len))

            self._header_len = header_len
            self._header_cached = args[0][:header_len]

            if not self._body_changed:
                # _dissect(...) didn't call _init_handler(): set raw bytes.
                self._body_bytes = args[0][header_len:]
            # logger.warning("could not dissect in %s: %r" % (self.__class__.__name__, e))
            # Reset the changed-flags: original unpacked value = no changes
            self._reset_changed()
            self._unpacked = False
        else:
            if len(kwargs) > 0:
                # overwrite default parameters
                # logger.debug("new packet with keyword args (%s)", self.__class__.__name__)
                # _unpack is set to None: nothing to unpack until now

                for k, v in kwargs.items():
                    # logger.debug("setting: %s=%s", k, v)
                    setattr(self, k, v)
            # no reset: directly assigned = changed
            # keyword args means: allready unpacked (nothing to unpack)
            self._unpacked = True

    def _dissect(self, buf):
        """
        Dissect packet bytes by doing some (or nothing) of the following:
        - call self._init_triggerlist(...) to initiate TriggerLists
        - call self._init_handler(...) to initiate upper layer handler
        - activate/deactivate non-TriggerList fields by setting values/None to fields

        buf -- bytestring to be dissected
        return -- header length
        """
        # _dissect(...) was not overwritten: no changes to header, return original header length
        return self._header_len

    def __len__(self):
        """Return total length (= header + all upper layer data) in bytes."""
        if self._lazy_handler_data is not None:
            # lazy data present: avoid unneeded parsing
            # logger.debug("returning length from cached lazy handler in %s", self.__class__.__name__)
            return self.header_len + len(self._lazy_handler_data[1])
        elif self._higher_layer is not None:
            # logger.debug("returning length from present handler in %s, handler is: %s"\
            # % (self.__class__.__name__, self._higher_layer))
            return self.header_len + len(self._higher_layer)
        else:
            # Assume bodybytes are set
            # logger.debug("returning length from raw bytes in %s", self.__class__.__name__)
            return self.header_len + len(self._body_bytes)

    #
    # public access to header length: keep it uptodate
    #
    def _get_header_len(self):
        if self._header_changed and self._header_format_changed:
            # header has NOT changed if __init__ just finished -> avoid unneeded re-formating
            # update format to get the real length
            self._update_header_format()
        return self._header_len

    # update format if needed and return actual header size
    header_len = property(_get_header_len)

    def _get_dissect_error(self):
        return (self._errors & ERROR_DISSECT) != 0

    dissect_error = property(_get_dissect_error)
    errors = property(lambda obj: obj._errors)

    def is_error_present(self, error):
        """
        Check if one of packetracer.ERROR_XXX is present
        error -- the error to be check against internal error state
        """
        return (self._errors & error) != 0

    def _get_bodybytes(self):
        """
        Return raw data bytes or handler bytes (including all upper layers) if present.
        This is the same as calling bin() but excluding this header and without resetting changed-status.
        """
        if self._lazy_handler_data is not None:
            # no need to parse: raw bytes for all upper layers
            return self._lazy_handler_data[1]
        elif self._higher_layer is not None:
            # some handler was set
            hndl = self._higher_layer
            return hndl._pack_header() + hndl._get_bodybytes()
        else:
            # return raw bytes (no handler)
            return self._body_bytes

    def _set_bodybytes(self, value):
        """
        Set body bytes to value (bytestring). This will reset any handler.

        value -- a byte string (do NOT set to None)
        """
        if self._higher_layer is not None:
            # reset all handler data
            self._set_higherlayer(None)
        # logger.debug("setting new raw data: %s", value)
        self._body_bytes = value
        self._body_changed = True
        self._lazy_handler_data = None
        # logger.debug("notify after setting body bytes")
        self._notify_changelistener()

    # Get and set bytes for body. Note: this returns bytes even if higher_layer returns None.
    # Setting body_bytes will clear any handler (higher_layer will return None afterwards).
    body_bytes = property(_get_bodybytes, _set_bodybytes)

    def _get_higherlayer(self):
        """
        Retrieve next upper layer. This is the only direct way to do this.
        return -- handler object or None if not present.
        """
        if self._lazy_handler_data is not None:
            self._lazy_init_handler()
        return self._higher_layer

    @staticmethod
    def get_id_for_handlerclass(origin_class, handler_class):
        """
        return -- id associated for the given handler_class used in class origin_class.
            None if nothing was found. Example: origin_class = Ethernet, handler_class = IP,
            id will be ETH_TYPE_IP
        """
        try:
            return Packet._handlerclass_id_dct[origin_class][handler_class]
        except:
            # logger.debug("Could not find body handler id for %s in current class %s",
            # hndl.__class__, self.__class__)
            pass
        return None

    def _set_higherlayer(self, hndl):
        """
        Set body handler for this packet and make it accessible via layername[addedtypeclass]
        like ethernet[ip.IP]. If handler is None any handler will be reset and data will be set to an empty byte string.

        hndl -- the handler to be set: None or a Packet instance. Setting to None
            will clear any handler and set body_bytes to b"".
        """
        if self._higher_layer is not None:
            # clear old linked data of upper layer if body handler is already parsed
            # A.B -> A.higher_layer = x -> B.lower_layer = None
            # logger.debug("removing old data handler connections")
            self._higher_layer._lower_layer = None

        if hndl is None:
            # avoid (body_bytes=None, handler=None)
            self._body_bytes = b""
        else:
            # set a new body handler
            # associate ip, arp etc with handler-instance to call "ether.ip", "ip.tcp" etc
            self._body_bytes = None
            hndl._lower_layer = self

        self._higher_layer = hndl
        self._body_changed = True
        self._lazy_handler_data = None
        # logger.debug("notify after setting handler")
        self._notify_changelistener()

    # deprecated, wording "higher_layer/highest_layer layer is more consistent
    upper_layer = property(_get_higherlayer, _set_higherlayer)
    # Get/set body handler. Note: this will force lazy dissecting when reading
    higher_layer = property(_get_higherlayer, _set_higherlayer)

    def _set_lower_layer(self, val):
        if self._lower_layer is not None:
            # remove upper layer (us) from current lower layer before
            # setting a new lower layer
            self._lower_layer.higher_layer = None

        self._lower_layer = val

    # Get/set next lower body handler
    lower_layer = property(lambda pkt: pkt._lower_layer, _set_lower_layer)

    def _lowest_layer(self):
        current = self

        while current._lower_layer is not None:
            current = current._lower_layer

        return current

    def _get_highest_layer(self):
        current = self

        # unpack all layer, assuming string class will be never found
        self._final_unpack_clz = str.__class__

        while current.higher_layer is not None:
            current = current.higher_layer

        return current

    def _set_highest_layer(self, layer):
        """
        Replaces the current highest layer with a new one,
        eg with new layer "D" A.B.C becomes A.B.D.
        """
        layer_to_change = self.highest_layer.lower_layer

        if layer_to_change is None:
            return

        layer_to_change.higher_layer = layer

    # get lowest layer
    lowest_layer = property(_lowest_layer)
    # get top layer
    highest_layer = property(_get_highest_layer)

    def disconnect_layer(self):
        """
        Disconnect and return this layer. Connects lower and upper layer
        with each other. This is the same as 'pkt.lower_layer = pkt.higher_layer'
        without returning the middle layer (pkt).
        return -- This layer
        """
        # Connect lower/upper layer of this layer
        if self.lower_layer is not None and self.higher_layer is not None:
            self.lower_layer.higher_layer = self.higher_layer

        self.lower_layer = None
        self.higher_layer = None

        return self

    def _lazy_init_handler(self):
        """
        Lazy initialize the handler previously set by _init_handler.
        Make sure this is not called more than once
        """
        handler_data = self._lazy_handler_data

        try:
            # Instantiate handler class using lazy data buffer
            # See _init_handler() for 2nd place where handler instantation takes place
            # logger.debug("lazy parsing using: %s", handler_data)
            type_instance = handler_data[0](handler_data[1], self)

            self._set_higherlayer(type_instance)
            # this was a lazy init: same as direct dissecting -> no body change
            self._body_changed = False
        except:
            # error on lazy dissecting: set raw bytes
            self._errors |= ERROR_DISSECT
            self._body_bytes = handler_data[1]
        # logger.warning("Can't set handler data (malformed packet?): base=%s handler_type/handlerclass=%r, reason: %s",
        #	self.__class__, handler_data[0], ex)
        self._lazy_handler_data = None

    def __getitem__(self, packet_type):
        """
        Check every layer upwards (inclusive this layer) for the given Packet class
        and return the first matched instance or None if nothing was found.

        packet_type -- Packet class to search for like TCP or combined
            multi-value like Ethernet,IP,TCP. For multi-value the last
            given Type in sequence will be returned.
        return -- First finding of packet_type or None if nothing was found
        """
        p_instance = self

        # multi-value index search
        if type(packet_type) is tuple:
            type_cnt = 0
            packet_type_len = len(packet_type)

            for pkt_clz in packet_type:
                if pkt_clz != p_instance.__class__:
                    # mismatch
                    return None

                type_cnt += 1
                # highest layer reached
                if p_instance.higher_layer is None:
                    break
                elif type_cnt != packet_type_len:
                    # end of match sequence in packet_type not reached, go higher
                    p_instance = p_instance.higher_layer

            # return last matching layer
            return p_instance if type_cnt == packet_type_len else None
        # single-value index search
        else:
            # set most top layer to be unpacked, __getattr__() could be called unpacking lazy data
            self._final_unpack_clz = packet_type

            while not type(p_instance) is packet_type:
                # this will auto-parse lazy handler data via _get_higherlayer()
                p_instance = p_instance.higher_layer

                if p_instance is None:
                    break

            # logger.debug("returning found packet-handler: %s->%s", type(self), type(p_instance))
            return p_instance

    def __iter__(self):
        """
        Iterate over every layer starting from first layer.
        To start from the lowest layer use "for l in pkt.lowest_layer".
        """
        p_instance = self
        # Unpack until highest layer; assume string class never gets found as layer
        self._final_unpack_clz = str.__class__

        while p_instance is not None:
            yield p_instance
            # this will auto-parse lazy handler data via _get_higherlayer()
            p_instance = p_instance.higher_layer

            if p_instance is None:
                break

    def __contains__(self, clz):
        return self[clz] is not None

    def __eq__(self, clz):
        """
        Compare class of this object to the given class/object
        """
        # convert object to its class
        if not type(clz) == MetaPacket:
            clz = clz.__class__
        return self.__class__ == clz

    def dissect_full(self):
        """
        Recursive unpack ALL data inlcuding lazy header etc up to highest layer inlcuding danymic fields.
        """
        for name in self._header_field_names:
            self.__getattribute__(name)

        try:
            self.higher_layer.dissect_full()
        except:
            # no handler present
            pass

    def __add__(self, packet_or_bytes_to_add):
        """
        Concatinate a packet with another packet or bytes.
        Note: Beware of side effects as Packets remain connected until removed, eg via pkt.higher_layer = None.

        packet_or_bytes_to_add -- The packet or bytes to be added as highest layer
        """
        if type(packet_or_bytes_to_add) is not bytes:
            self.highest_layer.higher_layer = packet_or_bytes_to_add
        else:
            self.highest_layer.body_bytes += packet_or_bytes_to_add
        return self

    def __iadd__(self, packet_or_bytes_to_add):
        """
        Concatinate a packet with another packet or bytes.
        Note: Beware of side effects as Packets remain connected

        packet_or_bytes_to_add -- The packet or bytes to be added as highest layer
        """
        if type(packet_or_bytes_to_add) is not bytes:
            self.highest_layer.higher_layer = packet_or_bytes_to_add
        else:
            self.highest_layer.body_bytes += packet_or_bytes_to_add
        return self

    def split_layers(self):
        """
        Splits all layers to indepent ones starting from this one not connectedto each other
        e.g. A.B.C -> [A, B, C]
        return -- [layer1, layer2, ...]
        """
        layers = [layer for layer in self]

        for layer in layers:
            # avoid overwriting bytes, only reset handler
            if layer._body_bytes is None:
                layer.higher_layer = None
            layer.lower_layer = None
        return layers

    def _summarize(self):
        """
        Print a summary of this layer state. Shows all header, even deactivated ones.
        """
        # values need to be unpacked to be shown
        if not self._unpacked:
            self._unpack()

        # create key=value descriptions
        # show all header even deactivated ones
        layer_sums_l = []

        for name in self._header_field_names:
            name_real = name[1:]
            val = getattr(self, name_real)
            value_alt = ""
            value_translated = ""

            try:
                # Try to get convenient name
                value_alt = " = " + getattr(self, name_real + "_s")
            except:
                # Not set
                pass

            try:
                # Try to get translated name
                # logger.debug("Looking for translation: %s -> %s" % (self.__class__, name_real + "_t"))
                value_translated = getattr(self, name_real + "_t")

                if value_translated != "":
                    # Nothing found
                    value_translated = " = " + value_translated
            except:
                # Not set
                pass

            # Values: int
            if type(val) is int:
                format = getattr(self, name + "_format")
                layer_sums_l.append("%-12s (%s): 0x%X = %d = %s" % (name_real, format, val, val,
                                                                    bin(val)) + value_alt + value_translated)
            # Inactive
            elif val is None:
                layer_sums_l.append("%-16s: (inactive)" % name_real)
            else:
                # Values: bytes
                if type(val) is bytes:
                    bts_cnt = "(%d)" % len(val)
                    layer_sums_l.append("%-9s %6s: %s" % (name_real, bts_cnt, val) +
                                        value_alt + value_translated)
                # Values Triggerlist (can contain Packets, tuples, bytes)
                else:
                    layer_sums_l.append("%-16s: %s" % (name_real, val) + value_alt)

        if self.higher_layer is None:
            # No upper layer present: describe body bytes
            bts_cnt = "(%d)" % len(self.body_bytes)
            layer_sums_l.append("%-9s %6s: " % ("bodybytes", bts_cnt) + "%s" % self.body_bytes)

        layer_sums = "%s\n\t%s" % (
            self.__module__[9:] + "." + self.__class__.__name__,
            "\n\t".join(layer_sums_l))

        return layer_sums

    def __str__(self):
        # recalculate fields like checksums, lengths etc
        if self._header_changed or self._body_changed:
            # logger.debug("header/body changed: need to reparse (%s)", self.__class__)
            self.bin()
        # this does lazy init of handler
        upperlayer_str = "\n%s" % self.higher_layer if self.higher_layer is not None else ""
        return self._summarize() + upperlayer_str

    def _unpack(self):
        """
        Unpack a full layer (set field values) unpacked (extracted) from cached header bytes.
        This will use the current value of _header_cached to set all field values.
        NOTE:
        - This is only called by the Packet class itself
        - This is called prior to changing ANY header values
        """
        # Needed to set here (and not at the end) to avoid recursive calls
        self._unpacked = True
        # logger.debug("unpacking header: %s", self._header_field_names)
        # we need the whole format when:
        # format changed or some TriggestLists are non-empty (not yet dissected)
        if self._header_format_changed:
            self._update_header_format()

        # logger.debug("unpacking 1: %s, %s,\n%s,\n(format via xxx_format) %s,\n%s,\n%s\nformat.size %d\ncached size: %d" %
        #	(self.__class__,
        #	self._header_field_names,
        #	self._header_format.format,
        #	[self_getattr(name + "_format") for name in self._header_field_names],
        #	[self_getattr(name + "_active") for name in self._header_field_names],
        #	self._header_cached,
        #	self._header_format.size,
        #	len(self._header_cached)))

        # logger.debug([self_getattr(name) for name in self._header_field_names])
        try:
            header_unpacked = self._header_format.unpack(self._header_cached)
        except:
            self._errors |= ERROR_NOT_UNPACKED
            # just warn user about incomplete data
            errormsg = "could not unpack in: %s, format: %s, names: %s, value to unpack: %s (%d bytes)," \
                       " invalid value for format?" % (
                           self.__class__.__name__,
                           self._header_format.format,
                           self._header_field_names,
                           self._header_cached,
                           len(self._header_cached)
                       )

            logger.warning(errormsg)
            return
        # logger.debug("unpacking via format: %s -> %s", self._header_format.format, header_unpacked)
        cnt = 0
        self_setattr = self.__setattr__
        self_getattr = self.__getattribute__

        # logger.debug("unpacking 2: %s, %s -> %s,\n%s,\n %s\n",
        #	(self.__class__, header_unpacked, self._header_field_names,
        # 	[self_getattr(name + "_format") for name in self._header_field_names],
        # 	[self_getattr(name + "_active") for name in self._header_field_names])
        for name in self._header_field_names:
            # only set values if active simple field
            if self_getattr(name + "_active"):
                if self_getattr(name + "_format") is not None:
                    # logger.debug("!!!!! unpacking value: %s -> %s", name, header_unpacked[cnt])
                    self_setattr(name, header_unpacked[cnt])
                # inactive fields are not in unpacked list
                cnt += 1

    def reverse_address(self):
        """
        Reverse source <-> destination address of THIS packet. This is at minimum
        defined for: Ethernet, IP, TCP, UDP
        """
        pass

    def reverse_all_address(self):
        """
        Reverse source <-> destination address of EVERY packet upwards including this one
        (reverse_address has to be implemented).
        """
        current_hndl = self

        while current_hndl is not None:
            current_hndl.reverse_address()
            current_hndl = current_hndl.higher_layer

    def _init_handler(self, hndl_type, buffer):
        """
        Called by overwritten "_dissect()". 1) Store handler for later dissect or 2) directly dissect it.
        Notes for 2): Initiate the handler-parser using the given buffer and set it using _set_higherlayer()
        On any error this will set raw bytes given for body data.

        hndl_type -- A value to place the handler in the handler-dict like
            dict[Class.__name__][hndl_type] (eg type-id, port-number)
        buffer -- The buffer to be used to create the handler
        """
        # Empty buffer must lead to empty body. Initiating packets using empty buffer
        # would lead to wrong (default) values
        if len(buffer) == 0:
            # logger.debug("empty buffer given for _init_handler()!")
            return

        # self.__class__ MUST be contained, otherwise calling _init_handler() would be illegal
        try:
            # Likely to succeed
            clz = Packet._id_handlerclass_dct[self.__class__][hndl_type]
        except:
            self.body_bytes = buffer
            self._errors |= ERROR_UNKNOWN_PROTO
            # errormsg = "Unknown upper layer type for %s: %d, feel free to implement" % (
            #	self.__class__, hndl_type)
            # logger.warning(errormsg)
            return

        try:
            if self._final_unpack_clz is None or self._final_unpack_clz is self.__class__:
                # set lazy handler data, __getattr__() will be called on access
                # to handler (field not yet initiated)
                # logger.debug("setting handler name: %s -> %s", self.__class__.__name__, clz_name)
                self._lazy_handler_data = [clz, buffer]
                # set name although we don't set a handler (needed for direction() et al)
                self._body_bytes = None
                # avoid setting body_bytes by _unpack()
                self._body_changed = True
            else:
                # Continue parsing next upper layer, happens on "__iter__()": avoid unneeded lazy-data
                # handling/creating uneeded meta data for later body handling
                # logger.debug("--------> direct init in: %s", self.__class__.__name__)
                type_instance = clz(buffer, self)
                self._set_higherlayer(type_instance)
        except:
            # logger.warning("Can't set handler data (malformed?): base=%s handler_type/id=%r, reason: %s",
            #	self.__class__, Packet._id_handlerclass_dct[self.__class__][hndl_type], ex)
            # set raw bytes as data (eg handler class not found)
            self.body_bytes = buffer
            self._errors |= ERROR_DISSECT

    def _init_triggerlist(self, name, bts, dissect_callback):
        """
        Inititiate a TriggerList field. It will be dissected ondemand.

        name -- name of the dynamic filed to be initiated
        bts -- bts to be dissected
        dissect_callback -- callback to be used to dissect, signature:
            callback(bytes) -> returns list of bytes, packets, ...
        """
        self.__setattr__("_%s" % name, [bts, dissect_callback])
        self._header_format_changed = True

    def direction_all(self, other_packet):
        """
        Check for direction on ALL layers from this one upwards.
        This continues upwards until no body handler can be found anymore.
        The extending class can overwrite direction() to implement an individual check,

        other_packet -- Packet to be compared with this Packet
        return -- Bitwise AND-concatination of all directions of ALL layers starting from
            this one upwards. Directions are: [DIR_SAME | DIR_REV | DIR_UNKNOWN].
            This can be checked via eg "direction_found & DIR_SAME"
        """
        dir_ext = self.direction(other_packet)
        # logger.debug("direction of %s: %d", self.__class__, dir_ext)

        try:
            # check upper layers and combine current result
            # logger.debug("direction? checking next layer")
            dir_upper = self.higher_layer.direction_all(other_packet.higher_layer)

            return dir_ext & dir_upper
        except AttributeError:
            # one of both _higher_layer was None
            # Example: TCP ACK (last step of handshake, no payload) <-> TCP ACK + Telnet
            # logger.debug("AttributeError, direction: %d", dir_ext)
            # logger.debug(e)
            return dir_ext

    def direction(self, other):
        """
        Check if this layer got a specific direction compared to "other". Can be overwritten.

        return -- [DIR_SAME | DIR_REV | DIR_UNKNOWN | DIR_NOT_IMPLEMENTED]
        """
        return Packet.DIR_NOT_IMPLEMENTED

    def is_direction(self, packet2, direction):
        """
        Same as "direction_all()" but using explicit direction to be checked.
        As direction_all can be DIR_SAME and DIR_REV at the same time, this call
        is more clearly.

        packet2 -- packet to be compared to this packet
        direction -- check for this direction (DIR_...)
        return -- True if direction is found in this packet, False otherwise.
        """
        # logger.debug("direction_all & direction = %d & %d", self.direction_all(packet2), direction)
        return self.direction_all(packet2) & direction == direction

    def _update_higherlayer_id(self):
        """
        Updates the upperlayer id named by _id_fieldname (FIELD_FLAG_IS_TYPEFIELD was
        set) based on the upperlayer class and simply assigning the associated id to that field.

        Example: current layer = Ethernet, id field = type, body handler class = IP, eth.type
        will be set to ETH_TYPE_IP.

        If updating the type id is more complex than a simple assignmet this method has to
        be overwritten.
        """
        # do nothing if:
        # type id field not known or this is a parsed packet (non self-made) or we got no body handler
        # or nothing has changed
        # logger.debug("%s -> _id_fieldname: %s", self.__class__, self._id_fieldname)
        if self._id_fieldname is None \
                or not self._body_changed \
                or self._higher_layer is None \
                or not self.__getattribute__("%s_au_active" % self._id_fieldname) \
                or self._lazy_handler_data is not None:
            # logger.debug("Will NOT update!")
            return

        # logger.debug("will update handler id, %s / %s / %s / %s",
        #	self._id_fieldname,
        #	self.__getattribute__("%s_au_active" % self._id_fieldname),
        #	self._lazy_handler_data,
        #	self._body_changed)
        try:
            handler_clz = self._higher_layer.__class__
            # logger.debug("handler class is: %s", handler_clz)

            self.__setattr__(self._id_fieldname,
                             Packet._handlerclass_id_dct[self.__class__][handler_clz])
        except:
            # No type id found, something like eth + Telnet
            # logger.debug("no type id found for %s, class: %s -> %s" %
            #	(self._higher_layer.__class__, self.__class__, handler_clz))
            pass

    def _update_fields(self):
        """
        Overwrite this to update header fields. Only gets called if this or any other upper layer has changed.
        Callflow on a packet "pkt = layer1 + layer2 + layer3 -> pkt.bin()":
        layer3._update_fields() -> layer2._update_fields() -> layer1._update_fields() ...
        """
        pass

    def bin(self, update_auto_fields=True):
        """
        Return this header and body (including all upper layers) as byte string
        and reset changed-status.

        update_auto_fields -- if True auto-update fields like checksums, else leave them be
        """
        # Update all above layers until a non-handler layer is found
        if update_auto_fields and self._changed():
            # Collect layers to be updated:
            # Iterate update for A.B.C like C->B->A: A needs uptodate B and C,
            # B needs uptodate C
            layers = []
            layer_it = self

            while layer_it is not None:
                layers.append(layer_it)
                # Upper layer is not yet dissected but could need update:
                # ip:changed + tcp:notchanged/parsed -> tcp needs update
                if layer_it._lazy_handler_data is not None:
                    # Next upper layer forces update in layet_it
                    if layer_it._header_changed and \
                            layer_it._lazy_handler_data[0].__class__ in layer_it._update_dependants:
                        # Force dissecting
                        layer_it = layer_it.higher_layer
                    else:
                        layer_it = None
                else:
                    layer_it = layer_it.higher_layer
            # Start from the top
            layers.reverse()

            for layer in layers:
                layer._update_fields()

        if self._lazy_handler_data is not None:
            # logger.debug("Got lazy data layer: %s -> %s", self.__class__, self._lazy_handler_data[0])
            # no need to parse, just take lazy handler data bytes
            bodybytes_tmp = self._lazy_handler_data[1]
        elif self._higher_layer is not None:
            # logger.debug("Got upper layer: %s -> %s", self.__class__, self._higher_layer.__class__)
            # Don't update fields, this was already done above
            bodybytes_tmp = self.higher_layer.bin(update_auto_fields=False)
        else:
            # logger.debug("Got raw bytes in %s", self.__class__)
            # raw bytes
            bodybytes_tmp = self._body_bytes

        header_tmp = self._pack_header()

        # now every layer got informed about our status, reset it
        self._reset_changed()
        return header_tmp + bodybytes_tmp

    def _update_header_format(self):
        """
        Update format of this packet header. Needs to be called on changes to dynamic fields.
        """
        header_format = [">"]
        header_format_append = header_format.append
        self_getattr = self.__getattribute__

        for name in self._header_field_names:
            if not self_getattr(name + "_active"):
                continue

            val = self_getattr(name)

            if val.__class__ in HEADER_TYPES_SIMPLE:  # assume bytes/int
                header_format_append(self_getattr(name + "_format"))
            # logger.debug("adding format for (simple): %s, %s, val: %s format: %s",
            # self.__class__, name, self_getattr(name), self_getattr(name + "_format"))
            else:  # assume TriggerList
                if val.__class__ == list:
                    # TriggerList not yet initiated: take cached value
                    header_format_append("%ds" % len(val[0]))
                # logger.debug("adding format for: %s, %s, val: %s", self.__class__, name, val[0])
                else:
                    # Assume packet
                    header_format_append("%ds" % len(val.bin()))

        self._header_format = Struct("".join(header_format))
        self._header_len = self._header_format.size
        self._header_format_changed = False

    def _pack_header(self):
        """
        Return header as byte string.
        """
        if not self._header_changed:
            # return cached data if nothing changed
            # logger.warning("returning cached header (hdr changed=%s): %s->%s",
            # self._header_changed, self.__class__.__name__, self._header_cached)
            return self._header_cached

        if not self._unpacked:
            # this happens on: Packet(b"bytes") -> only changes to TriggerList. We need to unpack buffer values
            # to re-read them for header packing
            self._unpack()
        elif self._header_format_changed:
            # _unpack will call _update_header_format() if needed
            # real format needed for correct packing
            self._update_header_format()

        self_getattr = self.__getattribute__
        header_values = []
        header_values_append = header_values.append

        for name in self._header_field_names:
            if not self_getattr(name + "_active"):
                continue
            val = self_getattr(name)
            # two options:
            # - simple type (int, bytes, ...)	-> add given value
            # - TriggerList	(found via format None) -> call bin()
            if val.__class__ in HEADER_TYPES_SIMPLE:  # assume bytes/int
                header_values_append(val)
            else:  # assume TriggerList
                if val.__class__ == list:
                    header_values_append(val[0])
                else:
                    # Assume packet
                    header_values_append(val.bin())

        # logger.debug("header bytes for %s: %s = %s",
        # 	self.__class__.__name__, self._header_format.format, header_bytes)
        # Individual unpacking is about 4 times slower than cumulative
        self._header_cached = self._header_format.pack(*header_values)
        # logger.debug(">>> cached header: %s (%d)", self._header_cached, len(self._header_cached))
        self._header_changed = False

        return self._header_cached

    # readonly access to header
    header_bytes = property(_pack_header)

    def _changed(self):
        """
        Check if this or any upper layer changed in header or body

        return -- True if header or body changed, else False
        """
        changed = False
        p_instance = self

        while p_instance is not None:
            if p_instance._header_changed or p_instance._body_changed:
                changed = True
                break
            elif p_instance._lazy_handler_data is None:
                # one layer up, stop if next layer is not yet initiated which means: no change
                p_instance = p_instance.higher_layer
            else:
                # nothing changed upwards: lazy handler data still present/nothing got parsed
                break
        return changed

    def _reset_changed(self):
        """Set the header/body changed-flag to False. This won't clear caches."""
        self._header_changed = False
        self._body_changed = False

    def _add_change_listener(self, listener_cb):
        """
        Add a new callback to be called on changes to header or body.

        listener_cb -- the change listener to be added as callback-function
        """
        try:
            self._changelistener.add(listener_cb)
        except:
            # change listener not yet initiated
            self._changelistener = {listener_cb}

    def _remove_change_listener(self):
        """
        Remove all change listener.
        """
        if self._changelistener is not None:
            self._changelistener.clear()

    def _notify_changelistener(self):
        """
        Notify listener about changes in header or body using signature callback(self).
        This is primarily meant for triggerlist to react
        on changes in packets like Triggerlist[packet1, packet2, ...].
        """
        # logger.debug("packet is notifying!!!")
        # no listener added so far -> nothing to notify
        if self._changelistener is None:
            return

        for listener_cb in self._changelistener:
            # logger.debug("notify...")
            listener_cb()

    @classmethod
    def load_handler(cls, clz_add, handler):
        """
        Load Packet handler classes using a shared dictionary.

        clz_add -- class for which handler has to be added
        handler -- dict of handlers to be set like { id | (id1, id2, ...) : class }, id can be a tuple of values
        """
        if clz_add in Packet._id_handlerclass_dct:
            # logger.debug("handler already loaded: %s", clz_name)
            return

        # logger.debug("adding classes as handler: [%s] = %s", clz_add, handler)

        Packet._id_handlerclass_dct[clz_add] = {}
        Packet._handlerclass_id_dct[clz_add] = {}

        for handler_id, packetclass in handler.items():
            # packetracer.Packet.load_handler(IP, { ID : class } )
            if type(handler_id) is not tuple:
                Packet._id_handlerclass_dct[clz_add][handler_id] = packetclass
                Packet._handlerclass_id_dct[clz_add][packetclass] = handler_id
            else:
                # logger.debug("loading multi-it handler: clz_add=%s, packetclass=%s, handler_id[0]=%s" %
                #	(clz_add, packetclass, handler_id[0]))
                # packetracer.Packet.load_handler(IP, { (ID1, ID2, ...) : class } )
                for id_x in handler_id:
                    Packet._id_handlerclass_dct[clz_add][id_x] = packetclass
                # ambiguous relation of "handler class -> type ids", take 1st one
                Packet._handlerclass_id_dct[clz_add][packetclass] = handler_id[0]

    def hexdump(self, length=16, only_header=False):
        """
        length -- amount of bytes per line
        only_header -- if True: just dump header, else header + body (default)

        return -- hexdump output string for this packet (header or header + body).
        """
        bytepos = 0
        res = []

        if only_header:
            buf = self._pack_header()
        else:
            buf = self.bin()
        buflen = len(buf)

        while bytepos < buflen:
            line = buf[bytepos: bytepos + length]
            hexa = " ".join(["%02x" % x for x in line])
            # line = line.translate(__vis_filter)
            line = re.sub(PROG_NONVISIBLE_CHARS, b".", line)
            res.append("  %04d:      %-*s %s" % (bytepos, length * 3, hexa, line))
            bytepos += length
        return "\n".join(res)


#
# utility functions
# These could be put into separate modules but this would lead to recursive import problems.
#
# avoid unneeded references for performance reasons
randint = random.randint


def byte2hex(buf):
    """Convert a bytestring to a hex-represenation:
    b'1234' -> '\x31\x32\x33\x34'"""
    return "\\x" + "\\x".join(["%02X" % x for x in buf])


# MAC address
def mac_str_to_bytes(mac_str):
    """Convert mac address AA:BB:CC:DD:EE:FF to byte representation."""
    return b"".join([bytes.fromhex(x) for x in mac_str.split(":")])


def mac_bytes_to_str(mac_bytes):
    """Convert mac address from byte representation to AA:BB:CC:DD:EE:FF."""
    return "%02X:%02X:%02X:%02X:%02X:%02X" % unpack_mac(mac_bytes)


def get_rnd_mac():
    """Create random mac address as bytestring"""
    return pack_mac(randint(0, 255), randint(0, 255), randint(0, 255),
                    randint(0, 255), randint(0, 255), randint(0, 255))


def get_property_mac(varname):
    """Create a get/set-property for a MAC address as string-representation."""
    # logger.debug("--------------------- returning property")
    return property(
        lambda obj: mac_bytes_to_str(obj.__getattribute__(varname)),
        lambda obj, val: obj.__setattr__(varname, mac_str_to_bytes(val))
    )


# IPv4 address
def ip4_str_to_bytes(ip_str):
    """Convert ip address 127.0.0.1 to byte representation."""
    ips = [int(x) for x in ip_str.split(".")]
    return pack_ipv4(ips[0], ips[1], ips[2], ips[3])


def ip4_bytes_to_str(ip_bytes):
    """Convert ip address from byte representation to 127.0.0.1."""
    return "%d.%d.%d.%d" % unpack_ipv4(ip_bytes)


def get_rnd_ipv4():
    """Create random ipv4 adress as bytestring"""
    return pack_ipv4(randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255))


def get_property_ip4(var):
    """Create a get/set-property for an IP4 address as string-representation."""
    return property(
        lambda obj: ip4_bytes_to_str(obj.__getattribute__(var)),
        lambda obj, val: obj.__setattr__(var, ip4_str_to_bytes(val))
    )


# IPv6 address
def ip6_str_to_bytes(ip6_str):
    """Convert ip address 127.0.0.1 to byte representation."""
    return v6_int_to_packed(int(IPv6Address(ip6_str)))


def ip6_bytes_to_str(ip6_bytes):
    """Convert ip address from byte representation to 127.0.0.1."""
    return str(IPv6Address(ip6_bytes))


def get_property_ip6(var):
    """Create a get/set-property for an IP6 address as string-representation."""
    return property(
        lambda obj: ip6_bytes_to_str(obj.__getattribute__(var)),
        lambda obj, val: obj.__setattr__(var, ip6_str_to_bytes(val))
    )


# DNS names
def dns_name_decode(name, cb_mc_bytes=lambda: b""):
    """
    DNS domain name decoder (bytes to string)

    name -- example: b"\x03www\x07example\x03com\x00"
    cb_bytes -- callback to get bytes used to find name in case of Message Compression
        cb_bytes_pointer(): bytes
    return -- example: "www.example.com."
    """
    # ["www", "example", "com"]
    name_decoded = []
    parsed_pointers = set()
    off = 1
    buf = name

    while off < len(buf):
        size = buf[off - 1]
        if size == 0:
            break
        elif (size & 0b11000000) == 0:
            # b"xxx" -> "xxx"
            name_decoded.append(buf[off:off + size].decode())
            off += size + 1
        else:
            # DNS message compression
            off = (((buf[off - 1] & 0b00111111) << 8) | buf[off]) + 1
            buf = cb_mc_bytes()
            # logger.debug("Got compressed DNS: %s" % buf)

            if off in parsed_pointers:
                # dns message loop, abort...
                break
            parsed_pointers.add(off)
    return ".".join(name_decoded) + "."


def dns_name_encode(name):
    """
    DNS domain name encoder (string to bytes)

    name -- example: "www.example.com"
    return -- example: b'\x03www\x07example\x03com\x00'
    """
    name_encoded = [b""]
    # "www" -> b"www"
    labels = [part.encode() for part in name.split(".") if len(part) != 0]

    for label in labels:
        # b"www" -> "\x03www"
        name_encoded.append(chr(len(label)).encode() + label)
    return b"".join(name_encoded) + b"\x00"


def get_property_dnsname(var, cb_mc_bytes=lambda obj: b""):
    """
    Create a get/set-property for a DNS name.

    cb_bytes -- callback to get bytes used to find name in case of Message Compression
        cb_bytes_pointer(containing_obj) -- bytes
    """
    return property(
        lambda obj: dns_name_decode(obj.__getattribute__(var),
                                    cb_mc_bytes=lambda: cb_mc_bytes(obj)),
        lambda obj, val: obj.__setattr__(var, dns_name_encode(val))
    )


def get_property_bytes_num(var, format_target):
    """
    Creates a get/set-property for "bytes (format Xs) <-> number" where len(bytes) is not 2**x.
    Sometimes numbers aren't encoded as multiple of 2 (see SSL -> Handshake -> 3 bytes = integer???).
    That's bad. How to convert between both representations? Well...

    var -- varname to create a property for
    format_target -- real format of the theader used to create a number.

    Note: only use with static headers
    """
    format_target_struct = Struct(format_target)
    format_target_unpack = format_target_struct.unpack
    format_target_pack = format_target_struct.pack
    format_varname_s = ("_%s" % var) + "_format"

    def get_formatlen_of_var(obj):
        format_var_s = obj.__getattribute__(format_varname_s)

        if format_var_s is None:
            logger.warning("Got None format for %s, can't convert for convenience!", var)
            return 0

        return Struct(format_var_s).size

    def get_val_bts_to_int(obj):
        format_var_len = get_formatlen_of_var(obj)
        prefix_bts = (b"\x00" * (format_target_struct.size - format_var_len))
        return format_target_unpack(prefix_bts + obj.__getattribute__(var))[0]

    def set_val_int_to_bts(obj, val):
        format_var_len = get_formatlen_of_var(obj)
        obj.__setattr__(var, format_target_pack(format_target, val)[:-format_var_len])

    return property(
        # bytes -> int
        get_val_bts_to_int,
        # int -> bytes
        set_val_int_to_bts
    )


def get_property_translator(
        varname,
        varname_regex,
        cb_get_description=lambda value, value_name_dct: value_name_dct[value]):
    """
    Get a descriptor allowing to make a value->name translation for variable values

    varname_regex -- The regex to find variables.
    cb_get_description -- lambda value, value_name_dct: Description
    return -- property allowing get-access to get an descriptive name
    """
    # Get globals of calling module containing the variables in question
    globals_caller = inspect.stack()[1][0].f_globals

    def collect_cb():
        varname_pattern = re.compile(varname_regex)
        return {value: name for name, value in globals_caller.items() if
                type(value) in VARFILTER_TYPES and varname_pattern.match(name)}

    ldict = LazyDict(collect_cb)

    def descricptor_cb(value):
        if value not in ldict:
            return ""

        # logger.debug("Trying to get description!")
        return cb_get_description(value, ldict)

    # Only get access
    return property(
        lambda obj: descricptor_cb(obj.__getattribute__(varname))
    )


def get_ondemand_property(varname, initval_cb):
    """
    Creates a property whose value gets initialized ondemand.
    This is meant as an alternative to an initialization in __init__
    to decrease initial loading time
    """
    varname_shadowed = "_%s" % varname

    def get_var(self):
        try:
            return self.__getattribute__(varname_shadowed)
        except:
            val = initval_cb()
            self.__setattr__(varname_shadowed, val)
            return val

    def set_var(self, value):
        return self.__setattr__(varname_shadowed, value)

    return property(get_var, set_var)
