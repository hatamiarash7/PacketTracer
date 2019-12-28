"""TriggerList for handling dynamic headers."""
import logging

logger = logging.getLogger("packetracer")

TRIGGERLIST_CONTENT_SIMPLE = {bytes, tuple}


class TriggerList(list):
	"""
	List with trigger-capabilities representing a Packet header.
	This list can contain any type of raw bytes, tuples like (key, value)
	or packets. Calling bin() will reassemble a content like
	[b"somebytes", mypacket, ("tuplekey", "tuplevalue")]
	to this: b"somebytes" + mypacket.bin() + ("tuplekey", "tuplevalue")[1].
	Custom reassemblation for tuples can be done by overwriting "_pack()".
	"""

	def __init__(self, packet, dissect_callback=None, buffer=b"", headerfield_name=""):
		"""
		packet -- packet where this TriggerList gets integrated
		dissect_callback -- callback which dessects byte string b"buffer", returns [a, b, c, ...]
		buffer -- byte string to be dissected
		headerfield_name -- name of this triggerlist when placed in a packet
		"""
		super().__init__()
		# set by external Packet
		# logger.debug(">>> init of TriggerList (contained in %s): %s" %
		# (packet.__class__.__name__, buffer))
		self._packet = packet
		self._dissect_callback = dissect_callback
		self._cached_result = buffer
		self._headerfield_name = headerfield_name

	def _lazy_dissect(self):
		if self._packet._unpacked == False:
			# Before changing TriggerList we need to unpack or
			# cached header won't fit on _unpack(...)
			# This is called before any changes to TriggerList so place it here.
			# Ignore if TriggerList changed in _dissect (_unpacked is None)
			self._packet._unpack()

		if self._dissect_callback is None:
			# already dissected, ignore
			return

		try:
			#logger.debug("Dissecting in TL")
			initial_list_content = self._dissect_callback(self._cached_result)
		except:
			# If anything goes wrong: raw bytes will be accessible in any case
			#logger.debug("Failed to dissect in TL")
			initial_list_content = [self._cached_result]

		self._dissect_callback = None
		# This is re-calling _lazy_dissect() but directly returning after second if
		# extend() is clearing cache -> remember cache
		cache_tmp = self._cached_result
		self.extend(initial_list_content)
		self._cached_result = cache_tmp

	# Python predefined overwritten methods

	def __getitem__(self, pos):
		self._lazy_dissect()
		return super().__getitem__(pos)

	def __iadd__(self, v):
		"""Item can be added using '+=', use 'append()' instead."""
		self._lazy_dissect()
		super().__iadd__(v)
		self.__refresh_listener([v])
		return self

	def __setitem__(self, k, v):
		self._lazy_dissect()
		try:
			# Remove listener from old packet which gets overwritten
			self[k].remove_change_listener(None, remove_all=True)
		except:
			pass
		super().__setitem__(k, v)
		self.__refresh_listener([v])

	def __delitem__(self, k):
		# logger.debug("removing elements: %r" % k)
		self._lazy_dissect()
		if type(k) is int:
			itemlist = [self[k]]
		else:
			# Assume slice: [x:y]
			itemlist = self[k]
		super().__delitem__(k)
		# logger.debug("removed, handle mod")
		self.__refresh_listener(itemlist, connect_packet=False)

	# logger.debug("finished removing")

	def __len__(self):
		self._lazy_dissect()
		return super().__len__()

	def __iter__(self):
		self._lazy_dissect()
		return super().__iter__()

	def append(self, v):
		self._lazy_dissect()
		super().append(v)
		# logger.debug("handling mod")
		self.__refresh_listener([v])

	# logger.debug("finished")

	def extend(self, v):
		self._lazy_dissect()
		super().extend(v)
		self.__refresh_listener(v)

	def insert(self, pos, v):
		self._lazy_dissect()
		super().insert(pos, v)
		self.__refresh_listener([v])

	def clear(self):
		self._lazy_dissect()
		items = [item for item in self]
		super().clear()
		self.__refresh_listener(items, connect_packet=False)

	def __refresh_listener(self, val, connect_packet=True):
		"""
		Handle modifications of this TriggerList (adding, removing, ...).
		WARNING: packets can only be put in one tl once at a time

		val -- list of bytes, tuples or packets
		connect_packet -- connect packet to this tl and parent packet
		"""
		for v in val:
			# Ignore non-packets
			if type(v) in TRIGGERLIST_CONTENT_SIMPLE:
				continue

			if connect_packet:
				# Allow packet in TL to access packet containing this TL:
				# packet1( TL[packet2->"access to packet1"] )
				v._triggelistpacket_parent = self._packet
				# TriggerList observes changes on packets:
				# base packet <- TriggerList (observes changes, set changed status
				# in basepacket) <- contained packet (changes)
				# Add change listener to the packet this TL is contained in.
				lwrapper = lambda: self._notify_change()
				v._add_change_listener(lwrapper)
			else:
				# Remove any old listener
				v._remove_change_listener()
				# Remove old parent
				v._triggelistpacket_parent = None
		# logger.debug("refreshed listener!")
		self._notify_change()

	def _notify_change(self):
		"""
		Update _header_changed and _header_format_changed of the Packet having
		this TriggerList as field and _cached_result.
		Called by: this list on changes or Packets in this list
		"""
		# logger.debug("!!! Packet notified about update: %r -> %r" % (self._packet.__class__, self))

		self._packet._header_changed = True
		self._packet._header_format_changed = True
		# List changed: old cache of TriggerList not usable anymore
		self._cached_result = None

	def bin(self):
		"""
		Output the TriggerLists elements as concatenated bytestring.
		Custom implementations for tuple-handling can be set by overwriting _pack().
		"""
		# logger.debug("packing triggerlist content")
		# logger.debug("sep in TriggerList: %r" % self._packet.sep)

		if self._cached_result is None:
			result_arr = []
			entry_type = None

			for entry in self:
				entry_type = type(entry)
				# logger.debug("type is: %r" % entry_type)

				if entry_type is bytes:
					result_arr.append(entry)
				elif entry_type is tuple:
					result_arr.append(self._pack(entry))
				else:
					# This Must be a packet, otherthise invalid entry!
					result_arr.append(entry.bin())

			self._cached_result = b"".join(result_arr)
		# logger.debug("new cached result: %s" % self._cached_result)

		return self._cached_result

	def find_pos(self, search_cb, offset=0):
		"""
		Find an item-position giving search callback as search criteria.

		search_cb -- callback to compare values, signature: callback(value) [True|False]
			Return True to return value found.
		offset -- start at index "offset" to search
		return -- index of first element found or None
		"""
		self._lazy_dissect()
		while offset < len(self):
			try:
				if search_cb(self[offset]):
					return offset
			except:
				# error on callback (unknown fields etc), ignore
				pass
			offset += 1
		# logger.debug("position not found")
		return None

	def find_value(self, search_cb, offset=0):
		"""
		Same as find_pos() but directly returning found value or None.
		"""
		self._lazy_dissect()
		try:
			return self[self.find_pos(search_cb, offset=offset)]
		except:
			return None

	def _pack(self, tuple_entry):
		"""
		This can  be overwritten to convert tuples in TriggerLists to bytes (see layer567/http.py)
		return -- byte string representation of this tuple entry
			eg (b"Host", b"localhost") -> b"Host: localhost"
		"""
		return tuple_entry[1]

	def __repr__(self):
		self._lazy_dissect()
		return super().__repr__()

	def __str__(self):
		self._lazy_dissect()
		tl_descr_l = []
		contains_pkt = False

		for val_tl in self:
			if type(val_tl) in TRIGGERLIST_CONTENT_SIMPLE:
				tl_descr_l.append("%s" % str(val_tl))
			else:
				# assume packet
				#pkt_fqn = val_tl.__module__[9:] + "." + val_tl.__class__.__name__
				#tl_descr_l.append(pkt_fqn)
				tl_descr_l.append("%s" % val_tl)
				contains_pkt = True

		if not contains_pkt or len(tl_descr_l) == 0:
			# Oneline output
			return "[" + ", ".join(tl_descr_l) + "]"
		else:
			# Multiline output
			final_descr = ["(see below)\n" + "-" * 10 + "\n"]

			for idx, val in enumerate(tl_descr_l):
				idx_descr = "%s[%d]" % (self._headerfield_name[1:], idx)
				final_descr.append("-> %s:\n%s\n" % (idx_descr, val))
			final_descr.append("-" * 10)
			return "".join(final_descr)

	def get_by_key(self, key_needle, idx_startat=0):
		"""
		Allow retrieving the value of a tuple key/value-pair.
		This isn't done via dictionaries as keys don't have to be unique.
		This isn't done by __getitem__ either because it would be to ambiguous
		in contrast to index access.

		key -- The key to ssearch for a value like (key, value). The search
			is case INsensitive!
		return -- First matching value corresponding to key like idx, b"value"
			or None, None if nothing was found

		"""
		try:
			key_needle = key_needle.lower()
		except:
			# not a string
			pass

		idx = self.find_pos(
			search_cb=lambda tpl: tpl[0] == key_needle or tpl[0].lower() == key_needle,
			offset=idx_startat)

		if idx is None:
			return None, None
		return idx, self[idx][1]

	def set_by_key(self, key_needle, value, idx_startat=0):
		"""
		Do inverse of get_by_key()
		"""
		try:
			key_needle = key_needle.lower()
		except:
			# not a string
			pass

		idx = self.find_pos(
			search_cb=lambda tpl: tpl[0] == key_needle or tpl[0].lower() == key_needle,
			offset=idx_startat)

		if idx is None:
			return
		# Update using original key
		self[idx] = (self[idx][0], value)
