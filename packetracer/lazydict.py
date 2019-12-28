import logging

logger = logging.getLogger("packetracer")


class LazyDict(dict):
	def __init__(self, cb_createentries):
		super().__init__()
		self._cb_createentries = cb_createentries

	def _lazy_init(self):
		if self._cb_createentries is None:
			return

		new_entries = self._cb_createentries()
		#logger.debug("Updating dict: %s" % new_entries)
		self.update(new_entries)
		self._cb_createentries = None

	# Python predefined overwritten methods
	# TODO: not all functions overwritten yet
	def __contains__(self, key):
		self._lazy_init()
		return super().__contains__(key)

	def __getitem__(self, key):
		self._lazy_init()
		return super().__getitem__(key)

	def __setitem__(self, key, value):
		self._lazy_init()
		super().__setitem__(key, value)

	def __delitem__(self, key):
		self._lazy_init()
		pass

	def __str__(self):
		self._lazy_init()
		return super().__str__()

	def __iter__(self):
		self._lazy_init()
		super().__iter__()

	def __len__(self):
		self._lazy_init()
		return super().__len__()

	def items(self):
		self._lazy_init()
		return super().items()
