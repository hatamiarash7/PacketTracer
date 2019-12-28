import pkgutil
import importlib

from packetracer.packetracer import Packet
module_packetracer = importlib.import_module("packetracer")

for importer, modname, ispkg in pkgutil.walk_packages(path=module_packetracer.__path__,
	prefix=module_packetracer.__name__ + ".",
	onerror=lambda x: None):

	if ispkg:
		#print(">>> found package: %s" % modname)
		pass
	else:
		mod = importlib.import_module(modname)

print("# All packetracer packet classes, their header names and default values ")

packet_subclasses = Packet.__subclasses__()
name_fullclass = {clz.__module__ + "." + clz.__name__: clz for clz in packet_subclasses}
name_fullclass = [(key, value) for key, value in sorted(name_fullclass.items())]

for name, clz in name_fullclass:
	#print(">> %s" % name)
	obj = clz()
	print("%s" % obj)
	print()
