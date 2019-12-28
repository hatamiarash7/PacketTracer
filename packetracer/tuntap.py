"""
Wraper for TUN/TAP interfaces.
https://www.kernel.org/doc/Documentation/networking/tuntap.txt

packets written to /dev/net/tun look like "outer network -> tunX" (coming for another network)
and get handled by the kernel state machine.

> Prerequisites
mkdir /dev/net
# Create the character device /dev/net/XXX and let it point to major number 10, minor number 200.
# The devnode has to be used in "TuntapInterface -> devnode": When "/dev/net/xxx" is used this
# will create the interface xxx0
mknod /dev/net/tunA c 10 200
mknod /dev/net/tunB c 10 200

mknod /dev/net/tapA c 10 200
mknod /dev/net/tapB c 10 200

> Test tunnel
ping4 -c 1  -I tunA0 192.168.12.35; ping4  -c 1 -I tunB0 192.168.12.34
ping4 -c 1  -I tapA0 192.168.12.35; ping4  -c 1 -I tapB0 192.168.12.34

> Notes
Routing (fd -> tun/tap -> eth -> internet -> eth -> tun/tap -> fd):
	tap works (mac_src=anything, mac_dst=tap, ip_src/dst: like tun)
	tun works (ip_src=tun, ip_dst=server)
		Advantage over tap: no icmp-messages on returning packets.

> Useful commands
ip tuntap add dev tun0 mode tun user mike group users
ip addr add 192.168.3.1/24 dev tun0
ip rule list; ip link show
ip tuntap del dev tun0 mode tun; ip tuntap del dev tun1 mode tun;
# If "ip tuntap del dev tunA0 mode tun" does not work
ip link delete tunA0
"""

from fcntl import ioctl
import os
from os import read as os_read
from os import write as os_write
import struct
import time
import threading
import subprocess
import logging
import pathlib

from packetracer.layer12 import ethernet
from packetracer.layer3 import ip
from packetracer import utils

logger = logging.getLogger("packetracer")

# Some constants used to ioctl the device file
TUNSETIFF	= 0x400454CA
TUNSETOWNER	= TUNSETIFF + 2
SG_SET_TIMEOUT	= 0x2201
IFF_TUN		= 0x0001
IFF_TAP		= 0x0002
#  The kernel adds a 4-byte preamble to the frame, avoid this
# TODO: set lowest layer based on meta info
"""
3.2 Frame format:
If flag IFF_NO_PI is not set each frame format is:
	Flags [2 bytes]
	Proto [2 bytes]
	Raw protocol(IP, IPv6, etc) frame.
"""
IFF_NO_PI	= 0x1000

TYPE_TUN	= 0
TYPE_TAP	= 1

TYPE_STR_DCT = {TYPE_TUN: "tun", TYPE_TAP: "tap"}


def exec_syscmd(cmd):
	output = subprocess.getoutput(cmd)
	logger.info(output)


class TuntapInterface(object):
	def __init__(self,
		iface_name,
		devnode="/dev/net/tunA",
		ifacetype=TYPE_TUN,
		ip_src="12.34.56.1",
		ip_dst="12.34.56.2",
		is_local_tunnel=False):
		"""
		iface_name -- name of the local interface to be used. See devnode.
		devnode -- Path to the devnoce used for this interface. /dev/net/tunA will result in iface_name tunA0, tunA1 etc.
		ifacetype -- TYPE_TUN or TYPE_TAP
		ip_src -- Local IP address of the interface iface_name (/32 address will be used)
		ip_dst -- Remote connection point of the local interface iface_name (/32 address will be used)
		is_local_tunnel -- True is endpoint is also local, otherwise False
		"""

		self._closed = False
		self._iface_name = iface_name
		self._devnode = devnode
		self._is_newly_created = False
		self._ifacetype = ifacetype
		self._is_local_tunnel = is_local_tunnel

		TuntapInterface.create_devnode(devnode)

		# Open TUN or TAP device file
		self._iface_fd = open(devnode, "r+b", buffering=0)
		tuntap_opt = IFF_TUN if ifacetype == TYPE_TUN else IFF_TAP
		self._ifr = struct.pack("16sH", iface_name.encode("UTF-8"), tuntap_opt | IFF_NO_PI)
		# Connect interface name with file descriptor. Creates the actual network interface.
		ioctl(self._iface_fd, TUNSETIFF, self._ifr)
		#ioctl(self._iface_fd, SG_SET_TIMEOUT, 1000)
		self._fileno_iface_fd = self._iface_fd.fileno()
		# Optionally, we want it be accessed by the normal user.
		# ioctl(self._iface_fd, TUNSETOWNER, 1000)

		if ip_src is not None and ip_dst is not None:
			TuntapInterface.configure_interface(iface_name, ip_src, ip_dst, is_local_tunnel=is_local_tunnel)
		utils.set_interface_state(iface_name, state_active=True)

	is_newly_created = property(lambda self: self._is_newly_created)

	@staticmethod
	def create_devnode(devnode):
		"""
		Create the given devnode if not already present.
		devnode -- Name of the devnode which will be created: "/dev/net/devnode"
		"""
		if pathlib.Path(devnode).exists():
			#logger.debug("devnode %s already exists" % devnode)
			return

		#logger.debug("Creating devnode: %s" % devnode)
		exec_syscmd("mkdir /dev/net")
		exec_syscmd("mknod %s c 10 200" % devnode)

	@staticmethod
	def configure_interface(iface_name, ip_src, ip_dst, is_local_tunnel=False):
		"""
		is_local_tunnel -- Adjust routing rules so that this interface can be used locally (eg tun0 <-> tun1
			where tun0 and tun1 are both local interfaces)
		"""
		# Wait for interface to be created
		#time.sleep(1)
		#output = exec_syscmd("ifconfig %s %s/24" % (iface_name, ip_src))
		#output = exec_syscmd("ifconfig %s %s/24 pointopoint %s" % (iface_name, ip_src, ip_dst))
		#output = exec_syscmd("ifconfig %s %s pointopoint %s" % (iface_name, ip_src, ip_dst))
		exec_syscmd("ifconfig %s %s/24" % (iface_name, ip_src))

		if is_local_tunnel:
			# Packet with target ip_dst goes through "lo" if ip_dst is on the same host.
			# Avoid this by removing local rules
			exec_syscmd("ip route del %s table local" % ip_src)
			# pointopoint creates implicit rule in "main"
			# Problem if src/dst tun are on the same host: packets pop out of tun1 (target), but the kernel
			# does not recognize them as being addressed to the local host. (we removed the rule above)
			# Solution: distinct routing decisions and configure routing in such a way that the local
			# type routes are only "seen" by the input routing decision
			tid = 13
			exec_syscmd("ip route add local %s dev %s table %d" % (ip_src, iface_name, tid))
			# make sure previous rules have been removed
			# iif NAME = select the incoming device to match
			# http://man7.org/linux/man-pages/man8/ip-rule.8.html
			exec_syscmd("ip rule del iif %s lookup %d" % (iface_name, tid))
			exec_syscmd("ip rule add iif %s lookup %d" % (iface_name, tid))

	def read(self):
		"""Read an IP packet been sent to this TUN device."""
		try:
			return os_read(self._fileno_iface_fd, 1024 * 4)
		except TypeError:
			# read after closing
			return None

	def write(self, bts):
		"""Write an IP packet to this TUN device."""
		try:
			os_write(self._fileno_iface_fd, bts)
		except TypeError:
			# write after closing
			pass

	def close(self):
		if self._closed:
			return
		self._closed = True

		try:
			#self._iface_fd.close()
			os.close(self._fileno_iface_fd)
			self._fileno_iface_fd = None
		except Exception as ex:
			print(ex)

		if self._is_local_tunnel:
			exec_syscmd("ip rule del iif %s lookup %d" % (self._iface_name, 13))


class LocalTunnel(object):
	"""
	Local Back-to-back tunnel based on tun interfaces: local <-> ip:tun1:dev <-> dev:tun2:ip <-> local
	"""
	def __init__(self, ip_iface_A="192.168.2.1", ip_iface_B="192.168.3.1"):
		self._ifacetype = TYPE_TAP
		islocaltunnel = True
		ifacetype_str = TYPE_STR_DCT[self._ifacetype]
		self._state_active = False

		iface_name_A = ifacetype_str + "A0"
		self._dev_A = TuntapInterface(
			iface_name=iface_name_A,
			devnode="/dev/net/" + ifacetype_str + "A",
			ifacetype=self._ifacetype,
			ip_src=ip_iface_A,
			is_local_tunnel=islocaltunnel
		)
		iface_name_B = ifacetype_str + "B0"
		self._dev_B = TuntapInterface(
			iface_name=iface_name_B,
			devnode="/dev/net/" + ifacetype_str + "B",
			ifacetype=self._ifacetype,
			ip_src=ip_iface_B,
			is_local_tunnel=islocaltunnel
		)

		utils.flush_arp_cache()
		#mac_A = utils.get_mac_for_iface(iface_name_A)
		#mac_B = utils.get_mac_for_iface(iface_name_B)
		#utils.add_arp_entry(ip_iface_A, mac_A, iface_name_B)
		#utils.add_arp_entry(ip_iface_B, mac_B, iface_name_A)

		self._rs_thread_A = None
		self._rs_thread_B = None

	def _start_cycler_threads(self):
		self._rs_thread_A = threading.Thread(target=LocalTunnel.read_write_cycler,
			args=[self, self._dev_A, self._dev_B, "1to2"])
		self._rs_thread_B = threading.Thread(target=LocalTunnel.read_write_cycler,
			args=[self, self._dev_B, self._dev_A, "2to1"])
		self._rs_thread_A.start()
		self._rs_thread_B.start()

	@staticmethod
	def read_write_cycler(obj, iface_in, iface_out, name):
		while obj._state_active:
			try:
				bts = iface_in.read()
				try:
					ip.IP(bts) if obj._ifacetype == TYPE_TUN else ethernet.Ethernet(bts)
					#logger.debug("Sending in cycler %s (%s -> %s):\n%s\n%s" %
					#	(name, iface_in._iface_name, iface_out._iface_name, bts, pkt))
					iface_out.write(bts)
				except:
					pass
			except ValueError as ex:
				logger.exception(ex)
				break
			except OSError as ex:
				logger.exception(ex)
				break
			except Exception as ex:
				logger.exception(ex)
				break

	def set_state(self, state_active):
		if self._state_active is None:
			return

		if state_active == self._state_active:
			return

		self._state_active = state_active

		if state_active:
			self._start_cycler_threads()
		else:
			self._dev_A.close()
			self._dev_B.close()

			for th in [self._rs_thread_A, self._rs_thread_B]:
				try:
					th.join()
				except:
					pass

			self._state_active = None
