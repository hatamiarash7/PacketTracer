"""
Interceptor example via nftables

# Add table
nft add table inet queuetable
# Add chain to table
nft add chain inet queuetable input { type filter hook input priority 0\; }
# Add rule to chain
nft insert rule inet queuetable input counter queue num 0-3 bypass
# Delete table
nft delete table inet queuetable

# List handles
nft --handle --numeric list chain inet queuetable input
# List rules
nft list ruleset
https://wiki.nftables.org/wiki-nftables/index.php/Queueing_to_userspace
# Show ARP cache for IPv6
ip -6 neigh
"""
import time

from packetracer import interceptor
from packetracer.layer12 import ethernet
from packetracer.layer3 import ip, ip6

id_class = {
	ethernet.ETH_TYPE_IP: ip.IP,
	ethernet.ETH_TYPE_IP6: ip6.IP6
}


def verdict_cb(ll_data, ll_proto_id, data, ctx):
	clz = id_class.get(ll_proto_id, None)

	if clz is not None:
		pkt = clz(data)
		print("Got a packet: %s" % pkt.__class__)
	else:
		print("Unknown NW layer proto: %X" % ll_proto_id)

	return data, interceptor.NF_ACCEPT


ictor = interceptor.Interceptor()
ictor.start(verdict_cb, queue_ids=[0, 1, 2, 3])

try:
	time.sleep(999)
except KeyboardInterrupt:
	pass
ictor.stop()
