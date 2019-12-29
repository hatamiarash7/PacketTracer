![banner](banner.jpg)


[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fhatamiarash7%2FPacketTracer.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fhatamiarash7%2FPacketTracer?ref=badge_shield)

# Packet Tracer ( Beta )

The low-level packet tracer library for Python

## What you can do
Create custom packets via keywords or from raw bytes :

```python
from packetracer.layer3.ip import IP
from packetracer.layer3.icmp import ICMP

# Packet via keywords
ip0 = IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +\
	ICMP(type=8) +\
	ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")

# Packet from raw bytes. ip1_bts can also be retrieved via ip0.bin()
ip1_bts = b"E\x00\x00*\x00\x00\x00\x00@\x01;)\x7f\x00\x00\x01\xc0\xa8\x00\x01\x08\x00\xc0?\x00{\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00foobar"
ip1 = IP(ip1_bts) 
# Change source IPv4 address
ip0.src_s = "1.2.3.4"
# Change ICMP payload
ip0[IP,ICMP,ICMP.Echo].body_bytes = b"foobar2"

# Output packet (similar result for ip1)
print("%s" % ip0)
layer3.ip.IP
        v_hl        : 0x45 = 69 = 0b1000101
        tos         : 0x0 = 0 = 0b0
        len         : 0x2B = 43 = 0b101011
        id          : 0x0 = 0 = 0b0
        off         : 0x0 = 0 = 0b0
        ttl         : 0x40 = 64 = 0b1000000
        p           : 0x1 = 1 = 0b1
        sum         : 0xB623 = 46627 = 0b1011011000100011
        src         : b'\x01\x02\x03\x04' = 1.2.3.4
        dst         : b'\xc0\xa8\x00\x01' = 192.168.0.1
        opts        : []
layer3.icmp.ICMP
        type        : 0x8 = 8 = 0b1000
        code        : 0x0 = 0 = 0b0
        sum         : 0x8E3F = 36415 = 0b1000111000111111
layer3.icmp.Echo
        id          : 0x7B = 123 = 0b1111011
        seq         : 0x1 = 1 = 0b1
        ts          : 0x0 = 0 = 0b0
        bodybytes   : b'foobar2'
```

Read/write packets from/to file ( pcap/tcpdump format ). You can test with [Wireshark](https://www.wireshark.org/):

```python
from packetracer import ppcap
from packetracer.layer12 import ethernet
from packetracer.layer3 import ip
from packetracer.layer4 import tcp

preader = ppcap.Reader(filename="packets_ether.pcap")
pwriter = ppcap.Writer(filename="packets_ether_new.pcap", linktype=ppcap.DLT_EN10MB)

for ts, buf in preader:
	eth = ethernet.Ethernet(buf)

	if eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None:
		print("%d: %s:%s -> %s:%s" % (ts, eth[ip.IP].src_s, eth[tcp.TCP].sport,
			eth[ip.IP].dst_s, eth[tcp.TCP].dport))
		pwriter.write(eth.bin())

pwriter.close()
```

Send/receive layer 2 packets:

```python
from packetracer import psocket
from packetracer.layer12 import ethernet

psock = psocket.SocketHndl(timeout=10)

def filter_pkt(pkt):
	return pkt.ip.tcp.sport == 80

# Receive raw bytes
for raw_bytes in psock:
	eth = ethernet.Ethernet(raw_bytes)
	print("Got packet: %r" % eth)
	eth.reverse_address()
	eth.higher_layer.reverse_address()
	# Send bytes
	psock.send(eth.bin())
	# Receive raw bytes
	bts = psock.recv()
	# Send/receive based on source/destination data in packet
	pkts = psock.sr(packet_ip)
	# Use filter to get specific packets
	pkts = psock.recvp(filter_match_recv=filter_pkt)
	# stop on first packet
	break

psock.close()
```

Intercept (and modificate) Packets eg for MITM:

```python
# Add iptables rule:
# iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-balance 0:2
import time

from packetracer import interceptor
from packetracer.layer3 import ip, icmp

# ICMP Echo request intercepting
def verdict_cb(ll_data, ll_proto_id, data, ctx):
	ip1 = ip.IP(data)
	icmp1 = ip1[icmp.ICMP]

	if icmp1 is None or icmp1.type != icmp.ICMP_TYPE_ECHO_REQ:
		return data, interceptor.NF_ACCEPT

	echo1 = icmp1[icmp.ICMP.Echo]

	if echo1 is None:
		return data, interceptor.NF_ACCEPT

	pp_bts = b"PACKETRACER"
	print("changing ICMP echo request packet")
	echo1.body_bytes = echo1.body_bytes[:-len(pp_bts)] + pp_bts
	return ip1.bin(), interceptor.NF_ACCEPT

ictor = interceptor.Interceptor()
ictor.start(verdict_cb, queue_ids=[0, 1, 2])
print("now sind a ICMP echo request to localhost: ping 127.0.0.1")
time.sleep(999)
ictor.stop()
```


## Prerequisites
- Python 3.x (CPython, Pypy, Jython or whatever Interpreter)
- Optional: netifaces >=0.10.6 (for utils)
- Optional (for interceptor):
  - CPython
  - Linux based system with kernel support for NFQUEUE target. The config option is at:
	- Networking Options -> Network packet filtering -> Core Netfilter -> NFQUEUE target
  - iptables (alternatively nftables)
    - NFQUEUE related rulez can be added eg "iptables -I INPUT 1 -j NFQUEUE --queue-num 0"
  - libnetfilter_queue library (see http://www.netfilter.org/projects/libnetfilter_queue)

## Installation
There is two way :
- Clone newest version
  - ```git clone https://github.com/hatamiarash7/PacketTracer.git```
  - ```cd packetracer```
  - ```python setup.py install```
- Use pip (synched to master on major version changes)
  - ```pip install packetracer```

## Usage examples
See examples/ and tests/test_packetracer.py.

## Testing
Tests are executed as follows:

1) Add packetracer directory to the PYTHONPATH.

- ```cd packetracer```
- ```export PYTHONPATH=$(pwd):$PYTHONPATH```

2) execute tests

- ```python tests/test_packetracer.py```

**Performance test results: packetracer**
```
orC = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, CPython v3.6
orP = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, Pypy 5.10.1
rounds per test: 10000
=====================================
>>> parsing (IP + ICMP)
orC = 86064 p/s
orP = 208346 p/s
>>> creating/direct assigning (IP only header)
orC = 41623 p/s
orP = 59370 p/s
>>> bin() without change (IP)
orC = 170356 p/s
orP = 292133 p/s
>>> output with change/checksum recalculation (IP)
orC = 10104 p/s
orP = 23851 p/s
>>> basic/first layer parsing (Ethernet + IP + TCP + HTTP)
orC = 62748 p/s
orP = 241047 p/s
>>> changing Triggerlist element value (Ethernet + IP + TCP + HTTP)
orC = 101552 p/s
orP = 201994 p/s
>>> changing Triggerlist/text based proto (Ethernet + IP + TCP + HTTP)
orC = 37249 p/s
orP = 272972 p/s
>>> direct assigning and concatination (Ethernet + IP + TCP + HTTP)
orC = 7428 p/s
orP = 14315 p/s
>>> full packet parsing (Ethernet + IP + TCP + HTTP)
orC = 6886 p/s
orP = 17040 p/s
```

**Performance test results: packetracer vs. dpkt vs. scapy**
```
Comparing packetracer, dpkt and scapy performance (parsing Ethernet + IP + TCP + HTTP)
orC = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, CPython v3.6
orC2 = Intel Core2 Duo CPU @ 1,866 GHz, 2GB RAM, CPython v2.7
rounds per test: 10000
=====================================
>>> testing packetracer parsing speed
orC = 17938 p/s
>>> testing dpkt parsing speed
orC = 12431 p/s
>>> testing scapy parsing speed
orC2 = 726 p/s
```

# Usage hints
## Performance related
- For maxmimum performance start accessing attributes at lowest level e.g. for filtering:
```
# This will lazy parse only needed layers behind the scenes
if ether.src == "...":
    ...
elif ip.src == "...":
    ...
elif tcp.sport == "...":
    ...
```

- Avoid to convert packets using the "%s" or "%r" format as it triggers parsing behind the scene:
```
pkt = Ethernet() + IP() + TCP()
# This parses ALL layers
packet_print = "%s" % pkt
```

- Avoid searching for a layer using single-value index-notation via pkt[L] as it parses all layers until L is found or highest layer is reached:
```
packet_found = pkt[Telnet]
# Alternative: Use multi-value index-notation. This will stop parsing at any non-matching layer:
packet_found = pkt[Ethernet,IP,TCP,Telnet]
```

- Use pypy instead of cpython (~3x faster related to full packet parsing)

- For even more performance disable auto fields (affects calling bin(...)):
```
pkt = ip.IP(src_s="1.2.3.4", dst_s="1.2.3.5") + tcp.TCP()
# Disable checksum calculation (and any other update) for IP and TCP (only THIS packet instance)
pkt.sum_au_active = False
pkt.tcp.sum_au_active = False
bts = pkt.bin(update_auto_fields=False)
```

- Enlarge receive/send buffers to get max performance. This can be done using the following commands
	(taken from: http://www.cyberciti.biz/faq/linux-tcp-tuning/):
```
sysctl -w net.core.rmem_max=12582912
sysctl -w net.core.rmem_default=12582912
sysctl -w net.core.wmem_max=12582912
sysctl -w net.core.wmem_default=12582912
sysctl -w net.core.optmem_max=2048000
sysctl -w net.core.netdev_max_backlog=5000
sysctl -w net.unix.max_dgram_qlen=1000
sysctl -w net.ipv4.tcp_rmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_wmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_mem="21228 87380 12582912"
sysctl -w net.ipv4.udp_mem="21228 87380 12582912"
sysctl -w net.ipv4.tcp_window_scaling=1
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.ipv4.tcp_sack=1
```

## Misc related
- Assemblation of TCP/UDP streams can be done by tshark using pipes
	with "-i -" and "-z follow,prot,mode,filter[,range]"


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fhatamiarash7%2FPacketTracer.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fhatamiarash7%2FPacketTracer?ref=badge_large)
