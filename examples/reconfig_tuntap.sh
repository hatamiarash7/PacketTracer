# Example script to configure two tun interfaces
for iface in tun0 tun1; do
ip tuntap del dev $iface mode tun
ip tuntap add dev $iface mode tun
ifconfig $iface up
echo 1 > /proc/sys/net/ipv4/conf/$iface/accept_local
done

IP1="192.168.0.1"
IP2="192.168.0.2"
ifconfig tun0 $IP1 pointopoint $IP2
ifconfig tun1 $IP2 pointopoint $IP1

# unbound socket -> send to tun-IP -> goes through "lo": avoid this by removing local rules
ip route del $IP1 table local
ip route del $IP2 table local

ip rule del iif tun0 lookup 13
ip rule del iif tun1 lookup 13

# pointopoint creates implicit rule in "main"
# The problem is that our packets pop out of tun1 (on tun1 ingress), but the kernel
# does not recognize them as being addressed to the local host. (we removed the rule above)
# Solution: distinct routing decisions and configure routing in such a way that the local
# type routes are only "seen" by the input routing decision
ip route add local $IP1 dev tun0 table 13
ip rule add iif tun0 lookup 13

ip route add local $IP2 dev tun1 table 13
ip rule add iif tun1 lookup 13


ip rule show
ip route ls table local
ip route ls table main
ip route show table 13
#ip route show table all
#cat /etc/iproute2/rt_tables

# ping -I tun0 192.168.0.2
# ping -I tun1 192.168.0.1
