import time

from packetracer import tuntap

ip_src = "192.168.1.123"
ip_dst = "192.168.1.1"

lt = tuntap.LocalTunnel(ip_iface_A=ip_src, ip_iface_B=ip_dst)
lt.set_state(True)

try:
    time.sleep(9999)
except:
    pass
lt.set_state(False)
