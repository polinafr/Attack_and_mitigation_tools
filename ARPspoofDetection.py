from scapy.all import *
#from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, getmacbyip, Ether




def main():
    while True:
        sniff(filter='arp', prn=detection)


def detection(packet):
    if compare_macs(packet) and check_ip_mac(packet):
        print("Warning! ARP spoof attack detected")


# checks that the mac of the ip is equal to one that was proposed in packet
def check_ip_mac(packet):
    if packet[ARP].op == 2:
        proposed_IP = packet[ARP].psrc
        # print("spoofed")
        return not (getmacbyip(proposed_IP) == packet[ARP].hwsrc)


def compare_macs(packet):
    if packet[ARP].op == 2:
        src_bool = (packet[ARP].hwsrc == packet[Ether].src)
        dst_bool = (packet[ARP].hwdst == packet[Ether].dst)
        return (not src_bool) or (not dst_bool)




if __name__ == '__main__':
    main()
