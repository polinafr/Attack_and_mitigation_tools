from scapy.all import *
#from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, getmacbyip, Ether
import os




def main():
    while True:
        sniff(filter='arp', prn=detection)


def detection(packet):
    if more_than_one_ip() and check_ip_mac(packet):
        print("Warning! ARP spoof attack detected")


# checks that the mac of the ip is equal to one that was proposed in packet
def check_ip_mac(packet):
    if packet[ARP].op == 2:
        proposed_IP = packet[ARP].psrc
        # print("spoofed")
        return not (getmacbyip(proposed_IP) == packet[ARP].hwsrc)


def is_legal_mac(mac):
    if len(mac)!=17:
        return False
    pairs=mac.split(':')
    for pair in pairs:
        if len(pair)!=2:
            return False
        for letter in pair:
            if letter>'f':
                return False
            if letter<'0':
                return False
            if letter>'9' and letter<'a':
                return False
    return True


def more_than_one_ip():
    with os.popen('arp -a') as arp:
        broadcast_mac='ff:ff:ff:ff:ff:ff'
        zero_mac = '00:00:00:00:00:00'
        table = arp.read()
        mac_addresses=[]
        table_info = table.split()
        for word in table_info:
            if is_legal_mac(word.replace('-', ':')):
                if word!=broadcast_mac and word != zero_mac:
                    mac_addresses.append(word)
        sorted_macs = sorted(mac_addresses)
        for index in range(len(sorted_macs)-1):
            if mac_addresses[index] == mac_addresses[index+1]:
                return True
        return False
                #check that mac is legal and if not-broadcast/network mac appears more than once - warning
"""def check_if_alive(packet):
    if packet[ARP].op==2:
        target_ip=packet[ARP].psrc
        new_mac=packet[ARP].hwsrc

        with os.popen('arp -a') as arp:
            table = arp.read()
            index=table.find(target_ip)
            if index>0:
                while table[index].isdigit() or table[index]=='.':
                    index+=1

                while table[index]==' ':
                    index+=1
                previous_mac=table[index:index+17].replace('-', ':')
                if previous_mac!=packet[ARP].hwsrc:
                    #check that the previous is not alive
                    request = Ether(src=get_if_hwaddr(conf.iface), dst = previous_mac)/
                    ans=sr1()
"""



"""def compare_macs(packet):
    if packet[ARP].op == 2:
        src_bool = (packet[ARP].hwsrc == packet[Ether].src)
        dst_bool = (packet[ARP].hwdst == packet[Ether].dst)
        return (not src_bool) or (not dst_bool)"""




if __name__ == '__main__':
    main()
